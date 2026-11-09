//! Raw application attachment. The broker owns no descriptor, policy or private
//! control traffic. Configuration requests, capture leases and transport attempts
//! have separate lifetimes; retiring a capture cannot cancel its successor request.
use crate::tun_provider::TunConfig;
use std::{
    collections::VecDeque,
    io,
    sync::{Arc, Mutex, Weak},
};
use talpid_types::relay_flow::{
    MAX_TARGETS, RelayAttempt, RelayAttemptOwner, RelayBuffer, RelayBufferAllocator,
    RelayBufferReservation, RelayCapture, RelayCaptureGeneration, RelayCaptureOwner,
    RelayFlowError, RelayPacket, RelaySink, RelaySources, RelayTargetId, RelayWriteOutcome,
};
use tokio::sync::{Notify, watch};

pub const PACKET_CAPACITY: usize = 256;
// Both queue allocations, their insertion peaks, notifications, watch state and
// half metadata. Withheld before allocating, retained by every queue/half/reply.
const CHANNEL_STORAGE: usize = 2 * PACKET_CAPACITY * 256 + 8192;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AttachmentMode {
    Native,
    ManagedRequired,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AttachmentError {
    Disabled,
    CaptureUnready,
    OrdinaryUnready,
    Stale,
    Full,
    Closed,
    Busy,
    Invalid,
}

impl From<RelayFlowError> for AttachmentError {
    fn from(error: RelayFlowError) -> Self {
        match error {
            RelayFlowError::Invalid => Self::Invalid,
            RelayFlowError::Full => Self::Full,
            RelayFlowError::Stale => Self::Stale,
            RelayFlowError::Closed => Self::Closed,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BrokerSnapshot {
    pub mode: AttachmentMode,
    pub closed: bool,
    pub request: Option<u64>,
    pub capture_generation: Option<u64>,
    pub session_generation: Option<u64>,
    pub capture_ready: bool,
    pub attachment: Option<u64>,
    pub ordinary_ready: bool,
}

struct Configuration {
    id: u64,
    config: TunConfig,
    status: watch::Sender<RequestStatus>,
    release: watch::Sender<CaptureRelease>,
    release_changes: watch::Sender<u64>,
    _storage: Arc<dyn RelayBufferReservation>,
}

#[derive(Clone, Copy, Eq, PartialEq)]
struct CaptureRelease {
    transport_joined: bool,
    handover_joined: bool,
}

impl Configuration {
    fn update_release(&self, change: impl FnOnce(&mut CaptureRelease)) {
        if self.release.send_if_modified(|state| {
            let before = *state;
            change(state);
            before != *state
        }) {
            self.release_changes.send_modify(|revision| {
                *revision = revision.checked_add(1).expect("capture release revision");
            });
        }
    }
    fn release_ready(&self) -> bool {
        let state = *self.release.borrow();
        state.transport_joined && state.handover_joined
    }
}

#[derive(Clone)]
enum RequestStatus {
    Pending,
    Ready(CaptureReceipt),
    Cancelled,
    Failed,
}

/// Sole cancellation owner, retained across cancellation of `configured()`.
pub struct ConfigurationRequest {
    inner: Weak<Inner>,
    request: Arc<Configuration>,
    status: watch::Receiver<RequestStatus>,
}

/// Provider cleanup borrows one exact request. It cannot cancel a later request
/// or choose whichever target happens to be current when cleanup finally runs.
pub struct TransportCleanup {
    inner: Weak<Inner>,
    request: Weak<Configuration>,
}

/// Actor-side request capability. An old acknowledgement cannot satisfy a new
/// request, even when configurations compare equal.
#[derive(Clone)]
pub struct PendingCaptureRequest(Arc<Configuration>);

struct Capture {
    generation: u64,
    epoch: u64,
    predecessor: Option<u64>,
    config: Option<Arc<Configuration>>,
    owner: Option<RelayCaptureOwner>,
}

struct Queues {
    outbound: VecDeque<RelayPacket>,
    inbound: VecDeque<RelayPacket>,
}

struct Attempt {
    id: u64,
    target: RelayTargetId,
    request: Arc<Configuration>,
    owner: RelayAttemptOwner,
    queues: Mutex<Queues>,
    outbound: Notify,
    cancelled: watch::Sender<bool>,
    _storage: Arc<dyn RelayBufferReservation>,
}

impl Attempt {
    fn retire(&self) {
        self.owner.retire();
        self.cancelled.send_replace(true);
        let mut queues = self.queues.lock().expect("attachment queues");
        queues.outbound.clear();
        queues.inbound.clear();
        self.outbound.notify_one();
    }
}

struct State {
    mode: AttachmentMode,
    closed: bool,
    next_request: u64,
    next_attempt: u64,
    request: Option<Arc<Configuration>>,
    capture: Option<Capture>,
    attempts: [Option<Arc<Attempt>>; MAX_TARGETS],
    local_routes: Vec<ipnetwork::IpNetwork>,
    route_storage: Option<Arc<dyn RelayBufferReservation>>,
    paused: bool,
    next_reply: usize,
}

impl State {
    fn attempt(&self, target: RelayTargetId) -> Option<&Arc<Attempt>> {
        self.attempts.iter().flatten().find(|a| a.target == target)
    }
    fn detach_target(&mut self, target: RelayTargetId) {
        if let Some(slot) = self
            .attempts
            .iter_mut()
            .find(|a| a.as_ref().is_some_and(|a| a.target == target))
        {
            slot.take().expect("matched target").retire();
        }
    }
    fn detach(&mut self) {
        for slot in &mut self.attempts {
            if let Some(attempt) = slot.take() {
                attempt.retire();
            }
        }
    }
    fn retire_capture(&mut self) {
        // Revoke before dropping queues or acknowledging cleanup. Do not touch
        // request: it may be the successor that caused this capture's teardown.
        if let Some(capture) = self.capture.take() {
            if let Some(owner) = capture.owner {
                owner.retire();
            }
            if let Some(config) = capture.config {
                config.status.send_replace(RequestStatus::Failed);
                if self
                    .request
                    .as_ref()
                    .is_some_and(|r| Arc::ptr_eq(r, &config))
                {
                    self.request.take();
                }
            }
        }
        self.detach();
    }
    fn snapshot(&self) -> BrokerSnapshot {
        BrokerSnapshot {
            mode: self.mode,
            closed: self.closed,
            request: self.request.as_ref().map(|r| r.id),
            capture_generation: self.capture.as_ref().map(|c| c.epoch),
            session_generation: self
                .capture
                .as_ref()
                .filter(|c| c.owner.is_some())
                .map(|c| c.generation),
            capture_ready: self
                .capture
                .as_ref()
                .and_then(|c| c.owner.as_ref())
                .is_some_and(|owner| owner.capability().sink().is_some()),
            attachment: self.attempt(RelayTargetId::MULLVAD).map(|a| a.id),
            ordinary_ready: self
                .attempt(RelayTargetId::MULLVAD)
                .is_some_and(|a| a.owner.capability().current()),
        }
    }
}

struct Inner {
    state: Mutex<State>,
    changes: watch::Sender<BrokerSnapshot>,
    release_changes: watch::Sender<u64>,
    replies: Notify,
    application: Arc<dyn RelayBufferAllocator>,
    capture: Arc<dyn RelayBufferAllocator>,
    control: Arc<dyn RelayBufferAllocator>,
    _storage: Arc<dyn RelayBufferReservation>,
}

impl Inner {
    fn publish(&self, state: &State) {
        self.changes.send_if_modified(|snapshot| {
            let next = state.snapshot();
            if *snapshot == next {
                false
            } else {
                *snapshot = next;
                true
            }
        });
    }
}

#[derive(Clone)]
pub struct AttachmentBroker {
    inner: Arc<Inner>,
}

/// Sole capture lifecycle capability, allocated before platform open.
pub struct CaptureLease {
    inner: Arc<Inner>,
    generation: u64,
    unbound: Mutex<Option<RelayCaptureGeneration>>,
}

/// Retained transaction within one logical capture lease. Binding a fresh sink
/// does not discharge predecessor cleanup. Drop before explicit completion is
/// capture failure, never an implicit rollback or a new session.
pub struct CaptureEpochChange {
    inner: Arc<Inner>,
    session: u64,
    generation: u64,
    predecessor: RelaySink,
    previous_config: Option<Arc<Configuration>>,
    unbound: Mutex<Option<RelayCaptureGeneration>>,
    completed: bool,
}

/// Only the capture owner can issue this after actual identity observation.
#[derive(Clone)]
pub struct CaptureReceipt {
    inner: Weak<Inner>,
    generation: u64,
    configuration: Weak<Configuration>,
}

pub struct AttemptControl {
    inner: Weak<Inner>,
    attempt: Arc<Attempt>,
}
pub struct TransportReceive {
    control: AttemptControl,
}
pub struct TransportSend {
    control: AttemptControl,
}
pub struct TransportPair {
    pub control: AttemptControl,
    pub receive: TransportReceive,
    pub send: TransportSend,
}

/// A blocked write retains unchanged bytes, exact authority and channel credit.
pub struct AttachmentReply {
    inner: Weak<Inner>,
    attempt: Arc<Attempt>,
    packet: RelayPacket,
}

impl AttachmentBroker {
    pub fn same_broker(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.inner, &other.inner)
    }
    pub fn new(
        application: Arc<dyn RelayBufferAllocator>,
        capture: Arc<dyn RelayBufferAllocator>,
        control: Arc<dyn RelayBufferAllocator>,
    ) -> Result<Self, AttachmentError> {
        let storage = capture.try_reserve(8192)?;
        let state = State {
            mode: AttachmentMode::Native,
            closed: false,
            next_request: 0,
            next_attempt: 0,
            request: None,
            capture: None,
            attempts: std::array::from_fn(|_| None),
            local_routes: Vec::new(),
            route_storage: None,
            paused: false,
            next_reply: 0,
        };
        let changes = watch::channel(state.snapshot()).0;
        Ok(Self {
            inner: Arc::new(Inner {
                state: Mutex::new(state),
                changes,
                release_changes: watch::channel(0).0,
                replies: Notify::new(),
                application,
                capture,
                control,
                _storage: storage,
            }),
        })
    }

    pub fn snapshot(&self) -> BrokerSnapshot {
        self.inner
            .state
            .lock()
            .expect("attachment state")
            .snapshot()
    }
    pub fn changes(&self) -> watch::Receiver<BrokerSnapshot> {
        self.inner.changes.subscribe()
    }

    /// Retained runtime regions, never fresh per-attempt roots.
    pub fn control_buffers(&self) -> Arc<dyn RelayBufferAllocator> {
        self.inner.control.clone()
    }
    pub fn application_buffers(&self) -> Arc<dyn RelayBufferAllocator> {
        self.inner.application.clone()
    }

    /// Immutable configuration input for the next transport. The daemon changes
    /// this only after joined teardown; the broker never interprets local policy.
    pub fn set_local_routes(
        &self,
        routes: Vec<ipnetwork::IpNetwork>,
    ) -> Result<(), AttachmentError> {
        let storage = self.inner.capture.try_reserve(
            routes
                .capacity()
                .checked_mul(std::mem::size_of::<ipnetwork::IpNetwork>())
                .and_then(|n| n.checked_add(512))
                .ok_or(AttachmentError::Full)?,
        )?;
        let mut state = self.inner.state.lock().expect("attachment state");
        if state.closed {
            return Err(AttachmentError::Closed);
        }
        if state.request.is_some()
            || state.capture.is_some()
            || state.attempts.iter().any(Option::is_some)
        {
            return Err(AttachmentError::Busy);
        }
        state.local_routes = routes;
        state.route_storage = Some(storage);
        state.paused = false;
        Ok(())
    }

    pub fn local_routes(&self) -> Vec<ipnetwork::IpNetwork> {
        self.inner
            .state
            .lock()
            .expect("attachment state")
            .local_routes
            .clone()
    }

    pub fn capture_release_changes(&self) -> watch::Receiver<u64> {
        self.inner.release_changes.subscribe()
    }

    pub fn set_mode(&self, mode: AttachmentMode) -> Result<(), AttachmentError> {
        let mut state = self.inner.state.lock().expect("attachment state");
        if state.closed {
            return Err(AttachmentError::Closed);
        }
        if state.mode != mode {
            state.retire_capture();
            if let Some(request) = state.request.take() {
                request.status.send_replace(RequestStatus::Cancelled);
            }
            state.mode = mode;
            self.inner.publish(&state);
            self.inner.replies.notify_one();
        }
        Ok(())
    }

    /// Synchronous provider call. No JNI, descriptor acquisition or await.
    pub fn request_capture(
        &self,
        config: TunConfig,
    ) -> Result<ConfigurationRequest, AttachmentError> {
        let storage = self.inner.capture.try_reserve(1024)?;
        let mut state = self.inner.state.lock().expect("attachment state");
        if state.closed {
            return Err(AttachmentError::Closed);
        }
        if state.mode != AttachmentMode::ManagedRequired {
            return Err(AttachmentError::Disabled);
        }
        if state.paused {
            return Err(AttachmentError::Closed);
        }
        if state.request.is_some() {
            return Err(AttachmentError::Busy);
        }
        let id = state
            .next_request
            .checked_add(1)
            .ok_or(AttachmentError::Full)?;
        let (status_tx, status) = watch::channel(RequestStatus::Pending);
        let request = Arc::new(Configuration {
            id,
            config,
            status: status_tx,
            release: watch::channel(CaptureRelease {
                transport_joined: true,
                handover_joined: true,
            })
            .0,
            release_changes: self.inner.release_changes.clone(),
            _storage: storage,
        });
        state.next_request = id;
        state.request = Some(request.clone());
        self.inner.publish(&state);
        Ok(ConfigurationRequest {
            inner: Arc::downgrade(&self.inner),
            request,
            status,
        })
    }

    pub fn pending_request(&self) -> Option<PendingCaptureRequest> {
        self.inner
            .state
            .lock()
            .expect("attachment state")
            .request
            .clone()
            .map(PendingCaptureRequest)
    }

    pub fn open_capture(
        &self,
        request: Option<&PendingCaptureRequest>,
    ) -> Result<CaptureLease, AttachmentError> {
        let generation = RelayCaptureGeneration::fresh()?;
        let mut state = self.inner.state.lock().expect("attachment state");
        if state.closed {
            return Err(AttachmentError::Closed);
        }
        if state.capture.is_some() {
            return Err(AttachmentError::Busy);
        }
        if let Some(request) = request
            && (state.mode != AttachmentMode::ManagedRequired
                || !state
                    .request
                    .as_ref()
                    .is_some_and(|r| Arc::ptr_eq(r, &request.0)))
        {
            return Err(AttachmentError::Stale);
        }
        state.capture = Some(Capture {
            generation: generation.get(),
            epoch: generation.get(),
            predecessor: None,
            config: request.map(|r| r.0.clone()),
            owner: None,
        });
        self.inner.publish(&state);
        Ok(CaptureLease {
            inner: self.inner.clone(),
            generation: generation.get(),
            unbound: Mutex::new(Some(generation)),
        })
    }

    /// Native capture adapter only, after fd-bound exact VPN observation.
    fn observed_capture(
        &self,
        lease: &CaptureLease,
        interface: &str,
        network_handle: Option<u64>,
        sources: RelaySources,
        mtu: u16,
    ) -> Result<CaptureReceipt, AttachmentError> {
        if !Arc::ptr_eq(&self.inner, &lease.inner) {
            return Err(AttachmentError::Stale);
        }
        let mut state = self.inner.state.lock().expect("attachment state");
        let capture = state
            .capture
            .as_mut()
            .filter(|c| c.generation == lease.generation)
            .ok_or(AttachmentError::Stale)?;
        if capture.owner.is_some() {
            return Err(AttachmentError::Busy);
        }
        if let Some(request) = &capture.config
            && (request.config.mtu != mtu
                || request
                    .config
                    .addresses
                    .iter()
                    .any(|ip| !sources.contains(*ip))
                || request.config.addresses.len()
                    != usize::from(sources.ipv4.is_some()) + usize::from(sources.ipv6.is_some()))
        {
            return Err(AttachmentError::Invalid);
        }
        if capture.config.is_some() && network_handle.is_none() {
            return Err(AttachmentError::Invalid);
        }
        let generation = lease
            .unbound
            .lock()
            .expect("capture generation")
            .take()
            .ok_or(AttachmentError::Stale)?;
        let owner = RelayCaptureOwner::with_identity(
            generation,
            interface,
            network_handle,
            sources,
            mtu,
            self.inner.capture.as_ref(),
        )?;
        capture.owner = Some(owner);
        let receipt = CaptureReceipt {
            inner: Arc::downgrade(&self.inner),
            generation: lease.generation,
            configuration: capture
                .config
                .as_ref()
                .map(Arc::downgrade)
                .unwrap_or_default(),
        };
        self.inner.publish(&state);
        Ok(receipt)
    }

    pub fn acknowledge(
        &self,
        request: &PendingCaptureRequest,
        receipt: &CaptureReceipt,
    ) -> Result<(), AttachmentError> {
        let mut state = self.inner.state.lock().expect("attachment state");
        if !receipt.matches(&self.inner, &state) {
            return Err(AttachmentError::CaptureUnready);
        }
        if !state
            .request
            .as_ref()
            .is_some_and(|r| Arc::ptr_eq(r, &request.0))
            || !state
                .capture
                .as_ref()
                .and_then(|c| c.config.as_ref())
                .is_some_and(|r| r.config == request.0.config)
        {
            return Err(AttachmentError::Stale);
        }
        let receipt = CaptureReceipt {
            inner: receipt.inner.clone(),
            generation: receipt.generation,
            configuration: Arc::downgrade(&request.0),
        };
        request.0.status.send_replace(RequestStatus::Ready(receipt));
        state.capture.as_mut().expect("matching receipt").config = Some(request.0.clone());
        state.request.take();
        self.inner.publish(&state);
        Ok(())
    }

    pub fn acquire(&self, receipt: &CaptureReceipt) -> Result<TransportPair, AttachmentError> {
        let request = receipt
            .configuration
            .upgrade()
            .ok_or(AttachmentError::CaptureUnready)?;
        let config = &request.config;
        let sources = RelaySources {
            ipv4: config.addresses.iter().find_map(|ip| {
                if let std::net::IpAddr::V4(ip) = ip {
                    Some(*ip)
                } else {
                    None
                }
            }),
            ipv6: config.addresses.iter().find_map(|ip| {
                if let std::net::IpAddr::V6(ip) = ip {
                    Some(*ip)
                } else {
                    None
                }
            }),
        };
        self.acquire_target(receipt, RelayTargetId::MULLVAD, sources, config.mtu)
    }

    /// Attach an independently owned target to this session. Source/MTU belong
    /// to the target, not to the app-facing capture identity.
    pub fn acquire_target(
        &self,
        receipt: &CaptureReceipt,
        target: RelayTargetId,
        sources: RelaySources,
        mtu: u16,
    ) -> Result<TransportPair, AttachmentError> {
        let storage = self.inner.capture.try_reserve(CHANNEL_STORAGE)?;
        let mut state = self.inner.state.lock().expect("attachment state");
        if state.paused && target == RelayTargetId::MULLVAD {
            return Err(AttachmentError::OrdinaryUnready);
        }
        if !receipt.matches(&self.inner, &state) {
            return Err(AttachmentError::CaptureUnready);
        }
        if state.attempt(target).is_some() {
            return Err(AttachmentError::Busy);
        }
        let slot = state
            .attempts
            .iter()
            .position(Option::is_none)
            .ok_or(AttachmentError::Full)?;
        if !state
            .capture
            .as_ref()
            .and_then(|c| c.config.as_ref())
            .is_some_and(|r| {
                receipt
                    .configuration
                    .upgrade()
                    .is_some_and(|expected| Arc::ptr_eq(r, &expected))
                    && matches!(*r.status.borrow(), RequestStatus::Ready(_))
            })
        {
            return Err(AttachmentError::CaptureUnready);
        }
        let id = state
            .next_attempt
            .checked_add(1)
            .ok_or(AttachmentError::Full)?;
        let owner = state
            .capture
            .as_ref()
            .and_then(|c| c.owner.as_ref())
            .ok_or(AttachmentError::CaptureUnready)?
            .open_target(target, sources, mtu, self.inner.capture.as_ref())?;
        state
            .capture
            .as_ref()
            .and_then(|capture| capture.config.as_ref())
            .expect("configured capture")
            .update_release(|release| release.transport_joined = false);
        let attempt = Arc::new(Attempt {
            id,
            target,
            request: receipt
                .configuration
                .upgrade()
                .ok_or(AttachmentError::CaptureUnready)?,
            owner,
            queues: Mutex::new(Queues {
                outbound: VecDeque::with_capacity(PACKET_CAPACITY),
                inbound: VecDeque::with_capacity(PACKET_CAPACITY),
            }),
            outbound: Notify::new(),
            cancelled: watch::channel(false).0,
            _storage: storage,
        });
        let control = || AttemptControl {
            inner: Arc::downgrade(&self.inner),
            attempt: attempt.clone(),
        };
        let pair = TransportPair {
            control: control(),
            receive: TransportReceive { control: control() },
            send: TransportSend { control: control() },
        };
        state.next_attempt = id;
        state.attempts[slot] = Some(attempt);
        self.inner.publish(&state);
        Ok(pair)
    }

    pub fn close(&self) {
        let mut state = self.inner.state.lock().expect("attachment state");
        state.closed = true;
        state.retire_capture();
        if let Some(request) = state.request.take() {
            request.status.send_replace(RequestStatus::Cancelled);
        }
        self.inner.publish(&state);
        self.inner.replies.notify_one();
    }

    /// Capture the provider's cleanup authority before dispatching its operation.
    /// An empty selection stays empty even if a later request opens a target.
    pub fn transport_cleanup(&self) -> TransportCleanup {
        let state = self.inner.state.lock().expect("attachment state");
        let request = state.request.as_ref().or_else(|| {
            state
                .capture
                .as_ref()
                .and_then(|capture| capture.config.as_ref())
        });
        TransportCleanup {
            inner: Arc::downgrade(&self.inner),
            request: request.map(Arc::downgrade).unwrap_or_default(),
        }
    }

    /// Revoke ordinary output before requesting TSM teardown. Capture/platform
    /// release remains owned by the retained frontend and its joined stop.
    pub fn pause_transport(&self) {
        let mut state = self.inner.state.lock().expect("attachment state");
        state.paused = true;
        if let Some(config) = state
            .capture
            .as_ref()
            .and_then(|capture| capture.config.as_ref())
        {
            config.update_release(|release| release.handover_joined = false);
        }
        if let Some(request) = state.request.take() {
            request.update_release(|release| release.handover_joined = false);
            request.status.send_replace(RequestStatus::Cancelled);
        }
        state.detach_target(RelayTargetId::MULLVAD);
        self.inner.publish(&state);
        self.inner.replies.notify_one();
    }
}

impl CaptureReceipt {
    fn matches(&self, inner: &Arc<Inner>, state: &State) -> bool {
        Weak::ptr_eq(&self.inner, &Arc::downgrade(inner))
            && !state.closed
            && state.mode == AttachmentMode::ManagedRequired
            && state.capture.as_ref().is_some_and(|c| {
                c.epoch == self.generation
                    && c.owner
                        .as_ref()
                        .is_some_and(|owner| owner.capability().sink().is_some())
                    && c.config.is_some()
            })
    }
    pub fn current(&self) -> bool {
        self.inner.upgrade().is_some_and(|inner| {
            self.matches(&inner, &inner.state.lock().expect("attachment state"))
        })
    }

    /// Borrow the existing fd epoch only when its full observed configuration
    /// matches the new request. A route/DNS/source change needs a fresh epoch.
    pub fn acknowledge(&self, request: &PendingCaptureRequest) -> Result<(), AttachmentError> {
        let inner = self.inner.upgrade().ok_or(AttachmentError::Closed)?;
        AttachmentBroker { inner }.acknowledge(request, self)
    }
    pub fn generation(&self) -> u64 {
        self.generation
    }
}

impl PendingCaptureRequest {
    pub fn id(&self) -> u64 {
        self.0.id
    }
    pub fn config(&self) -> &TunConfig {
        &self.0.config
    }
    /// The daemon holds this stage before revoking an attempt for a normal TSM
    /// handover. A transport's own cleanup cannot bypass the actor's joined ack.
    pub fn defer_release(&self) {
        self.0
            .update_release(|release| release.handover_joined = false);
    }
    /// Called only at an observed joined TSM boundary, never at Disconnecting.
    pub fn handover_joined(&self) {
        self.0.update_release(|release| {
            release.transport_joined = true;
            release.handover_joined = true;
        });
    }
    pub fn release_ready(&self) -> bool {
        self.0.release_ready()
    }
    pub async fn wait_release(&self) {
        let mut changes = self.0.release.subscribe();
        while !self.0.release_ready() {
            let _ = changes.changed().await;
        }
    }
}

impl ConfigurationRequest {
    /// The transport owner calls this only after its device and private control
    /// tasks have joined. Cancellation/retirement alone never acknowledge it.
    pub fn transport_joined(&self) {
        self.request
            .update_release(|release| release.transport_joined = true);
    }
    pub async fn configured(&mut self) -> Result<CaptureReceipt, AttachmentError> {
        loop {
            let status = self.status.borrow_and_update().clone();
            match status {
                RequestStatus::Pending => {}
                RequestStatus::Ready(receipt) => {
                    return receipt
                        .current()
                        .then_some(receipt)
                        .ok_or(AttachmentError::CaptureUnready);
                }
                RequestStatus::Cancelled => return Err(AttachmentError::Closed),
                RequestStatus::Failed => return Err(AttachmentError::CaptureUnready),
            }
            self.status
                .changed()
                .await
                .map_err(|_| AttachmentError::Closed)?;
        }
    }
    pub fn cancel(&self) {
        cancel_configuration(&self.inner, &self.request);
    }
}

impl TransportCleanup {
    pub fn cancel(&self) {
        if let Some(request) = self.request.upgrade() {
            cancel_configuration(&self.inner, &request);
        }
    }
}

fn cancel_configuration(inner: &Weak<Inner>, request: &Arc<Configuration>) {
    if let Some(inner) = inner.upgrade() {
        let mut state = inner.state.lock().expect("attachment state");
        if state
            .request
            .as_ref()
            .is_some_and(|r| Arc::ptr_eq(r, request))
        {
            state.request.take();
        }
        if state
            .attempt(RelayTargetId::MULLVAD)
            .is_some_and(|a| Arc::ptr_eq(&a.request, request))
        {
            state.detach_target(RelayTargetId::MULLVAD);
        }
        request.status.send_replace(RequestStatus::Cancelled);
        inner.publish(&state);
        inner.replies.notify_one();
    }
}
impl Drop for ConfigurationRequest {
    fn drop(&mut self) {
        self.cancel();
    }
}

impl CaptureLease {
    pub fn generation(&self) -> u64 {
        self.generation
    }

    /// Allocate the successor epoch before platform work. Sources/MTU are the
    /// session's immutable app-side identity; a change requires a new session.
    pub fn begin_handover(
        &self,
        request: Option<&PendingCaptureRequest>,
        sources: RelaySources,
        mtu: u16,
    ) -> Result<CaptureEpochChange, AttachmentError> {
        let generation = RelayCaptureGeneration::fresh()?;
        let mut state = self.inner.state.lock().expect("attachment state");
        if state.closed {
            return Err(AttachmentError::Closed);
        }
        if let Some(request) = request
            && (state.mode != AttachmentMode::ManagedRequired
                || !state
                    .request
                    .as_ref()
                    .is_some_and(|r| Arc::ptr_eq(r, &request.0)))
        {
            return Err(AttachmentError::Stale);
        }
        let capture = state
            .capture
            .as_mut()
            .filter(|c| c.generation == self.generation)
            .ok_or(AttachmentError::Stale)?;
        if capture.predecessor.is_some() {
            return Err(AttachmentError::Busy);
        }
        let owner = capture
            .owner
            .as_ref()
            .ok_or(AttachmentError::CaptureUnready)?;
        if owner.identity().sources != sources
            || owner.identity().mtu != mtu
            || request.is_some_and(|request| {
                request.config().mtu != mtu
                    || request.config().addresses.len()
                        != usize::from(sources.ipv4.is_some()) + usize::from(sources.ipv6.is_some())
                    || request
                        .config()
                        .addresses
                        .iter()
                        .any(|source| !sources.contains(*source))
            })
        {
            return Err(AttachmentError::Invalid);
        }
        let predecessor = owner
            .capability()
            .sink()
            .ok_or(AttachmentError::CaptureUnready)?;
        owner.suspend_sink(&predecessor)?;
        let previous_config = capture.config.take();
        capture.predecessor = Some(capture.epoch);
        capture.epoch = generation.get();
        capture.config = request.map(|request| request.0.clone());
        let change = CaptureEpochChange {
            inner: self.inner.clone(),
            session: self.generation,
            generation: generation.get(),
            predecessor,
            previous_config,
            unbound: Mutex::new(Some(generation)),
            completed: false,
        };
        self.inner.publish(&state);
        self.inner.replies.notify_one();
        Ok(change)
    }

    /// A new target request may borrow this already observed fd epoch only for
    /// an exactly equal configuration. Changes need the owner's handover path.
    pub fn acknowledge_request(
        &self,
        request: &PendingCaptureRequest,
    ) -> Result<(), AttachmentError> {
        let receipt = CaptureReceipt {
            inner: Arc::downgrade(&self.inner),
            generation: self
                .inner
                .state
                .lock()
                .expect("attachment state")
                .capture
                .as_ref()
                .filter(|c| c.generation == self.generation)
                .map(|c| c.epoch)
                .ok_or(AttachmentError::Stale)?,
            configuration: Weak::new(),
        };
        receipt.acknowledge(request)
    }
    /// A feed retains this weak revoker, never the capture owner itself.
    pub fn revoker(&self) -> impl Fn() + Send + Sync + 'static {
        epoch_revoker(&self.inner, self.generation, self.generation)
    }
    /// Capture-adapter entry after exact fd/network/config observation. This
    /// consumes the unrepeatable identity token; loss requires joined replacement.
    pub fn bind_observed_identity(
        &self,
        interface: &str,
        network_handle: u64,
        sources: RelaySources,
        mtu: u16,
    ) -> Result<CaptureReceipt, AttachmentError> {
        AttachmentBroker {
            inner: self.inner.clone(),
        }
        .observed_capture(self, interface, Some(network_handle), sources, mtu)
    }
    /// Partial uses the same logical lease and checked sink without acquiring a
    /// NetworkCallback dependency. The fd name and plain-IP format are native.
    pub fn bind_partial_identity(
        &self,
        interface: &str,
        sources: RelaySources,
        mtu: u16,
    ) -> Result<CaptureReceipt, AttachmentError> {
        AttachmentBroker {
            inner: self.inner.clone(),
        }
        .observed_capture(self, interface, None, sources, mtu)
    }
    pub fn retire(&self) {
        let mut state = self.inner.state.lock().expect("attachment state");
        if state
            .capture
            .as_ref()
            .is_some_and(|c| c.generation == self.generation)
        {
            state.retire_capture();
        }
        self.inner.publish(&state);
        self.inner.replies.notify_one();
    }
    pub fn try_send(&self, bytes: &[u8]) -> Result<(), AttachmentError> {
        self.try_send_to(RelayTargetId::MULLVAD, bytes)
    }

    pub fn try_send_to(&self, target: RelayTargetId, bytes: &[u8]) -> Result<(), AttachmentError> {
        let state = self.inner.state.lock().expect("attachment state");
        if !state
            .capture
            .as_ref()
            .is_some_and(|c| c.generation == self.generation)
        {
            return Err(AttachmentError::Stale);
        }
        let attempt = state
            .attempt(target)
            .ok_or(AttachmentError::OrdinaryUnready)?;
        enqueue(&self.inner, attempt, bytes, true)
    }
    /// Checked Local sink authority, independent of every target's readiness.
    pub fn capability(&self) -> Option<RelayCapture> {
        let state = self.inner.state.lock().expect("attachment state");
        if !state
            .capture
            .as_ref()
            .is_some_and(|c| c.generation == self.generation)
        {
            return None;
        }
        Some(state.capture.as_ref()?.owner.as_ref()?.capability())
    }
    /// Event-driven, cancellation-safe receive. An empty queue never polls on a
    /// timer; configuration, cancellation and new replies wake the capture owner.
    pub async fn reply(&self) -> Result<AttachmentReply, AttachmentError> {
        loop {
            let wake = self.inner.replies.notified();
            {
                let mut state = self.inner.state.lock().expect("attachment state");
                if !state
                    .capture
                    .as_ref()
                    .is_some_and(|c| c.generation == self.generation)
                {
                    return Err(AttachmentError::Stale);
                }
                for offset in 0..MAX_TARGETS {
                    let index = (state.next_reply + offset) % MAX_TARGETS;
                    let Some(attempt) = state.attempts[index].clone() else {
                        continue;
                    };
                    let packet = attempt
                        .queues
                        .lock()
                        .expect("attachment queues")
                        .inbound
                        .pop_front();
                    if let Some(packet) = packet {
                        state.next_reply = (index + 1) % MAX_TARGETS;
                        return Ok(AttachmentReply {
                            inner: Arc::downgrade(&self.inner),
                            attempt: attempt.clone(),
                            packet,
                        });
                    }
                }
            }
            wake.await;
        }
    }
}

fn epoch_revoker(
    inner: &Arc<Inner>,
    session: u64,
    epoch: u64,
) -> impl Fn() + Send + Sync + 'static {
    let inner = Arc::downgrade(inner);
    move || {
        if let Some(inner) = inner.upgrade() {
            let mut state = inner.state.lock().expect("attachment state");
            if state
                .capture
                .as_ref()
                .is_some_and(|c| c.generation == session && c.epoch == epoch)
            {
                state.retire_capture();
            }
            inner.publish(&state);
            inner.replies.notify_one();
        }
    }
}

impl CaptureEpochChange {
    pub fn generation(&self) -> u64 {
        self.generation
    }

    pub async fn wait_predecessor_release(&self) {
        if let Some(config) = &self.previous_config {
            PendingCaptureRequest(config.clone()).wait_release().await;
        }
    }

    pub fn revoker(&self) -> impl Fn() + Send + Sync + 'static {
        epoch_revoker(&self.inner, self.session, self.generation)
    }

    pub fn bind_identity(
        &self,
        interface: &str,
        network_handle: Option<u64>,
        sources: RelaySources,
        mtu: u16,
    ) -> Result<CaptureReceipt, AttachmentError> {
        let mut state = self.inner.state.lock().expect("attachment state");
        let capture = state
            .capture
            .as_mut()
            .filter(|c| c.generation == self.session && c.epoch == self.generation)
            .ok_or(AttachmentError::Stale)?;
        let owner = capture
            .owner
            .as_ref()
            .ok_or(AttachmentError::CaptureUnready)?;
        // Validate before consuming the one-shot token so an invalid observation
        // cannot be mistaken for an already adopted descriptor.
        if owner.identity().sources != sources
            || owner.identity().mtu != mtu
            || (capture.config.is_some() && network_handle.is_none())
        {
            return Err(AttachmentError::Invalid);
        }
        let token = self
            .unbound
            .lock()
            .expect("capture epoch")
            .take()
            .ok_or(AttachmentError::Stale)?;
        owner.bind_sink(
            token,
            interface,
            network_handle,
            sources,
            mtu,
            self.inner.capture.as_ref(),
        )?;
        let receipt = CaptureReceipt {
            inner: Arc::downgrade(&self.inner),
            generation: self.generation,
            configuration: capture
                .config
                .as_ref()
                .map(Arc::downgrade)
                .unwrap_or_default(),
        };
        self.inner.publish(&state);
        self.inner.replies.notify_one();
        Ok(receipt)
    }

    /// Called after the old reactor/fd are dropped and its exact platform finish
    /// succeeds. Failed finish retains this transaction and blocks a third epoch.
    pub fn finish(&mut self) -> Result<(), AttachmentError> {
        if self
            .previous_config
            .as_ref()
            .is_some_and(|config| !config.release_ready())
        {
            return Err(AttachmentError::Busy);
        }
        let mut state = self.inner.state.lock().expect("attachment state");
        let capture = state
            .capture
            .as_mut()
            .filter(|c| c.generation == self.session && c.epoch == self.generation)
            .ok_or(AttachmentError::Stale)?;
        if capture
            .owner
            .as_ref()
            .and_then(|owner| owner.capability().sink())
            .is_none()
        {
            return Err(AttachmentError::CaptureUnready);
        }
        capture.predecessor = None;
        self.completed = true;
        self.inner.publish(&state);
        Ok(())
    }

    /// Requires positive pre-establish platform evidence and revalidated old
    /// observation. This never succeeds after binding a successor or retirement.
    pub fn rollback(&mut self) -> Result<(), AttachmentError> {
        let mut state = self.inner.state.lock().expect("attachment state");
        let capture = state
            .capture
            .as_mut()
            .filter(|c| c.generation == self.session && c.epoch == self.generation)
            .ok_or(AttachmentError::Stale)?;
        capture
            .owner
            .as_ref()
            .ok_or(AttachmentError::CaptureUnready)?
            .resume_sink(&self.predecessor)?;
        capture.epoch = capture.predecessor.take().ok_or(AttachmentError::Stale)?;
        capture.config = self.previous_config.take();
        self.completed = true;
        self.inner.publish(&state);
        self.inner.replies.notify_one();
        Ok(())
    }
}

impl Drop for CaptureEpochChange {
    fn drop(&mut self) {
        if !self.completed {
            (epoch_revoker(&self.inner, self.session, self.generation))();
        }
    }
}

impl Drop for CaptureLease {
    fn drop(&mut self) {
        self.retire();
    }
}

fn enqueue(
    inner: &Inner,
    attempt: &Attempt,
    bytes: &[u8],
    outbound: bool,
) -> Result<(), AttachmentError> {
    if !attempt.owner.capability().current() {
        return Err(AttachmentError::OrdinaryUnready);
    }
    let mut queues = attempt.queues.lock().expect("attachment queues");
    let queue = if outbound {
        &mut queues.outbound
    } else {
        &mut queues.inbound
    };
    if queue.len() == PACKET_CAPACITY {
        return Err(AttachmentError::Full);
    }
    let packet = attempt
        .owner
        .capability()
        .packet(RelayBuffer::copy_from(bytes, inner.application.as_ref())?)?;
    queue.push_back(packet);
    if outbound {
        attempt.outbound.notify_one();
    } else {
        inner.replies.notify_one();
    }
    Ok(())
}

impl AttemptControl {
    /// Private control may run while ordinary authority is still Pending.
    pub fn live(&self) -> bool {
        !*self.attempt.cancelled.borrow()
    }
    pub fn capability(&self) -> RelayAttempt {
        self.attempt.owner.capability()
    }
    pub fn current(&self) -> bool {
        self.capability().current()
    }
    /// Called by the transport owner after installing the real carrier and
    /// authenticating connectivity. Capture readiness is checked again here.
    pub fn activate(&self) -> Result<(), AttachmentError> {
        self.activate_checked(None)
    }
    /// Initial activation still requires the exact acquisition epoch. An
    /// already-active independent target follows the checked current sink after
    /// handover; its predecessor receipt deliberately remains stale. Validate
    /// both under the broker lock, ordered against epoch replacement/retirement.
    pub fn activate_with_receipt(&self, receipt: &CaptureReceipt) -> Result<(), AttachmentError> {
        self.activate_checked(Some(receipt))
    }
    fn activate_checked(&self, receipt: Option<&CaptureReceipt>) -> Result<(), AttachmentError> {
        let inner = self.inner.upgrade().ok_or(AttachmentError::Closed)?;
        let state = inner.state.lock().expect("attachment state");
        if !state
            .attempt(self.attempt.target)
            .is_some_and(|a| Arc::ptr_eq(a, &self.attempt))
        {
            return Err(AttachmentError::Stale);
        }
        if receipt.is_some_and(|receipt| !self.current() && !receipt.matches(&inner, &state)) {
            return Err(AttachmentError::CaptureUnready);
        }
        self.attempt.owner.activate()?;
        inner.publish(&state);
        Ok(())
    }
    pub async fn cancelled(&self) {
        let mut cancelled = self.attempt.cancelled.subscribe();
        while !*cancelled.borrow_and_update() {
            if cancelled.changed().await.is_err() {
                break;
            }
        }
    }
    pub fn detach(&self) {
        if let Some(inner) = self.inner.upgrade() {
            let mut state = inner.state.lock().expect("attachment state");
            if state
                .attempt(self.attempt.target)
                .is_some_and(|a| Arc::ptr_eq(a, &self.attempt))
            {
                state.detach_target(self.attempt.target);
            }
            inner.publish(&state);
            inner.replies.notify_one();
        }
    }
}
impl Drop for AttemptControl {
    fn drop(&mut self) {
        self.detach();
    }
}

impl TransportReceive {
    pub async fn recv(&mut self) -> Result<RelayPacket, AttachmentError> {
        loop {
            let wake = self.control.attempt.outbound.notified();
            if *self.control.attempt.cancelled.borrow() {
                return Err(AttachmentError::Stale);
            }
            if let Some(packet) = self
                .control
                .attempt
                .queues
                .lock()
                .expect("attachment queues")
                .outbound
                .pop_front()
            {
                return Ok(packet);
            }
            wake.await;
        }
    }
}

impl TransportSend {
    /// Only authenticated return traffic, after private-control demultiplexing.
    /// Bytes are opaque here; this capability supplies the exact attempt owner.
    pub fn try_send(&self, bytes: &[u8]) -> Result<(), AttachmentError> {
        let inner = self
            .control
            .inner
            .upgrade()
            .ok_or(AttachmentError::Closed)?;
        let state = inner.state.lock().expect("attachment state");
        if !state
            .attempt(self.control.attempt.target)
            .is_some_and(|a| Arc::ptr_eq(a, &self.control.attempt))
        {
            return Err(AttachmentError::Stale);
        }
        enqueue(&inner, &self.control.attempt, bytes, false)
    }
}

impl AttachmentReply {
    pub fn write_to(
        &mut self,
        sink: &RelaySink,
        operation: impl FnOnce(&[u8]) -> io::Result<usize>,
    ) -> RelayWriteOutcome {
        let outcome = self.packet.write_to(sink, operation);
        self.complete_write(outcome)
    }

    pub fn write(
        &mut self,
        operation: impl FnOnce(&[u8]) -> io::Result<usize>,
    ) -> RelayWriteOutcome {
        let outcome = self.packet.write(operation);
        self.complete_write(outcome)
    }

    fn complete_write(&self, outcome: RelayWriteOutcome) -> RelayWriteOutcome {
        if matches!(outcome, RelayWriteOutcome::Fatal(_)) {
            // packet.write has released all authority guards before broker entry.
            let control = AttemptControl {
                inner: self.inner.clone(),
                attempt: self.attempt.clone(),
            };
            control.detach();
        }
        outcome
    }
}

#[cfg(test)]
mod tests;
