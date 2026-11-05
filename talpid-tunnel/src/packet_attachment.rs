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
    RelayAttempt, RelayAttemptOwner, RelayBuffer, RelayBufferAllocator, RelayBufferReservation,
    RelayCaptureGeneration, RelayCaptureOwner, RelayFlowError, RelayPacket, RelaySources,
    RelayWriteOutcome,
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

/// Actor-side request capability. An old acknowledgement cannot satisfy a new
/// request, even when configurations compare equal.
#[derive(Clone)]
pub struct PendingCaptureRequest(Arc<Configuration>);

struct Capture {
    generation: u64,
    config: Option<Arc<Configuration>>,
    owner: Option<RelayCaptureOwner>,
}

struct Queues {
    outbound: VecDeque<RelayPacket>,
    inbound: VecDeque<RelayPacket>,
}

struct Attempt {
    id: u64,
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
    attempt: Option<Arc<Attempt>>,
    local_routes: Vec<ipnetwork::IpNetwork>,
    route_storage: Option<Arc<dyn RelayBufferReservation>>,
    paused: bool,
}

impl State {
    fn detach(&mut self) {
        if let Some(attempt) = self.attempt.take() {
            attempt.retire();
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
            capture_generation: self.capture.as_ref().map(|c| c.generation),
            capture_ready: self.capture.as_ref().is_some_and(|c| c.owner.is_some()),
            attachment: self.attempt.as_ref().map(|a| a.id),
            ordinary_ready: self
                .attempt
                .as_ref()
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

/// Only the capture owner can issue this after actual identity observation.
#[derive(Clone)]
pub struct CaptureReceipt {
    inner: Weak<Inner>,
    generation: u64,
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
            attempt: None,
            local_routes: Vec::new(),
            route_storage: None,
            paused: false,
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
        if state.request.is_some() || state.capture.is_some() || state.attempt.is_some() {
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
        network_handle: u64,
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
        let generation = lease
            .unbound
            .lock()
            .expect("capture generation")
            .take()
            .ok_or(AttachmentError::Stale)?;
        let owner = RelayCaptureOwner::new(
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
                .is_some_and(|r| Arc::ptr_eq(r, &request.0))
        {
            return Err(AttachmentError::Stale);
        }
        request
            .0
            .status
            .send_replace(RequestStatus::Ready(receipt.clone()));
        state.request.take();
        self.inner.publish(&state);
        Ok(())
    }

    pub fn acquire(&self, receipt: &CaptureReceipt) -> Result<TransportPair, AttachmentError> {
        let storage = self.inner.capture.try_reserve(CHANNEL_STORAGE)?;
        let mut state = self.inner.state.lock().expect("attachment state");
        if state.paused {
            return Err(AttachmentError::OrdinaryUnready);
        }
        if !receipt.matches(&self.inner, &state) {
            return Err(AttachmentError::CaptureUnready);
        }
        if state.attempt.is_some() {
            return Err(AttachmentError::Busy);
        }
        if !state
            .capture
            .as_ref()
            .and_then(|c| c.config.as_ref())
            .is_some_and(|r| matches!(*r.status.borrow(), RequestStatus::Ready(_)))
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
            .open_attempt(self.inner.capture.as_ref())?;
        state
            .capture
            .as_ref()
            .and_then(|capture| capture.config.as_ref())
            .expect("configured capture")
            .update_release(|release| release.transport_joined = false);
        let attempt = Arc::new(Attempt {
            id,
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
        state.attempt = Some(attempt);
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

    /// Provider-side reconfiguration in the selected managed mode. Platform
    /// descriptor release remains the capture actor's joined responsibility.
    pub fn retire_transport(&self) {
        let mut state = self.inner.state.lock().expect("attachment state");
        state.retire_capture();
        if let Some(request) = state.request.take() {
            request.status.send_replace(RequestStatus::Cancelled);
        }
        self.inner.publish(&state);
        self.inner.replies.notify_one();
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
        state.detach();
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
                c.generation == self.generation && c.owner.is_some() && c.config.is_some()
            })
    }
    pub fn current(&self) -> bool {
        self.inner.upgrade().is_some_and(|inner| {
            self.matches(&inner, &inner.state.lock().expect("attachment state"))
        })
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
        if let Some(inner) = self.inner.upgrade() {
            let mut state = inner.state.lock().expect("attachment state");
            if state
                .request
                .as_ref()
                .is_some_and(|r| Arc::ptr_eq(r, &self.request))
            {
                state.request.take();
            }
            if state
                .capture
                .as_ref()
                .and_then(|c| c.config.as_ref())
                .is_some_and(|r| Arc::ptr_eq(r, &self.request))
            {
                state.retire_capture();
            }
            self.request.status.send_replace(RequestStatus::Cancelled);
            inner.publish(&state);
            inner.replies.notify_one();
        }
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
    /// A feed retains this weak revoker, never the capture owner itself.
    pub fn revoker(&self) -> impl Fn() + Send + Sync + 'static {
        let inner = Arc::downgrade(&self.inner);
        let generation = self.generation;
        move || {
            if let Some(inner) = inner.upgrade() {
                let mut state = inner.state.lock().expect("attachment state");
                if state
                    .capture
                    .as_ref()
                    .is_some_and(|c| c.generation == generation)
                {
                    state.retire_capture();
                }
                inner.publish(&state);
                inner.replies.notify_one();
            }
        }
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
        .observed_capture(self, interface, network_handle, sources, mtu)
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
        let state = self.inner.state.lock().expect("attachment state");
        if !state
            .capture
            .as_ref()
            .is_some_and(|c| c.generation == self.generation)
        {
            return Err(AttachmentError::Stale);
        }
        let attempt = state
            .attempt
            .as_ref()
            .ok_or(AttachmentError::OrdinaryUnready)?;
        enqueue(&self.inner, attempt, bytes, true)
    }
    /// Snapshot the exact active attempt for checked Local sink operations.
    /// The returned capability must not be replaced on a live frontend.
    pub fn ordinary_attempt(&self) -> Option<RelayAttempt> {
        let state = self.inner.state.lock().expect("attachment state");
        if !state
            .capture
            .as_ref()
            .is_some_and(|c| c.generation == self.generation)
        {
            return None;
        }
        let attempt = state.attempt.as_ref()?.owner.capability();
        attempt.current().then_some(attempt)
    }
    /// Event-driven, cancellation-safe receive. An empty queue never polls on a
    /// timer; configuration, cancellation and new replies wake the capture owner.
    pub async fn reply(&self) -> Result<AttachmentReply, AttachmentError> {
        loop {
            let wake = self.inner.replies.notified();
            {
                let state = self.inner.state.lock().expect("attachment state");
                if !state
                    .capture
                    .as_ref()
                    .is_some_and(|c| c.generation == self.generation)
                {
                    return Err(AttachmentError::Stale);
                }
                if let Some(attempt) = &state.attempt {
                    if *attempt.cancelled.borrow() {
                        return Err(AttachmentError::Stale);
                    }
                    let packet = attempt
                        .queues
                        .lock()
                        .expect("attachment queues")
                        .inbound
                        .pop_front();
                    if let Some(packet) = packet {
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
        let inner = self.inner.upgrade().ok_or(AttachmentError::Closed)?;
        let state = inner.state.lock().expect("attachment state");
        if !state
            .attempt
            .as_ref()
            .is_some_and(|a| Arc::ptr_eq(a, &self.attempt))
        {
            return Err(AttachmentError::Stale);
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
                .attempt
                .as_ref()
                .is_some_and(|a| Arc::ptr_eq(a, &self.attempt))
            {
                state.detach();
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
            .attempt
            .as_ref()
            .is_some_and(|a| Arc::ptr_eq(a, &self.control.attempt))
        {
            return Err(AttachmentError::Stale);
        }
        enqueue(&inner, &self.control.attempt, bytes, false)
    }
}

impl AttachmentReply {
    pub fn write(
        &mut self,
        operation: impl FnOnce(&[u8]) -> io::Result<usize>,
    ) -> RelayWriteOutcome {
        let outcome = self.packet.write(operation);
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
