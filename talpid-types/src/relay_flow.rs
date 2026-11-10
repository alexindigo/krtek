//! Shared storage capabilities. A reservation is never packet or policy authority.
use std::{
    fmt, io,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    sync::{
        Arc, Mutex, Weak,
        atomic::{AtomicU64, Ordering},
    },
};

pub const MAX_RELAY_PACKET_SIZE: usize = 65_575;
pub const BUFFER_OVERHEAD: usize = 512;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RelayFlowError {
    Invalid,
    Full,
    Stale,
    Closed,
}

pub trait RelayBufferReservation: Send + Sync {
    fn bytes(&self) -> usize;
    /// Repeated requests share one child account. Children retain the parent
    /// charge, and its metadata is withheld from spendable child credit.
    fn allocator(&self) -> Result<Arc<dyn RelayBufferAllocator>, RelayFlowError>;
    /// Consume unique, unlent credit into tickets; refund any unused remainder.
    fn partition(
        self: Arc<Self>,
        sizes: &[usize],
    ) -> Result<Vec<Arc<dyn RelayBufferReservation>>, RelayFlowError>;
}

pub trait RelayBufferAllocator: Send + Sync {
    /// Refuse immediately, without allocating packet bytes or installing a waiter.
    fn try_reserve(&self, bytes: usize) -> Result<Arc<dyn RelayBufferReservation>, RelayFlowError>;
}

/// Fixed backing storage and its exclusive ticket. No growth or uncharged Vec
/// extraction is exposed. Moving or borrowing bytes retains their reservation.
pub struct RelayBuffer {
    bytes: Vec<u8>,
    _charge: Arc<dyn RelayBufferReservation>,
}

impl RelayBuffer {
    pub fn from_reservation(
        bytes: Vec<u8>,
        charge: Arc<dyn RelayBufferReservation>,
    ) -> Result<Self, RelayFlowError> {
        let needed = bytes
            .capacity()
            .checked_add(BUFFER_OVERHEAD)
            .ok_or(RelayFlowError::Invalid)?;
        if bytes.len() > MAX_RELAY_PACKET_SIZE || needed > charge.bytes() {
            return Err(RelayFlowError::Invalid);
        }
        // Validate exclusive ownership, including the absence of lent child
        // credit. A cloned ticket cannot fund independent backing allocations.
        let mut parts = charge.partition(&[needed])?;
        Ok(Self {
            bytes,
            _charge: parts.pop().expect("one storage ticket"),
        })
    }

    pub fn copy_from(
        bytes: &[u8],
        buffers: &dyn RelayBufferAllocator,
    ) -> Result<Self, RelayFlowError> {
        if bytes.len() > MAX_RELAY_PACKET_SIZE {
            return Err(RelayFlowError::Invalid);
        }
        let charge = buffers.try_reserve(bytes.len() + BUFFER_OVERHEAD)?;
        Self::from_reservation(bytes.to_vec(), charge)
    }

    /// Move encoder storage already covered by a transient peak reservation to
    /// its retained account. The peak remains charged throughout conversion.
    pub fn from_region(
        bytes: Vec<u8>,
        buffers: &dyn RelayBufferAllocator,
        transient: &dyn RelayBufferReservation,
    ) -> Result<Self, RelayFlowError> {
        let needed = bytes
            .capacity()
            .checked_add(BUFFER_OVERHEAD)
            .ok_or(RelayFlowError::Invalid)?;
        if bytes.len() > MAX_RELAY_PACKET_SIZE || needed > transient.bytes() {
            return Err(RelayFlowError::Invalid);
        }
        Self::from_reservation(bytes, buffers.try_reserve(needed)?)
    }

    pub fn as_slice(&self) -> &[u8] {
        &self.bytes
    }
}

impl std::ops::Deref for RelayBuffer {
    type Target = [u8];
    fn deref(&self) -> &[u8] {
        &self.bytes
    }
}
impl std::ops::DerefMut for RelayBuffer {
    fn deref_mut(&mut self) -> &mut [u8] {
        &mut self.bytes
    }
}
impl fmt::Debug for RelayBuffer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RelayBuffer")
            .field("bytes", &self.bytes.len())
            .finish_non_exhaustive()
    }
}

/// Diagnostic generation, allocated before platform open. Numbers alone never
/// authorize a write: the retained capture and attempt capabilities do that.
#[derive(Debug, Eq, PartialEq)]
pub struct RelayCaptureGeneration(u64);

impl RelayCaptureGeneration {
    pub fn fresh() -> Result<Self, RelayFlowError> {
        static NEXT: AtomicU64 = AtomicU64::new(1);
        NEXT.fetch_update(Ordering::Relaxed, Ordering::Relaxed, |n| n.checked_add(1))
            .map(Self)
            .map_err(|_| RelayFlowError::Full)
    }

    pub fn get(&self) -> u64 {
        self.0
    }
}

/// The immutable assigned (or partial-capture) source set. No transport policy.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RelaySources {
    pub ipv4: Option<Ipv4Addr>,
    pub ipv6: Option<Ipv6Addr>,
}

impl RelaySources {
    pub fn contains(self, source: IpAddr) -> bool {
        match source {
            IpAddr::V4(ip) => self.ipv4 == Some(ip),
            IpAddr::V6(ip) => self.ipv6 == Some(ip),
        }
    }
}

/// App-facing identity belongs to the logical session, not to a descriptor.
#[derive(Debug)]
pub struct RelayCaptureIdentity {
    pub generation: RelayCaptureGeneration,
    pub sources: RelaySources,
    pub mtu: u16,
}

/// One actual descriptor epoch. Partial captures have no NetworkCallback handle;
/// managed captures require the first full-width observed Android handle.
pub struct RelaySinkIdentity {
    pub generation: u64,
    pub interface: String,
    pub network_handle: Option<u64>,
    _charge: Arc<dyn RelayBufferReservation>,
}

impl fmt::Debug for RelaySinkIdentity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RelaySinkIdentity")
            .field("generation", &self.generation)
            .field("interface", &self.interface)
            .field("network_handle", &self.network_handle)
            .finish_non_exhaustive()
    }
}

/// A selector receipt, never ownership of the fd itself. Only the session owner
/// can install/resume it. A retained receipt cannot select a replacement sink.
#[derive(Clone, Debug)]
pub struct RelaySink(Arc<RelaySinkIdentity>);

impl RelaySink {
    pub fn identity(&self) -> &RelaySinkIdentity {
        &self.0
    }
}

struct Capture {
    identity: RelayCaptureIdentity,
    state: Mutex<CaptureState>,
    _charge: Arc<dyn RelayBufferReservation>,
}

struct CaptureState {
    live: bool,
    sink: Option<RelaySink>,
    last_sink: u64,
    attempts: [Weak<Attempt>; MAX_TARGETS],
}

/// Routing identity, separate from the unrepeatable lifetime of an attempt.
/// Only Mullvad is installed in production. The bounded second slot also lets
/// lifetime tests exercise an unrelated target without a plugin registry.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RelayTargetId(u64);

pub const MAX_TARGETS: usize = 2;

impl RelayTargetId {
    pub const MULLVAD: Self = Self(1);

    pub fn new(id: u64) -> Result<Self, RelayFlowError> {
        if id == 0 {
            return Err(RelayFlowError::Invalid);
        }
        Ok(Self(id))
    }

    pub fn get(self) -> u64 {
        self.0
    }
}

/// A logical capture capability. Local output borrows this, never a transport
/// attempt. Only the sole owner can retire it.
#[derive(Clone)]
pub struct RelayCapture(Arc<Capture>);

impl RelayCapture {
    pub fn with_current<T>(&self, operation: impl FnOnce() -> T) -> Result<T, RelayFlowError> {
        let state = self.0.state.lock().expect("capture state");
        if !state.live {
            return Err(RelayFlowError::Stale);
        }
        Ok(operation())
    }

    pub fn current(&self) -> bool {
        self.with_current(|| ()).is_ok()
    }

    pub fn sink(&self) -> Option<RelaySink> {
        let state = self.0.state.lock().expect("capture state");
        state.live.then(|| state.sink.clone()).flatten()
    }

    /// Serialize the final nonblocking syscall with sink selection and session
    /// retirement. No await, JNI or owner/broker reentry inside the callback.
    pub fn with_sink<T>(
        &self,
        sink: &RelaySink,
        operation: impl FnOnce() -> T,
    ) -> Result<T, RelayFlowError> {
        let state = self.0.state.lock().expect("capture state");
        if !state.live
            || !state
                .sink
                .as_ref()
                .is_some_and(|current| Arc::ptr_eq(&current.0, &sink.0))
        {
            return Err(RelayFlowError::Stale);
        }
        Ok(operation())
    }
}

/// Sole lifecycle owner. Dropping it revokes all retained packets, but their
/// backing allocations and charges survive until the actual last reference.
pub struct RelayCaptureOwner(Arc<Capture>);

impl RelayCaptureOwner {
    pub fn new(
        generation: RelayCaptureGeneration,
        interface: &str,
        network_handle: u64,
        sources: RelaySources,
        mtu: u16,
        buffers: &dyn RelayBufferAllocator,
    ) -> Result<Self, RelayFlowError> {
        Self::with_identity(
            generation,
            interface,
            Some(network_handle),
            sources,
            mtu,
            buffers,
        )
    }

    pub fn with_identity(
        generation: RelayCaptureGeneration,
        interface: &str,
        network_handle: Option<u64>,
        sources: RelaySources,
        mtu: u16,
        buffers: &dyn RelayBufferAllocator,
    ) -> Result<Self, RelayFlowError> {
        let epoch = generation.get();
        let owner = Self::session(generation, sources, mtu, buffers)?;
        // The initial owner reservation covers its fixed metadata and first sink.
        // Every later sink has its own reservation, retained by old receipts too.
        let sink = Self::checked_sink(epoch, interface, network_handle, owner.0._charge.clone())?;
        {
            let mut state = owner.0.state.lock().expect("capture state");
            state.last_sink = epoch;
            state.sink = Some(sink);
        }
        Ok(owner)
    }

    pub fn session(
        generation: RelayCaptureGeneration,
        sources: RelaySources,
        mtu: u16,
        buffers: &dyn RelayBufferAllocator,
    ) -> Result<Self, RelayFlowError> {
        if (sources.ipv4.is_none() && sources.ipv6.is_none()) || mtu == 0 {
            return Err(RelayFlowError::Invalid);
        }
        let charge = buffers.try_reserve(BUFFER_OVERHEAD)?;
        Ok(Self(Arc::new(Capture {
            identity: RelayCaptureIdentity {
                generation,
                sources,
                mtu,
            },
            state: Mutex::new(CaptureState {
                live: true,
                sink: None,
                last_sink: 0,
                attempts: std::array::from_fn(|_| Weak::new()),
            }),
            _charge: charge,
        })))
    }

    pub fn identity(&self) -> &RelayCaptureIdentity {
        &self.0.identity
    }

    fn checked_sink(
        generation: u64,
        interface: &str,
        network_handle: Option<u64>,
        charge: Arc<dyn RelayBufferReservation>,
    ) -> Result<RelaySink, RelayFlowError> {
        if generation == 0
            || interface.is_empty()
            || interface.len() >= 16
            || !interface
                .bytes()
                .all(|c| c.is_ascii_alphanumeric() || b"_.-".contains(&c))
            || network_handle == Some(0)
        {
            return Err(RelayFlowError::Invalid);
        }
        Ok(RelaySink(Arc::new(RelaySinkIdentity {
            generation,
            interface: interface.to_owned(),
            network_handle,
            _charge: charge,
        })))
    }

    /// Bind only after descriptor/format/config validation (and, for managed
    /// capture, exact observation). A new sink never changes app source identity.
    pub fn bind_sink(
        &self,
        generation: RelayCaptureGeneration,
        interface: &str,
        network_handle: Option<u64>,
        sources: RelaySources,
        mtu: u16,
        buffers: &dyn RelayBufferAllocator,
    ) -> Result<RelaySink, RelayFlowError> {
        let mut state = self.0.state.lock().expect("capture state");
        if !state.live || state.sink.is_some() || generation.get() <= state.last_sink {
            return Err(RelayFlowError::Stale);
        }
        if self.identity().sources != sources || self.identity().mtu != mtu {
            return Err(RelayFlowError::Invalid);
        }
        let sink = Self::checked_sink(
            generation.get(),
            interface,
            network_handle,
            buffers.try_reserve(BUFFER_OVERHEAD)?,
        )?;
        state.last_sink = generation.get();
        state.sink = Some(sink.clone());
        let records = sink_records(&state, true, "sink-bound");
        drop(state);
        emit_records(records);
        Ok(sink)
    }

    /// Expected descriptor loss during establish suspends the selector, not the
    /// logical session. The exact receipt prevents old cleanup suspending a new fd.
    pub fn suspend_sink(&self, sink: &RelaySink) -> Result<(), RelayFlowError> {
        let mut state = self.0.state.lock().expect("capture state");
        if !state.live
            || !state
                .sink
                .as_ref()
                .is_some_and(|current| Arc::ptr_eq(&current.0, &sink.0))
        {
            return Err(RelayFlowError::Stale);
        }
        state.sink = None;
        let records = sink_records(&state, false, "sink-suspended");
        drop(state);
        emit_records(records);
        Ok(())
    }

    /// Only for positive pre-establish retention, with the predecessor's
    /// observation rechecked by the caller. Cannot resurrect a replaced epoch.
    pub fn resume_sink(&self, sink: &RelaySink) -> Result<(), RelayFlowError> {
        let mut state = self.0.state.lock().expect("capture state");
        if !state.live || state.sink.is_some() || state.last_sink != sink.identity().generation {
            return Err(RelayFlowError::Stale);
        }
        state.sink = Some(sink.clone());
        let records = sink_records(&state, true, "sink-resumed");
        drop(state);
        emit_records(records);
        Ok(())
    }

    pub fn retire(&self) {
        let mut state = self.0.state.lock().expect("capture state");
        if !state.live {
            return;
        }
        state.live = false;
        let records = std::array::from_fn(|index| {
            state.attempts[index].upgrade().and_then(|attempt| {
                let mut phase = attempt.phase.lock().expect("attempt state");
                let changed = *phase != AttemptPhase::Retired;
                *phase = AttemptPhase::Retired;
                changed.then(|| AuthorityRecord::capture(&attempt, false, "capture-retired"))
            })
        });
        drop(state);
        emit_records(records);
    }

    pub fn capability(&self) -> RelayCapture {
        RelayCapture(self.0.clone())
    }

    pub fn open_attempt(
        &self,
        buffers: &dyn RelayBufferAllocator,
    ) -> Result<RelayAttemptOwner, RelayFlowError> {
        self.open_target(
            RelayTargetId::MULLVAD,
            self.0.identity.sources,
            self.0.identity.mtu,
            buffers,
        )
    }

    /// Each target has its own immutable source configuration and attempt. A
    /// replacement requires that exact target's explicit retirement; identical
    /// addresses never reuse authority or affect another target or Local.
    pub fn open_target(
        &self,
        target: RelayTargetId,
        sources: RelaySources,
        mtu: u16,
        buffers: &dyn RelayBufferAllocator,
    ) -> Result<RelayAttemptOwner, RelayFlowError> {
        if (sources.ipv4.is_none() && sources.ipv6.is_none()) || mtu == 0 {
            return Err(RelayFlowError::Invalid);
        }
        let mut capture = self.0.state.lock().expect("capture state");
        if !capture.live {
            return Err(RelayFlowError::Stale);
        }
        let live = |weak: &Weak<Attempt>| {
            weak.upgrade()
                .filter(|old| *old.phase.lock().expect("attempt state") != AttemptPhase::Retired)
        };
        if capture
            .attempts
            .iter()
            .filter_map(live)
            .any(|old| old.target == target)
        {
            return Err(RelayFlowError::Invalid);
        }
        let slot = capture
            .attempts
            .iter_mut()
            .find(|slot| live(slot).is_none())
            .ok_or(RelayFlowError::Full)?;
        let charge = buffers.try_reserve(BUFFER_OVERHEAD)?;
        let attempt = Arc::new(Attempt {
            serial: serial(),
            capture: self.0.clone(),
            target,
            sources,
            mtu,
            phase: Mutex::new(AttemptPhase::Pending),
            _charge: charge,
        });
        *slot = Arc::downgrade(&attempt);
        let record = AuthorityRecord::capture(&attempt, false, "pending");
        drop(capture);
        record.emit();
        Ok(RelayAttemptOwner(RelayAttempt(attempt)))
    }
}

impl Drop for RelayCaptureOwner {
    fn drop(&mut self) {
        self.retire();
    }
}

#[derive(Eq, PartialEq)]
enum AttemptPhase {
    Pending,
    Active,
    Retired,
}

struct Attempt {
    serial: u64,
    capture: Arc<Capture>,
    target: RelayTargetId,
    sources: RelaySources,
    mtu: u16,
    phase: Mutex<AttemptPhase>,
    _charge: Arc<dyn RelayBufferReservation>,
}

/// A semantic authority transition, captured at the actual switch under its
/// guards and emitted only after releasing them. No per-packet logging.
struct AuthorityRecord {
    session: u64,
    target: u64,
    attempt: u64,
    revision: u64,
    boottime_ns: Option<u64>,
    ready: bool,
    reason: &'static str,
}

fn serial() -> u64 {
    static NEXT: AtomicU64 = AtomicU64::new(1);
    NEXT.fetch_update(Ordering::Relaxed, Ordering::Relaxed, |n| n.checked_add(1))
        .expect("authority serial exhausted")
}

impl AuthorityRecord {
    fn capture(attempt: &Attempt, ready: bool, reason: &'static str) -> Self {
        #[cfg(any(target_os = "android", target_os = "linux"))]
        let boottime_ns = {
            let mut time = libc::timespec {
                tv_sec: 0,
                tv_nsec: 0,
            };
            // SAFETY: writable timespec and the platform's documented clock ID.
            let result = unsafe { libc::clock_gettime(libc::CLOCK_BOOTTIME, &raw mut time) };
            (result == 0).then(|| time.tv_sec as u64 * 1_000_000_000 + time.tv_nsec as u64)
        };
        #[cfg(not(any(target_os = "android", target_os = "linux")))]
        let boottime_ns = None;
        Self {
            session: attempt.capture.identity.generation.get(),
            target: attempt.target.get(),
            attempt: attempt.serial,
            revision: serial(),
            boottime_ns,
            ready,
            reason,
        }
    }
    fn emit(self) {
        log::info!(
            "target-authority session={} target={} attempt={} revision={} clock=CLOCK_BOOTTIME boottime_ns={} clock_valid={} ready={} reason={}",
            self.session,
            self.target,
            self.attempt,
            self.revision,
            self.boottime_ns.unwrap_or(0),
            self.boottime_ns.is_some(),
            self.ready,
            self.reason
        );
    }
}

fn sink_records(
    capture: &CaptureState,
    ready: bool,
    reason: &'static str,
) -> [Option<AuthorityRecord>; MAX_TARGETS] {
    std::array::from_fn(|index| {
        capture.attempts[index].upgrade().and_then(|attempt| {
            (*attempt.phase.lock().expect("attempt state") == AttemptPhase::Active)
                .then(|| AuthorityRecord::capture(&attempt, ready, reason))
        })
    })
}

fn emit_records(records: [Option<AuthorityRecord>; MAX_TARGETS]) {
    for record in records.into_iter().flatten() {
        record.emit();
    }
}

/// Only the lifecycle owner can activate an attempt after real readiness.
/// A packet producer receives the narrower cloneable RelayAttempt capability.
pub struct RelayAttemptOwner(RelayAttempt);

impl RelayAttemptOwner {
    pub fn capability(&self) -> RelayAttempt {
        self.0.clone()
    }

    pub fn activate(&self) -> Result<(), RelayFlowError> {
        let capture = self.0.0.capture.state.lock().expect("capture state");
        let mut phase = self.0.0.phase.lock().expect("attempt state");
        if !capture.live || capture.sink.is_none() || *phase == AttemptPhase::Retired {
            return Err(RelayFlowError::Stale);
        }
        let changed = *phase != AttemptPhase::Active;
        *phase = AttemptPhase::Active;
        let record = changed.then(|| AuthorityRecord::capture(&self.0.0, true, "activate"));
        drop(phase);
        drop(capture);
        if let Some(record) = record {
            record.emit();
        }
        Ok(())
    }

    pub fn retire(&self) {
        let capture = self.0.0.capture.state.lock().expect("capture state");
        let mut phase = self.0.0.phase.lock().expect("attempt state");
        let changed = *phase != AttemptPhase::Retired;
        *phase = AttemptPhase::Retired;
        let record = changed.then(|| AuthorityRecord::capture(&self.0.0, false, "retire"));
        drop(phase);
        drop(capture);
        if let Some(record) = record {
            record.emit();
        }
    }
}

impl Drop for RelayAttemptOwner {
    fn drop(&mut self) {
        self.retire();
    }
}

/// Exact capture/attempt lifetime, never a tuple, numeric epoch or origin flag.
#[derive(Clone)]
pub struct RelayAttempt(Arc<Attempt>);

impl RelayAttempt {
    pub fn same_attempt(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.0, &other.0)
    }
    pub fn identity(&self) -> &RelayCaptureIdentity {
        &self.0.capture.identity
    }

    pub fn target(&self) -> RelayTargetId {
        self.0.target
    }

    pub fn sink(&self) -> Option<RelaySink> {
        RelayCapture(self.0.capture.clone()).sink()
    }

    pub fn sources(&self) -> RelaySources {
        self.0.sources
    }

    pub fn mtu(&self) -> u16 {
        self.0.mtu
    }

    pub fn current(&self) -> bool {
        self.with_current(|| ()).is_ok()
    }

    /// One synchronous nonblocking operation, ordered against both retirements.
    /// No await, lifecycle/broker reentry or retention of borrowed bytes inside
    /// the callback. Lock order is capture then attempt, never the reverse.
    pub fn with_current<T>(&self, operation: impl FnOnce() -> T) -> Result<T, RelayFlowError> {
        let capture = self.0.capture.state.lock().expect("capture state");
        let phase = self.0.phase.lock().expect("attempt state");
        if !capture.live || capture.sink.is_none() || *phase != AttemptPhase::Active {
            return Err(RelayFlowError::Stale);
        }
        Ok(operation())
    }

    pub fn packet(&self, bytes: RelayBuffer) -> Result<RelayPacket, RelayFlowError> {
        self.with_current(|| RelayPacket {
            storage: Arc::new(bytes),
            attempt: self.clone(),
            consumed: false,
        })
    }
}

/// Fixed, immutable packet storage retained with exact lifetime authority.
/// Moving through a queue does not strip either. Views share backing, not credit.
pub struct RelayPacket {
    storage: Arc<RelayBuffer>,
    attempt: RelayAttempt,
    consumed: bool,
}

#[derive(Clone)]
pub struct RelayPacketView {
    storage: Arc<RelayBuffer>,
    attempt: RelayAttempt,
}

#[derive(Debug)]
pub enum RelayWriteOutcome {
    Written,
    Retry,
    Stale,
    Fatal(io::Error),
}

impl RelayPacket {
    pub fn view(&self) -> RelayPacketView {
        RelayPacketView {
            storage: self.storage.clone(),
            attempt: self.attempt.clone(),
        }
    }

    /// Whole-packet injection only. WouldBlock retains bytes/authority; all
    /// other failures consume this item and retire this exact attempt.
    pub fn write(
        &mut self,
        operation: impl FnOnce(&[u8]) -> io::Result<usize>,
    ) -> RelayWriteOutcome {
        self.write_selected(None, operation)
    }

    /// Capture injection checks the descriptor receipt as well as the exact
    /// target/session. The general writer is also used at target-side sinks.
    pub fn write_to(
        &mut self,
        sink: &RelaySink,
        operation: impl FnOnce(&[u8]) -> io::Result<usize>,
    ) -> RelayWriteOutcome {
        self.write_selected(Some(sink), operation)
    }

    fn write_selected(
        &mut self,
        sink: Option<&RelaySink>,
        operation: impl FnOnce(&[u8]) -> io::Result<usize>,
    ) -> RelayWriteOutcome {
        if self.consumed {
            return RelayWriteOutcome::Stale;
        }
        let capture = self.attempt.0.capture.state.lock().expect("capture state");
        let mut phase = self.attempt.0.phase.lock().expect("attempt state");
        if !capture.live || capture.sink.is_none() || *phase != AttemptPhase::Active {
            self.consumed = true;
            return RelayWriteOutcome::Stale;
        }
        if sink.is_some_and(|sink| {
            !capture
                .sink
                .as_ref()
                .is_some_and(|current| Arc::ptr_eq(&current.0, &sink.0))
        }) {
            // A wrong selector never consumes a still-live packet or retires its
            // target. Its owner may retry against the actual current sink.
            return RelayWriteOutcome::Retry;
        }
        match operation(&self.storage) {
            Ok(n) if n == self.storage.len() && n != 0 => {
                self.consumed = true;
                RelayWriteOutcome::Written
            }
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => RelayWriteOutcome::Retry,
            result => {
                self.consumed = true;
                *phase = AttemptPhase::Retired;
                let record = AuthorityRecord::capture(&self.attempt.0, false, "write-fatal");
                let outcome = RelayWriteOutcome::Fatal(result.err().unwrap_or_else(|| {
                    io::Error::new(io::ErrorKind::WriteZero, "incomplete raw IP packet write")
                }));
                drop(phase);
                drop(capture);
                record.emit();
                outcome
            }
        }
    }

    /// Consume at the actual WireGuard handoff, under the same authority check.
    /// The callback must perform the final nonblocking handoff, not stage bytes
    /// in another unqualified queue. It may not reenter lifecycle/broker locks.
    pub fn handoff<T>(self, operation: impl FnOnce(&[u8]) -> T) -> Result<T, RelayFlowError> {
        if self.consumed {
            return Err(RelayFlowError::Closed);
        }
        self.attempt.with_current(|| operation(&self.storage))
    }
}

impl RelayPacketView {
    pub fn bytes(&self) -> &[u8] {
        &self.storage
    }

    pub fn attempt(&self) -> &RelayAttempt {
        &self.attempt
    }
}
