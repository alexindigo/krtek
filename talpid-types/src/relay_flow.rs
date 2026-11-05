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

/// Bound only after the platform has identified the actual capture interface
/// and its VPN Network. The full Android network handle is opaque, not an i32.
#[derive(Debug)]
pub struct RelayCaptureIdentity {
    pub generation: RelayCaptureGeneration,
    pub interface: String,
    pub network_handle: u64,
    pub sources: RelaySources,
    pub mtu: u16,
}

struct Capture {
    identity: RelayCaptureIdentity,
    state: Mutex<CaptureState>,
    _charge: Arc<dyn RelayBufferReservation>,
}

struct CaptureState {
    live: bool,
    attempt: Weak<Attempt>,
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
        if interface.is_empty()
            || interface.len() >= 16
            || !interface
                .bytes()
                .all(|c| c.is_ascii_alphanumeric() || b"_.-".contains(&c))
            || network_handle == 0
            || (sources.ipv4.is_none() && sources.ipv6.is_none())
            || mtu == 0
        {
            return Err(RelayFlowError::Invalid);
        }
        let charge = buffers.try_reserve(BUFFER_OVERHEAD)?;
        Ok(Self(Arc::new(Capture {
            identity: RelayCaptureIdentity {
                generation,
                interface: interface.to_owned(),
                network_handle,
                sources,
                mtu,
            },
            state: Mutex::new(CaptureState {
                live: true,
                attempt: Weak::new(),
            }),
            _charge: charge,
        })))
    }

    pub fn identity(&self) -> &RelayCaptureIdentity {
        &self.0.identity
    }

    pub fn retire(&self) {
        self.0.state.lock().expect("capture state").live = false;
    }

    /// A capture has at most one non-retired transport attempt. Replacement
    /// requires explicit retirement; identical addresses do not reuse authority.
    pub fn open_attempt(
        &self,
        buffers: &dyn RelayBufferAllocator,
    ) -> Result<RelayAttemptOwner, RelayFlowError> {
        let mut capture = self.0.state.lock().expect("capture state");
        if !capture.live {
            return Err(RelayFlowError::Stale);
        }
        if let Some(old) = capture.attempt.upgrade()
            && *old.phase.lock().expect("attempt state") != AttemptPhase::Retired
        {
            return Err(RelayFlowError::Invalid);
        }
        let charge = buffers.try_reserve(BUFFER_OVERHEAD)?;
        let attempt = Arc::new(Attempt {
            capture: self.0.clone(),
            phase: Mutex::new(AttemptPhase::Pending),
            _charge: charge,
        });
        capture.attempt = Arc::downgrade(&attempt);
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
    capture: Arc<Capture>,
    phase: Mutex<AttemptPhase>,
    _charge: Arc<dyn RelayBufferReservation>,
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
        if !capture.live || *phase == AttemptPhase::Retired {
            return Err(RelayFlowError::Stale);
        }
        *phase = AttemptPhase::Active;
        Ok(())
    }

    pub fn retire(&self) {
        *self.0.0.phase.lock().expect("attempt state") = AttemptPhase::Retired;
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
    pub fn identity(&self) -> &RelayCaptureIdentity {
        &self.0.capture.identity
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
        if !capture.live || *phase != AttemptPhase::Active {
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
        if self.consumed {
            return RelayWriteOutcome::Stale;
        }
        let capture = self.attempt.0.capture.state.lock().expect("capture state");
        let mut phase = self.attempt.0.phase.lock().expect("attempt state");
        if !capture.live || *phase != AttemptPhase::Active {
            self.consumed = true;
            return RelayWriteOutcome::Stale;
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
                RelayWriteOutcome::Fatal(result.err().unwrap_or_else(|| {
                    io::Error::new(io::ErrorKind::WriteZero, "incomplete raw IP packet write")
                }))
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
