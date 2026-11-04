//! Shared storage capabilities. A reservation is never packet or policy authority.
use std::{fmt, sync::Arc};

pub const MAX_RELAY_PACKET_SIZE: usize = 65_575;
pub const BUFFER_OVERHEAD: usize = 512;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RelayFlowError {
    Invalid,
    Full,
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
