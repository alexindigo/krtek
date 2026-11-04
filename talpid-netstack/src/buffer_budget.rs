//! Reserve or refuse shared storage. No waiting, notification or authorization.
use std::sync::{
    Arc, Mutex, Weak,
    atomic::{AtomicUsize, Ordering},
};
use talpid_types::relay_flow::{RelayBufferAllocator, RelayBufferReservation, RelayFlowError};

/// Account/credit metadata allowance withheld from each region.
pub const REGION_OVERHEAD: usize = 512;

struct Account {
    limit: usize,
    used: AtomicUsize,
    _parent: Option<Arc<Credit>>,
}
struct Credit {
    account: Arc<Account>,
    bytes: usize,
    region: Mutex<Weak<Account>>,
}
impl Drop for Credit {
    fn drop(&mut self) {
        let previous = self.account.used.fetch_sub(self.bytes, Ordering::AcqRel);
        assert!(previous >= self.bytes, "storage counter underflow");
    }
}

#[derive(Clone)]
pub struct BufferBudget(Arc<Account>);
pub struct BufferCharge(Arc<Credit>);

impl BufferBudget {
    pub fn new(limit: usize) -> Self {
        Self(Arc::new(Account {
            limit,
            used: AtomicUsize::new(0),
            _parent: None,
        }))
    }
    pub fn used(&self) -> usize {
        self.0.used.load(Ordering::Acquire)
    }
    pub fn limit(&self) -> usize {
        self.0.limit
    }
    pub fn reserve(&self, bytes: usize) -> Result<BufferCharge, RelayFlowError> {
        self.0
            .used
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |used| {
                used.checked_add(bytes).filter(|next| *next <= self.0.limit)
            })
            .map_err(|_| RelayFlowError::Full)?;
        Ok(BufferCharge::new(self.0.clone(), bytes))
    }
}
impl BufferCharge {
    fn new(account: Arc<Account>, bytes: usize) -> Self {
        Self(Arc::new(Credit {
            account,
            bytes,
            region: Mutex::new(Weak::new()),
        }))
    }
    pub fn bytes(&self) -> usize {
        self.0.bytes
    }
    pub fn region(&self) -> Result<BufferBudget, RelayFlowError> {
        let limit = self
            .bytes()
            .checked_sub(REGION_OVERHEAD)
            .ok_or(RelayFlowError::Full)?;
        let mut cached = self.0.region.lock().expect("storage region cache");
        let account = cached.upgrade().unwrap_or_else(|| {
            let account = Arc::new(Account {
                limit,
                used: AtomicUsize::new(0),
                _parent: Some(self.0.clone()),
            });
            *cached = Arc::downgrade(&account);
            account
        });
        Ok(BufferBudget(account))
    }
    pub fn split(&mut self, bytes: usize) -> Result<Self, RelayFlowError> {
        let current = Arc::get_mut(&mut self.0).ok_or(RelayFlowError::Invalid)?;
        let remaining = current
            .bytes
            .checked_sub(bytes)
            .ok_or(RelayFlowError::Full)?;
        let part = Self::new(current.account.clone(), bytes);
        current.bytes = remaining;
        Ok(part)
    }
    /// Errors retain both tickets unchanged.
    pub fn absorb(&mut self, other: &mut Self) -> Result<(), RelayFlowError> {
        if !Arc::ptr_eq(&self.0.account, &other.0.account) {
            return Err(RelayFlowError::Invalid);
        }
        let current = Arc::get_mut(&mut self.0).ok_or(RelayFlowError::Invalid)?;
        let added = Arc::get_mut(&mut other.0).ok_or(RelayFlowError::Invalid)?;
        let total = current
            .bytes
            .checked_add(added.bytes)
            .ok_or(RelayFlowError::Full)?;
        current.bytes = total;
        added.bytes = 0;
        Ok(())
    }
    pub fn shrink(&mut self, bytes: usize) -> Result<(), RelayFlowError> {
        let current = Arc::get_mut(&mut self.0).ok_or(RelayFlowError::Invalid)?;
        let refund = current
            .bytes
            .checked_sub(bytes)
            .ok_or(RelayFlowError::Full)?;
        current.account.used.fetch_sub(refund, Ordering::AcqRel);
        current.bytes = bytes;
        Ok(())
    }
}
impl RelayBufferAllocator for BufferBudget {
    fn try_reserve(&self, bytes: usize) -> Result<Arc<dyn RelayBufferReservation>, RelayFlowError> {
        Ok(Arc::new(self.reserve(bytes)?))
    }
}
impl RelayBufferReservation for BufferCharge {
    fn bytes(&self) -> usize {
        self.bytes()
    }
    fn allocator(&self) -> Result<Arc<dyn RelayBufferAllocator>, RelayFlowError> {
        Ok(Arc::new(self.region()?))
    }
    fn partition(
        self: Arc<Self>,
        sizes: &[usize],
    ) -> Result<Vec<Arc<dyn RelayBufferReservation>>, RelayFlowError> {
        if sizes.len() > 256 {
            return Err(RelayFlowError::Full);
        }
        let total = sizes
            .iter()
            .try_fold(0usize, |sum, n| sum.checked_add(*n))
            .ok_or(RelayFlowError::Full)?;
        if total > self.bytes() {
            return Err(RelayFlowError::Full);
        }
        let mut owned = Arc::try_unwrap(self).map_err(|_| RelayFlowError::Invalid)?;
        if Arc::strong_count(&owned.0) != 1 {
            return Err(RelayFlowError::Invalid);
        }
        sizes
            .iter()
            .map(|n| Ok(Arc::new(owned.split(*n)?) as Arc<dyn RelayBufferReservation>))
            .collect()
    }
}

#[cfg(test)]
mod tests;
