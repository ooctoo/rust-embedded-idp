use crate::StoreError;
use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Arc,
};

/// One trusted Host shares this budget across registration and every password login entry.
#[derive(Clone, Default)]
pub struct PasswordWorkBudget(Arc<WorkState>);
#[derive(Default)]
struct WorkState {
    total: AtomicUsize,
    registration: AtomicUsize,
}
pub struct PasswordWorkPermit {
    state: Arc<WorkState>,
    registration: bool,
}
impl PasswordWorkBudget {
    pub fn try_login(&self) -> Result<PasswordWorkPermit, StoreError> {
        self.acquire(false)
    }
    pub fn try_registration(&self) -> Result<PasswordWorkPermit, StoreError> {
        self.acquire(true)
    }
    pub fn same_budget(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.0, &other.0)
    }
    fn acquire(&self, registration: bool) -> Result<PasswordWorkPermit, StoreError> {
        let reserve = |counter: &AtomicUsize, cap| {
            counter
                .fetch_update(Ordering::AcqRel, Ordering::Acquire, |n| {
                    (n < cap).then_some(n + 1)
                })
                .is_ok()
        };
        if registration && !reserve(&self.0.registration, 2) {
            return Err(unavailable());
        }
        if !reserve(&self.0.total, 4) {
            if registration {
                self.0.registration.fetch_sub(1, Ordering::AcqRel);
            }
            return Err(unavailable());
        }
        Ok(PasswordWorkPermit {
            state: self.0.clone(),
            registration,
        })
    }
}
impl Drop for PasswordWorkPermit {
    fn drop(&mut self) {
        self.state.total.fetch_sub(1, Ordering::AcqRel);
        if self.registration {
            self.state.registration.fetch_sub(1, Ordering::AcqRel);
        }
    }
}
fn unavailable() -> StoreError {
    StoreError::Backend("password.work_unavailable".into())
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn starts_leave_two_login_slots_and_release_only_on_drop() {
        let b = PasswordWorkBudget::default();
        let a = b.try_registration().unwrap();
        let c = b.try_registration().unwrap();
        assert!(b.try_registration().is_err());
        let d = b.try_login().unwrap();
        let e = b.try_login().unwrap();
        assert!(b.try_login().is_err());
        drop(a);
        let f = b.try_login().unwrap();
        assert!(b.try_registration().is_err());
        drop((c, d, e, f));
        assert!(b.try_registration().is_ok());
        assert!(b.same_budget(&b.clone()));
        assert!(!b.same_budget(&PasswordWorkBudget::default()));
    }
}
