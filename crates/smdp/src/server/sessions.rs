//! RSP sessions, in memory, keyed by transactionId.
//!
//! Not in the store: euicc-rsp offers no way to serialize an
//! rsp_dp_session_t, so there is nothing to persist. The consequence,
//! stated rather than hidden: one process, no horizontal scaling, and a
//! restart aborts every download in flight.

use std::collections::HashMap;
use std::time::{Duration, Instant};

use crate::rsp::DpSession;

/// An RSP session that never finishes must not pin memory forever.
const MAX_AGE: Duration = Duration::from_secs(600);

pub struct Entry {
    pub session: DpSession,
    /// Which order this download is for, learned at AuthenticateClient.
    pub order_id: Option<i64>,
    born: Instant,
}

#[derive(Default)]
pub struct Sessions {
    by_transaction: HashMap<Vec<u8>, Entry>,
}

impl Sessions {
    pub fn insert(&mut self, transaction_id: Vec<u8>, session: DpSession) {
        self.sweep();
        self.by_transaction.insert(
            transaction_id,
            Entry {
                session,
                order_id: None,
                born: Instant::now(),
            },
        );
    }

    pub fn get_mut(&mut self, transaction_id: &[u8]) -> Option<&mut Entry> {
        self.by_transaction.get_mut(transaction_id)
    }

    pub fn remove(&mut self, transaction_id: &[u8]) {
        self.by_transaction.remove(transaction_id);
    }

    fn sweep(&mut self) {
        let now = Instant::now();
        self.by_transaction
            .retain(|_, e| now.duration_since(e.born) < MAX_AGE);
    }
}
