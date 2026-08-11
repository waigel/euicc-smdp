//! What the CLI does, minus the argument parsing.
//!
//! Handlers hold no logic. When the admin API arrives, its HTTP handlers
//! call these same functions, so adding it is not a restructuring. That
//! is the one place this design builds ahead of what is being built, and
//! it is justified because the next step is already named rather than
//! imagined.

use crate::store::{NewOrder, Order, Store, StoreError};

#[derive(Debug)]
pub enum ServiceError {
    Store(StoreError),
}

impl std::fmt::Display for ServiceError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ServiceError::Store(e) => write!(f, "{e}"),
        }
    }
}

impl std::error::Error for ServiceError {}

impl From<StoreError> for ServiceError {
    fn from(e: StoreError) -> Self {
        ServiceError::Store(e)
    }
}

/// SGP.22 treats the MatchingID as the secret that authorises a
/// download, so a guessable one hands out Profiles. Drawn straight from
/// the OS CSPRNG rather than a userspace PRNG, for the same reason a
/// password would be.
///
/// The alphabet has 32 symbols, so each character carries exactly five
/// bits and the mapping is a plain mask -- no modulo, and therefore no
/// bias toward the front of the alphabet.
fn generate_matching_id() -> String {
    const ALPHABET: &[u8; 32] = b"ABCDEFGHJKLMNPQRSTUVWXYZ23456789";
    let mut raw = [0u8; 22];
    getrandom::fill(&mut raw).expect("the OS CSPRNG is unavailable");
    raw.iter().map(|b| ALPHABET[(b & 0x1f) as usize] as char).collect()
}

pub fn create_order(
    store: &dyn Store,
    iccid: &[u8; 10],
    upp: Vec<u8>,
    metadata: Vec<u8>,
    matching_id: Option<String>,
) -> Result<Order, ServiceError> {
    let matching_id = matching_id.unwrap_or_else(generate_matching_id);
    Ok(store.add_order(NewOrder {
        matching_id,
        iccid: *iccid,
        upp,
        metadata,
    })?)
}

pub fn list_orders(store: &dyn Store) -> Result<Vec<Order>, ServiceError> {
    Ok(store.list_orders()?)
}

/// `LPA:1$<host>$<matchingId>` -- SGP.22 v2.6 section 4.1. Nothing in
/// this project redeems one yet; it costs nothing to emit and it names
/// where this leads.
pub fn activation_code(host: &str, matching_id: &str) -> String {
    format!("LPA:1${host}${matching_id}")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::sqlite::SqliteStore;

    const ICCID: [u8; 10] = [0x98, 0x00, 0x10, 0x32, 0x54, 0x76, 0x98, 0x10, 0x32, 0x14];

    #[test]
    fn a_generated_matching_id_is_not_guessable_from_the_iccid() {
        let s = SqliteStore::in_memory().unwrap();
        let a = create_order(&s, &ICCID, b"upp".to_vec(), vec![0x30], None).unwrap();
        let b = create_order(&s, &ICCID, b"upp".to_vec(), vec![0x30], None).unwrap();
        assert_ne!(a.matching_id, b.matching_id, "two orders, two MatchingIDs");
        assert!(a.matching_id.len() >= 16, "too short to be unguessable");
    }

    #[test]
    fn an_explicit_matching_id_is_kept() {
        let s = SqliteStore::in_memory().unwrap();
        let o = create_order(&s, &ICCID, b"upp".to_vec(), vec![0x30], Some("MINE".into())).unwrap();
        assert_eq!(o.matching_id, "MINE");
    }

    #[test]
    fn the_activation_code_has_the_shape_an_lpa_parses() {
        assert_eq!(
            activation_code("smdp.example.com", "MATCH-1"),
            "LPA:1$smdp.example.com$MATCH-1"
        );
    }
}
