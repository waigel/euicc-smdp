//! What has to outlive a process: which eUICC was given which Profile.
//!
//! euicc-rsp deliberately has no Profile order database -- that is the
//! line between a protocol library and a server, and this is the other
//! side of it.

pub mod sqlite;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OrderState {
    /// Nobody has downloaded it.
    Available,
    /// An eUICC authenticated against it; `eid` and `euicc_cert` are set.
    Bound,
    /// A Bound Profile Package was handed out for it.
    Downloaded,
    /// The eUICC reported that it could not install it.
    Failed,
}

impl OrderState {
    fn as_str(self) -> &'static str {
        match self {
            OrderState::Available => "available",
            OrderState::Bound => "bound",
            OrderState::Downloaded => "downloaded",
            OrderState::Failed => "failed",
        }
    }

    /// A state this code does not understand is not a state to guess at.
    fn parse(s: &str) -> Result<Self, StoreError> {
        match s {
            "available" => Ok(OrderState::Available),
            "bound" => Ok(OrderState::Bound),
            "downloaded" => Ok(OrderState::Downloaded),
            "failed" => Ok(OrderState::Failed),
            other => Err(StoreError::UnknownState(other.to_string())),
        }
    }
}

#[derive(Debug, Clone)]
pub struct Order {
    pub id: i64,
    pub matching_id: String,
    pub iccid: [u8; 10],
    pub upp: Vec<u8>,
    /// An encoded StoreMetadataRequest (SGP.22 section 5.5.3).
    pub metadata: Vec<u8>,
    pub state: OrderState,
    /// Learned during AuthenticateClient. Kept because a notification
    /// arrives with no session behind it and no EID in it, so the only
    /// way to know whose signature to check is to have remembered.
    pub eid: Option<String>,
    pub euicc_cert: Option<Vec<u8>>,
}

#[derive(Debug, Clone)]
pub struct NewOrder {
    pub matching_id: String,
    pub iccid: [u8; 10],
    pub upp: Vec<u8>,
    pub metadata: Vec<u8>,
}

#[derive(Debug)]
pub enum StoreError {
    Db(rusqlite::Error),
    DuplicateMatchingId(String),
    UnknownState(String),
    /// The database was written by a newer version of this server.
    SchemaTooNew(i64),
    /// A stored ICCID that is not ten bytes -- the column is a BLOB, so
    /// nothing but this check keeps that honest.
    MalformedIccid(usize),
}

impl std::fmt::Display for StoreError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            StoreError::Db(e) => write!(f, "database: {e}"),
            StoreError::DuplicateMatchingId(m) => write!(f, "MatchingID already exists: {m}"),
            StoreError::UnknownState(s) => write!(f, "unknown order state: {s}"),
            StoreError::SchemaTooNew(v) => {
                write!(
                    f,
                    "this database has schema version {v}; this server understands 2"
                )
            }
            StoreError::MalformedIccid(n) => write!(f, "stored ICCID is {n} bytes, expected 10"),
        }
    }
}

impl std::error::Error for StoreError {}

pub trait Store: Send + Sync {
    fn add_order(&self, new: NewOrder) -> Result<Order, StoreError>;
    fn list_orders(&self) -> Result<Vec<Order>, StoreError>;
    fn order_by_matching_id(&self, id: &str) -> Result<Option<Order>, StoreError>;
    fn order_by_iccid(&self, iccid: &[u8; 10]) -> Result<Option<Order>, StoreError>;
    /// Record which eUICC this order went to. This is the row a future
    /// HandleNotification stands on.
    fn bind_euicc(&self, order: i64, eid: &str, euicc_cert: &[u8]) -> Result<(), StoreError>;
    fn set_state(&self, order: i64, state: OrderState) -> Result<(), StoreError>;

    /// Keep a notification that was delivered, whether or not it
    /// verified.
    ///
    /// Everything that arrives is kept. The Notification MEP has no way
    /// to tell an LPA that a notification was not accepted -- 204 is the
    /// only answer there is -- so by the time this runs the LPA has
    /// already removed it from the eUICC, which keeps no second copy.
    /// Discarding it here would destroy the only copy that exists, and
    /// an earlier version of this server did exactly that: five real
    /// notifications from a real card, gone, with nothing to look at
    /// afterwards.
    ///
    /// The bytes are kept as they arrived: the eUICC signed over them,
    /// and a re-encoding would be a different message. `verified` says
    /// whether that signature was checked and held.
    fn record_notification(&self, n: NewNotification) -> Result<(), StoreError>;

    fn notifications(&self) -> Result<Vec<StoredNotification>, StoreError>;
}

#[derive(Debug, Clone)]
pub struct NewNotification {
    /// Did it verify? A notification that did not is still kept: the
    /// LPA has already removed it from the eUICC by the time this is
    /// written, so not keeping it destroys the only copy.
    pub verified: bool,
    /// Which order it was matched to, by ICCID. None when no order
    /// carries that ICCID -- the notification is still genuine and
    /// still worth keeping.
    pub order_id: Option<i64>,
    pub seq_number: i64,
    pub operation: i32,
    pub iccid: Option<[u8; 10]>,
    pub installed: Option<bool>,
    pub raw: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct StoredNotification {
    pub id: i64,
    pub verified: bool,
    pub order_id: Option<i64>,
    pub seq_number: i64,
    pub operation: i32,
    pub installed: Option<bool>,
    pub raw: Vec<u8>,
}

#[cfg(test)]
mod tests {
    use super::sqlite::SqliteStore;
    use super::*;

    const ICCID: [u8; 10] = [0x98, 0x00, 0x10, 0x32, 0x54, 0x76, 0x98, 0x10, 0x32, 0x14];

    fn an_order() -> NewOrder {
        NewOrder {
            matching_id: "MATCH-0001".into(),
            iccid: ICCID,
            upp: b"the-uicc-profile-fixture".to_vec(),
            metadata: vec![0xbf, 0x25, 0x00],
        }
    }

    #[test]
    fn an_order_survives_a_round_trip() {
        let s = SqliteStore::in_memory().unwrap();
        let o = s.add_order(an_order()).unwrap();
        assert_eq!(o.state, OrderState::Available);
        let found = s.order_by_matching_id("MATCH-0001").unwrap().unwrap();
        assert_eq!(found.id, o.id);
        assert_eq!(found.upp, o.upp);
        assert_eq!(found.iccid, o.iccid);
        assert_eq!(found.metadata, o.metadata);
    }

    #[test]
    fn an_order_is_findable_by_iccid_too() {
        // The lookup HandleNotification will need: a notification carries
        // an ICCID and no EID.
        let s = SqliteStore::in_memory().unwrap();
        let o = s.add_order(an_order()).unwrap();
        let found = s.order_by_iccid(&ICCID).unwrap().unwrap();
        assert_eq!(found.id, o.id);
    }

    #[test]
    fn a_matching_id_is_unique() {
        let s = SqliteStore::in_memory().unwrap();
        s.add_order(an_order()).unwrap();
        let again = s.add_order(an_order());
        assert!(
            matches!(again, Err(StoreError::DuplicateMatchingId(_))),
            "two orders must not share a MatchingID -- it is how a download finds its Profile"
        );
    }

    #[test]
    fn binding_an_euicc_records_what_a_notification_will_need() {
        let s = SqliteStore::in_memory().unwrap();
        let o = s.add_order(an_order()).unwrap();
        assert!(o.eid.is_none() && o.euicc_cert.is_none());

        s.bind_euicc(
            o.id,
            "89049032123451234512345678901235",
            &[0x30, 0x82, 0x01],
        )
        .unwrap();
        s.set_state(o.id, OrderState::Bound).unwrap();

        let f = s.order_by_iccid(&ICCID).unwrap().unwrap();
        assert_eq!(f.eid.as_deref(), Some("89049032123451234512345678901235"));
        assert_eq!(f.euicc_cert.as_deref(), Some(&[0x30, 0x82, 0x01][..]));
        assert_eq!(f.state, OrderState::Bound);
    }

    #[test]
    fn an_older_database_migrates_rather_than_failing_at_the_first_insert() {
        // CREATE TABLE IF NOT EXISTS leaves an older table exactly as it
        // was and says nothing, so the code goes on believing in columns
        // that are not there. A real database written before `verified`
        // existed is rebuilt here to prove the migration runs and keeps
        // what was in it.
        let f = tempfile();
        {
            let c = rusqlite::Connection::open(&f).unwrap();
            c.execute_batch(
                "CREATE TABLE notifications (
                     id         INTEGER PRIMARY KEY,
                     order_id   INTEGER,
                     seq_number INTEGER NOT NULL,
                     operation  INTEGER NOT NULL,
                     iccid      BLOB,
                     installed  INTEGER,
                     raw        BLOB NOT NULL);
                 INSERT INTO notifications
                     (seq_number, operation, installed, raw)
                     VALUES (29, 0, 1, x'BF37');",
            )
            .unwrap();
        }

        let s = SqliteStore::open(&f).unwrap();
        let kept = s.notifications().unwrap();
        assert_eq!(kept.len(), 1, "the row survived the migration");
        assert!(
            kept[0].verified,
            "and is marked verified: the version that wrote it stored nothing else"
        );
        assert_eq!(kept[0].seq_number, 29);

        // And the new column is usable, which is what failed before.
        s.record_notification(NewNotification {
            verified: false,
            order_id: None,
            seq_number: 30,
            operation: 1,
            iccid: None,
            installed: None,
            raw: vec![0x30],
        })
        .unwrap();
        assert_eq!(s.notifications().unwrap().len(), 2);
        let _ = std::fs::remove_file(&f);
    }

    fn tempfile() -> std::path::PathBuf {
        let mut p = std::env::temp_dir();
        p.push(format!(
            "smdp-migrate-{}.db",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        p
    }

    #[test]
    fn an_unknown_matching_id_is_none_not_an_error() {
        let s = SqliteStore::in_memory().unwrap();
        assert!(s.order_by_matching_id("nope").unwrap().is_none());
    }

    #[test]
    fn listing_gives_back_what_went_in() {
        let s = SqliteStore::in_memory().unwrap();
        s.add_order(an_order()).unwrap();
        let mut second = an_order();
        second.matching_id = "MATCH-0002".into();
        s.add_order(second).unwrap();
        assert_eq!(s.list_orders().unwrap().len(), 2);
    }
}
