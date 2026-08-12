//! The default and, for now, only Store provider.
//!
//! SQLite is bundled rather than linked against whatever the host
//! happens to have, so the build does not depend on the machine.

use std::path::Path;
use std::sync::Mutex;

use rusqlite::{params, Connection, OptionalExtension};

use super::{NewNotification, NewOrder, Order, OrderState, Store, StoreError, StoredNotification};

const SCHEMA: &str = "
CREATE TABLE IF NOT EXISTS orders (
    id           INTEGER PRIMARY KEY,
    matching_id  TEXT    NOT NULL UNIQUE,
    iccid        BLOB    NOT NULL,
    upp          BLOB    NOT NULL,
    metadata     BLOB    NOT NULL,
    state        TEXT    NOT NULL,
    eid          TEXT,
    euicc_cert   BLOB
);
CREATE INDEX IF NOT EXISTS orders_by_iccid ON orders(iccid);

CREATE TABLE IF NOT EXISTS notifications (
    id         INTEGER PRIMARY KEY,
    order_id   INTEGER,
    seq_number INTEGER NOT NULL,
    operation  INTEGER NOT NULL,
    iccid      BLOB,
    installed  INTEGER,
    verified   INTEGER NOT NULL,
    raw        BLOB NOT NULL
);
";

/// rusqlite's Connection is Send but not Sync, and Store is both, so the
/// connection sits behind a Mutex. One process, one connection: this
/// server keeps its RSP sessions in memory anyway, so it cannot be run
/// more than once against the same state regardless.
pub struct SqliteStore {
    conn: Mutex<Connection>,
}

impl SqliteStore {
    pub fn open(path: impl AsRef<Path>) -> Result<Self, StoreError> {
        let conn = Connection::open(path).map_err(StoreError::Db)?;
        Self::prepare(conn)
    }

    pub fn in_memory() -> Result<Self, StoreError> {
        let conn = Connection::open_in_memory().map_err(StoreError::Db)?;
        Self::prepare(conn)
    }

    fn prepare(conn: Connection) -> Result<Self, StoreError> {
        conn.execute_batch(SCHEMA).map_err(StoreError::Db)?;
        Ok(SqliteStore {
            conn: Mutex::new(conn),
        })
    }
}

const COLUMNS: &str = "id, matching_id, iccid, upp, metadata, state, eid, euicc_cert";

fn row_to_order(row: &rusqlite::Row<'_>) -> rusqlite::Result<Result<Order, StoreError>> {
    let iccid_blob: Vec<u8> = row.get(2)?;
    let state_str: String = row.get(5)?;
    Ok((|| {
        let iccid: [u8; 10] = iccid_blob
            .as_slice()
            .try_into()
            .map_err(|_| StoreError::MalformedIccid(iccid_blob.len()))?;
        Ok(Order {
            id: row.get(0).map_err(StoreError::Db)?,
            matching_id: row.get(1).map_err(StoreError::Db)?,
            iccid,
            upp: row.get(3).map_err(StoreError::Db)?,
            metadata: row.get(4).map_err(StoreError::Db)?,
            state: OrderState::parse(&state_str)?,
            eid: row.get(6).map_err(StoreError::Db)?,
            euicc_cert: row.get(7).map_err(StoreError::Db)?,
        })
    })())
}

impl SqliteStore {
    fn one(
        &self,
        where_clause: &str,
        key: &dyn rusqlite::ToSql,
    ) -> Result<Option<Order>, StoreError> {
        let conn = self.conn.lock().unwrap();
        let sql = format!("SELECT {COLUMNS} FROM orders WHERE {where_clause}");
        let found = conn
            .query_row(&sql, params![key], row_to_order)
            .optional()
            .map_err(StoreError::Db)?;
        match found {
            Some(r) => r.map(Some),
            None => Ok(None),
        }
    }
}

impl Store for SqliteStore {
    fn add_order(&self, new: NewOrder) -> Result<Order, StoreError> {
        let conn = self.conn.lock().unwrap();
        let rc = conn.execute(
            "INSERT INTO orders (matching_id, iccid, upp, metadata, state)
             VALUES (?1, ?2, ?3, ?4, ?5)",
            params![
                new.matching_id,
                &new.iccid[..],
                new.upp,
                new.metadata,
                OrderState::Available.as_str()
            ],
        );
        match rc {
            Ok(_) => {}
            // The UNIQUE constraint is the point, not an accident, so it
            // gets its own error rather than a generic database one.
            Err(rusqlite::Error::SqliteFailure(e, _))
                if e.code == rusqlite::ErrorCode::ConstraintViolation =>
            {
                return Err(StoreError::DuplicateMatchingId(new.matching_id));
            }
            Err(e) => return Err(StoreError::Db(e)),
        }
        Ok(Order {
            id: conn.last_insert_rowid(),
            matching_id: new.matching_id,
            iccid: new.iccid,
            upp: new.upp,
            metadata: new.metadata,
            state: OrderState::Available,
            eid: None,
            euicc_cert: None,
        })
    }

    fn list_orders(&self) -> Result<Vec<Order>, StoreError> {
        let conn = self.conn.lock().unwrap();
        let sql = format!("SELECT {COLUMNS} FROM orders ORDER BY id");
        let mut stmt = conn.prepare(&sql).map_err(StoreError::Db)?;
        let rows = stmt.query_map([], row_to_order).map_err(StoreError::Db)?;
        let mut out = Vec::new();
        for r in rows {
            out.push(r.map_err(StoreError::Db)??);
        }
        Ok(out)
    }

    fn order_by_matching_id(&self, id: &str) -> Result<Option<Order>, StoreError> {
        self.one("matching_id = ?1", &id)
    }

    fn order_by_iccid(&self, iccid: &[u8; 10]) -> Result<Option<Order>, StoreError> {
        self.one("iccid = ?1", &&iccid[..])
    }

    fn bind_euicc(&self, order: i64, eid: &str, euicc_cert: &[u8]) -> Result<(), StoreError> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "UPDATE orders SET eid = ?2, euicc_cert = ?3 WHERE id = ?1",
            params![order, eid, euicc_cert],
        )
        .map_err(StoreError::Db)?;
        Ok(())
    }

    fn record_notification(&self, n: NewNotification) -> Result<(), StoreError> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT INTO notifications
                 (order_id, seq_number, operation, iccid, installed, verified, raw)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![
                n.order_id,
                n.seq_number,
                n.operation,
                n.iccid.map(|i| i.to_vec()),
                n.installed.map(|b| b as i64),
                n.verified as i64,
                n.raw
            ],
        )
        .map_err(StoreError::Db)?;
        Ok(())
    }

    fn notifications(&self) -> Result<Vec<StoredNotification>, StoreError> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn
            .prepare(
                "SELECT id, order_id, seq_number, operation, installed, verified, raw
                 FROM notifications ORDER BY id",
            )
            .map_err(StoreError::Db)?;
        let rows = stmt
            .query_map([], |r| {
                Ok(StoredNotification {
                    id: r.get(0)?,
                    order_id: r.get(1)?,
                    seq_number: r.get(2)?,
                    operation: r.get(3)?,
                    installed: r.get::<_, Option<i64>>(4)?.map(|v| v != 0),
                    verified: r.get::<_, i64>(5)? != 0,
                    raw: r.get(6)?,
                })
            })
            .map_err(StoreError::Db)?;
        let mut out = Vec::new();
        for r in rows {
            out.push(r.map_err(StoreError::Db)?);
        }
        Ok(out)
    }

    fn set_state(&self, order: i64, state: OrderState) -> Result<(), StoreError> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "UPDATE orders SET state = ?2 WHERE id = ?1",
            params![order, state.as_str()],
        )
        .map_err(StoreError::Db)?;
        Ok(())
    }
}
