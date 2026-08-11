# euicc-smdp, part two: the server itself — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Turn the Rust session wrapper into a running SM-DP+: a store that remembers which eUICC got which Profile, a CLI that seeds orders, and the three ES9+ endpoints over HTTP — proven end to end by driving the running server with the recorded session fixtures.

**Architecture:** One binary with subcommands, `serve` among them, the shape Ory Hydra uses. CLI handlers hold no logic; they call a service module over a `Store` trait, so the admin API that replaces CLI seeding later calls the same functions. Sessions live in process memory keyed by transactionId; only what must outlive a restart goes to SQLite.

**Tech Stack:** Rust 1.95, `axum` 0.8, `tokio` 1.53, `rusqlite` 0.40, `clap` 4.6, `serde`/`serde_json` — versions confirmed by resolution, not recalled.

## Global Constraints

- Spec: `docs/superpowers/specs/2026-08-11-euicc-smdp-server-design.md`. Its "The ES9+ endpoints" section records the JSON binding as read out of SGP.22 v2.6 section 6.5 — follow it rather than re-deriving it.
- Four binding facts that are easy to get wrong, all from the spec: **ES9+ requests carry no `header`**; a synchronous function answers **HTTP 200 regardless of outcome**, with failure expressed in `functionExecutionStatus`; `transactionId` is **uppercase hex**, every other payload field is base64 DER; request and response both carry `X-Admin-Protocol: gsma/rsp/v2.6.0` and `Content-Type: application/json`.
- `RspError::Refused` and `RspError::NotReached` must keep leading to different answers. They no longer pick the HTTP status — they pick what goes in the body.
- Everything must be provable with `cargo test` and no card reader. `vendor/euicc-rsp/testdata/session/` is the input.
- No secret ever reaches a log. `DpSession`'s `Debug` is deliberately opaque; keep it that way.

---

### Task 1: The store

**Files:**
- Create: `crates/smdp/src/store/mod.rs`, `crates/smdp/src/store/sqlite.rs`
- Modify: `crates/smdp/src/lib.rs`, `crates/smdp/Cargo.toml`

**Interfaces:**
- Consumes: nothing from part one.
- Produces:
  ```rust
  #[derive(Debug, Clone, PartialEq, Eq)]
  pub enum OrderState { Available, Bound, Downloaded, Failed }

  #[derive(Debug, Clone)]
  pub struct Order {
      pub id: i64,
      pub matching_id: String,
      pub iccid: [u8; 10],
      pub upp: Vec<u8>,
      pub metadata: Vec<u8>,      // an encoded StoreMetadataRequest
      pub state: OrderState,
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

  pub trait Store: Send + Sync {
      fn add_order(&self, new: NewOrder) -> Result<Order, StoreError>;
      fn list_orders(&self) -> Result<Vec<Order>, StoreError>;
      fn order_by_matching_id(&self, id: &str) -> Result<Option<Order>, StoreError>;
      fn order_by_iccid(&self, iccid: &[u8; 10]) -> Result<Option<Order>, StoreError>;
      fn bind_euicc(&self, order: i64, eid: &str, euicc_cert: &[u8]) -> Result<(), StoreError>;
      fn set_state(&self, order: i64, state: OrderState) -> Result<(), StoreError>;
  }

  pub struct SqliteStore;   // SqliteStore::open(path) / SqliteStore::in_memory()
  ```
  `bind_euicc` is the row notifications will later stand on: it stores the EID and `CERT.EUICC.ECDSA` learned during `AuthenticateClient`, so a future `HandleNotification` can verify a signature with no session behind it. It costs two columns now and removes the reason notifications were blocked.

- [ ] **Step 1: Write the failing tests**

`crates/smdp/src/store/mod.rs`, at the bottom:

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::sqlite::SqliteStore;

    fn an_order() -> NewOrder {
        NewOrder {
            matching_id: "MATCH-0001".into(),
            iccid: [0x98, 0x00, 0x10, 0x32, 0x54, 0x76, 0x98, 0x10, 0x32, 0x14],
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
    }

    #[test]
    fn an_order_is_findable_by_iccid_too() {
        // This is the lookup HandleNotification will need: a notification
        // carries an ICCID and no EID.
        let s = SqliteStore::in_memory().unwrap();
        let o = s.add_order(an_order()).unwrap();
        let found = s.order_by_iccid(&o.iccid).unwrap().unwrap();
        assert_eq!(found.id, o.id);
    }

    #[test]
    fn a_matching_id_is_unique() {
        let s = SqliteStore::in_memory().unwrap();
        s.add_order(an_order()).unwrap();
        assert!(
            s.add_order(an_order()).is_err(),
            "two orders must not share a MatchingID -- it is how a download finds its Profile"
        );
    }

    #[test]
    fn binding_an_euicc_records_what_a_notification_will_need() {
        let s = SqliteStore::in_memory().unwrap();
        let o = s.add_order(an_order()).unwrap();
        assert!(o.eid.is_none() && o.euicc_cert.is_none());

        s.bind_euicc(o.id, "89049032123451234512345678901235", &[0x30, 0x82, 0x01])
            .unwrap();
        s.set_state(o.id, OrderState::Bound).unwrap();

        let f = s.order_by_iccid(&o.iccid).unwrap().unwrap();
        assert_eq!(f.eid.as_deref(), Some("89049032123451234512345678901235"));
        assert_eq!(f.euicc_cert.as_deref(), Some(&[0x30, 0x82, 0x01][..]));
        assert_eq!(f.state, OrderState::Bound);
    }

    #[test]
    fn an_unknown_matching_id_is_none_not_an_error() {
        let s = SqliteStore::in_memory().unwrap();
        assert!(s.order_by_matching_id("nope").unwrap().is_none());
    }
}
```

- [ ] **Step 2: Run them to verify they fail**

```bash
cargo test -p smdp --lib
```

Expected: the `store` module does not exist.

- [ ] **Step 3: Implement**

```bash
cd crates/smdp && cargo add rusqlite --features bundled
```

`bundled` compiles SQLite in, so the build does not depend on what the host happens to have.

`sqlite.rs` opens a connection behind a `Mutex` (the `Store` trait is `Send + Sync`, and `rusqlite::Connection` is `Send` but not `Sync`), runs the schema on open, and maps rows to `Order`. The schema:

```sql
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
```

`OrderState` is stored as its lowercase name, and an unknown value read back is a `StoreError` rather than a silent default — a state this code does not understand is not a state to guess at.

- [ ] **Step 4: Run the tests to verify they pass**

```bash
cargo test -p smdp --lib
```

Expected: five tests pass.

- [ ] **Step 5: Commit**

```bash
git add -A && git commit -m "feat: a store that remembers which eUICC got which Profile"
```

---

### Task 2: The service seam, and the CLI

The CLI holds no logic. It parses arguments and calls the service; when the admin API arrives, its handlers call the same functions. That is the one place this design builds ahead of what is being built, and it is justified because the next step is already named rather than imagined.

**Files:**
- Create: `crates/smdp/src/service.rs`, `crates/smdp/src/bin/smdp.rs`
- Modify: `crates/smdp/src/lib.rs`, `crates/smdp/Cargo.toml`

**Interfaces:**
- Consumes: Task 1.
- Produces:
  ```rust
  pub fn create_order(
      store: &dyn Store,
      iccid: &[u8; 10],
      upp: Vec<u8>,
      metadata: Vec<u8>,
      matching_id: Option<String>,
  ) -> Result<Order, ServiceError>;

  pub fn list_orders(store: &dyn Store) -> Result<Vec<Order>, ServiceError>;

  /// `LPA:1$<host>$<matchingId>` -- SGP.22 section 4.1.
  pub fn activation_code(host: &str, matching_id: &str) -> String;
  ```
  `create_order` generates a MatchingID when none is given.

- [ ] **Step 1: Write the failing tests**

In `service.rs`:

```rust
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
```

- [ ] **Step 2: Run them to verify they fail**

```bash
cargo test -p smdp --lib service
```

Expected: no `service` module.

- [ ] **Step 3: Implement the service and the CLI**

```bash
cd crates/smdp && cargo add clap --features derive && cargo add rand
```

MatchingIDs come from `rand`, not a counter: SGP.22 treats a MatchingID as the secret that authorises a download, so a guessable one hands out Profiles. Twenty-two characters of an alphanumeric alphabet is the shape used here.

`src/bin/smdp.rs` with `clap`'s derive:

```
smdp order add   --db PATH --upp FILE --iccid HEX --profile-name NAME --sp-name NAME [--matching-id ID] [--host HOST]
smdp order list  --db PATH
smdp serve       --db PATH --addr ADDR --server-address HOST      (Task 5)
```

`order add` prints the MatchingID and, when `--host` is given, the activation code. `--iccid` takes 20 hex digits and is rejected otherwise, with a message naming what was wrong.

The `StoreMetadataRequest` `order add` records is built from `--iccid`, `--profile-name` and `--sp-name`. **Building it needs an encoder this repository does not have yet** — `euicc-rsp` builds one only inside its test fixtures. For this task, `order add` takes `--metadata FILE` (a pre-encoded `StoreMetadataRequest`, such as `vendor/euicc-rsp/testdata/session/store-metadata.der`), and `--profile-name`/`--sp-name` are not yet accepted. Say so in `--help` rather than pretending.

- [ ] **Step 4: Run the tests to verify they pass**

```bash
cargo test -p smdp --lib
```

Expected: three new tests pass, plus Task 1's five.

- [ ] **Step 5: Prove the CLI end to end**

```bash
cargo run -p smdp --bin smdp -- order add --db /tmp/smdp-check.db \
  --upp vendor/euicc-rsp/testdata/session/upp.der \
  --metadata vendor/euicc-rsp/testdata/session/store-metadata.der \
  --iccid 98001032547698103214 --host smdp.example.com
cargo run -p smdp --bin smdp -- order list --db /tmp/smdp-check.db
rm -f /tmp/smdp-check.db
```

Expected: a MatchingID and an `LPA:1$smdp.example.com$...` line, then a list containing that one order.

- [ ] **Step 6: Commit**

```bash
git add -A && git commit -m "feat: orders go in through a CLI, and the logic is not in the CLI"
```

---

### Task 3: The ES9+ JSON binding

Types only — no HTTP yet. Getting the wire format right is separable from serving it, and it is where the spec's four correction points live.

**Files:**
- Create: `crates/smdp/src/es9/mod.rs`, `crates/smdp/src/es9/wire.rs`
- Modify: `crates/smdp/src/lib.rs`, `crates/smdp/Cargo.toml`

**Interfaces:**
- Consumes: nothing.
- Produces: serde types for the three request and three response bodies named in the spec's field table, plus:
  ```rust
  pub fn to_hex_upper(b: &[u8]) -> String;
  pub fn from_hex(s: &str) -> Result<Vec<u8>, WireError>;

  /// The `header` every ES9+ *response* carries. Requests have none.
  pub struct ResponseHeader { pub function_execution_status: FunctionExecutionStatus }
  pub enum ExecutionStatus { ExecutedSuccess, ExecutedWithWarning, Failed, Expired }
  ```
  Payload fields are `Vec<u8>` in Rust and base64 on the wire; `transactionId` is `Vec<u8>` in Rust and uppercase hex on the wire.

- [ ] **Step 1: Write the failing tests**

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_transaction_id_is_uppercase_hex_not_base64() {
        // SGP.22 6.5.2.6: pattern ^[0-9,A-F]{2,32}$ -- the one payload
        // field that is not base64.
        let req = GetBoundProfilePackageRequest {
            transaction_id: vec![0x01, 0xab, 0xff],
            prepare_download_response: vec![0x30, 0x00],
        };
        let v: serde_json::Value = serde_json::to_value(&req).unwrap();
        assert_eq!(v["transactionId"], "01ABFF");
        assert_eq!(v["prepareDownloadResponse"], "MAA=");
    }

    #[test]
    fn a_request_carries_no_header() {
        // 6.5.1.1: "HTTP messages for ES9+ and ES11 SHALL not contain
        // the <JSON requestHeader>".
        let req = InitiateAuthenticationRequest {
            euicc_challenge: vec![0u8; 16],
            euicc_info1: vec![0x30, 0x00],
            smdp_address: "smdp.example.com".into(),
        };
        let v: serde_json::Value = serde_json::to_value(&req).unwrap();
        assert!(v.get("header").is_none(), "an ES9+ request has no header");
        assert_eq!(v.as_object().unwrap().len(), 3);
    }

    #[test]
    fn a_failed_response_says_so_in_the_body_not_the_status_code() {
        let r = ResponseHeader::failed("8.1.1", "3.9", "the address is not this server's");
        let v: serde_json::Value = serde_json::to_value(&r).unwrap();
        assert_eq!(v["header"]["functionExecutionStatus"]["status"], "Failed");
        assert_eq!(
            v["header"]["functionExecutionStatus"]["statusCodeData"]["subjectCode"],
            "8.1.1"
        );
    }

    #[test]
    fn hex_round_trips_and_rejects_rubbish() {
        assert_eq!(to_hex_upper(&[0x0a, 0xf0]), "0AF0");
        assert_eq!(from_hex("0af0").unwrap(), vec![0x0a, 0xf0]);
        assert!(from_hex("zz").is_err());
        assert!(from_hex("abc").is_err(), "an odd number of digits is not bytes");
    }

    #[test]
    fn a_recorded_response_serialises_to_the_recorded_bytes() {
        // The fields the C library produced, carried through JSON and
        // back, must still be the bytes it signed.
        let resp = std::fs::read(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../vendor/euicc-rsp/testdata/session/initiate-response.der"
        ))
        .unwrap();
        let f = crate::rsp::initiate_fields(&resp).unwrap();
        let body = InitiateAuthenticationResponse {
            transaction_id: vec![0x01, 0x02],
            server_signed1: f.server_signed1.to_vec(),
            server_signature1: f.server_signature1.to_vec(),
            euicc_ci_pkid_to_be_used: f.euicc_ci_pkid.to_vec(),
            server_certificate: f.server_certificate.to_vec(),
        };
        let s = serde_json::to_string(&body).unwrap();
        let back: InitiateAuthenticationResponse = serde_json::from_str(&s).unwrap();
        assert_eq!(back.server_signed1, f.server_signed1);
        assert_eq!(back.server_certificate, f.server_certificate);
    }
}
```

- [ ] **Step 2: Run them to verify they fail**

```bash
cargo test -p smdp --lib es9
```

- [ ] **Step 3: Implement**

```bash
cd crates/smdp && cargo add serde --features derive && cargo add serde_json base64
```

Every struct is `#[serde(rename_all = "camelCase")]` with a `with =` module for the base64 fields and another for the hex `transactionId`. `ResponseHeader::failed` and `ResponseHeader::success` are constructors so no handler assembles one by hand.

- [ ] **Step 4: Run the tests to verify they pass**

- [ ] **Step 5: Commit**

```bash
git add -A && git commit -m "feat: the ES9+ JSON binding, as the specification has it"
```

---

### Task 4: The three endpoints, over plain HTTP

**Files:**
- Create: `crates/smdp/src/server/mod.rs`, `crates/smdp/src/server/es9.rs`, `crates/smdp/src/server/sessions.rs`
- Create: `crates/smdp/tests/http.rs`
- Modify: `crates/smdp/src/bin/smdp.rs` (the `serve` subcommand), `Cargo.toml`

**Interfaces:**
- Consumes: Tasks 1–3 and part one's `DpSession`.
- Produces:
  ```rust
  pub struct ServerConfig { pub server_address: String }
  pub fn router(store: Arc<dyn Store>, cfg: ServerConfig) -> axum::Router;
  ```

**The one load-bearing `unsafe` in this task.** `DpSession` holds a raw pointer, so it is neither `Send` nor `Sync`, and an axum handler must be `Send`. Sessions therefore live in a `Mutex<HashMap<Vec<u8>, DpSession>>` and `DpSession` gets:

```rust
// Safety: rsp_dp_session_t is a plain heap struct that euicc-rsp only
// ever touches through the pointer it is handed; the library keeps no
// thread-local state for it. Moving one between threads is therefore
// sound. Send only -- never Sync: two threads inside one session at once
// is not something the C side promises anything about, which is why
// every session sits behind a Mutex.
unsafe impl Send for DpSession {}
```

Write that comment. An `unsafe impl` without a stated argument is a promise nobody checked.

- [ ] **Step 1: Write the failing test**

`crates/smdp/tests/http.rs` — the whole point of the task, driving a real server with the recorded session:

```rust
// Binds to port 0, so the test never collides with anything.
#[tokio::test]
async fn the_recorded_session_downloads_through_the_server() {
    let store = std::sync::Arc::new(SqliteStore::in_memory().unwrap());
    let order = smdp::service::create_order(
        store.as_ref(),
        &ICCID,
        fixture("upp.der"),
        fixture("store-metadata.der"),
        Some("MATCH-1".into()),
    )
    .unwrap();

    let addr = spawn(store.clone()).await;
    let c = reqwest::Client::new();

    // 1 -- InitiateAuthentication
    let r: serde_json::Value = post(&c, &addr, "initiateAuthentication", json!({
        "euiccChallenge": b64(&fixture("euicc-challenge.bin")),
        "euiccInfo1": b64(&fixture("euicc-info1.der")),
        "smdpAddress": "smdp.example.com",
    })).await;
    assert_eq!(r["header"]["functionExecutionStatus"]["status"], "Executed-Success");
    let tid = r["transactionId"].as_str().unwrap().to_string();
    assert_eq!(tid, tid.to_uppercase(), "transactionId is uppercase hex");

    // 2 -- AuthenticateClient
    let r: serde_json::Value = post(&c, &addr, "authenticateClient", json!({
        "transactionId": tid,
        "authenticateServerResponse": b64(&fixture("auth-server-response.der")),
    })).await;
    assert_eq!(r["header"]["functionExecutionStatus"]["status"], "Executed-Success");

    // 3 -- GetBoundProfilePackage
    let r: serde_json::Value = post(&c, &addr, "getBoundProfilePackage", json!({
        "transactionId": tid,
        "prepareDownloadResponse": b64(&fixture("prepare-download-response.der")),
    })).await;
    let bpp = b64_decode(r["boundProfilePackage"].as_str().unwrap());
    assert_eq!(
        bpp,
        fixture("bound-profile-package.der"),
        "the served BPP differs from the one euicc-rsp recorded"
    );

    // and the order remembers the eUICC, which is what notifications will need
    let o = store.order_by_matching_id("MATCH-1").unwrap().unwrap();
    assert!(o.eid.is_some() && o.euicc_cert.is_some());
    assert_eq!(o.state, smdp::store::OrderState::Downloaded);
    let _ = order;
}

#[tokio::test]
async fn a_wrong_smdp_address_fails_in_the_body_with_status_200() {
    // SGP.22 6.3: a synchronous function answers 200 whether it
    // succeeded or not.
    let store = std::sync::Arc::new(SqliteStore::in_memory().unwrap());
    let addr = spawn(store).await;
    let resp = reqwest::Client::new()
        .post(format!("http://{addr}/gsma/rsp2/es9plus/initiateAuthentication"))
        .json(&json!({
            "euiccChallenge": b64(&fixture("euicc-challenge.bin")),
            "euiccInfo1": b64(&fixture("euicc-info1.der")),
            "smdpAddress": "someone-else.example.com",
        }))
        .send().await.unwrap();
    assert_eq!(resp.status(), 200, "a refusal is still a 200");
    let v: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(v["header"]["functionExecutionStatus"]["status"], "Failed");
}

#[tokio::test]
async fn an_unknown_transaction_id_is_refused() {
    let store = std::sync::Arc::new(SqliteStore::in_memory().unwrap());
    let addr = spawn(store).await;
    let v: serde_json::Value = post(&reqwest::Client::new(), &addr, "authenticateClient", json!({
        "transactionId": "AABBCCDD",
        "authenticateServerResponse": b64(&fixture("auth-server-response.der")),
    })).await;
    assert_eq!(v["header"]["functionExecutionStatus"]["status"], "Failed");
}
```

Write `spawn`, `post`, `b64`, `b64_decode`, `fixture` and `ICCID` as helpers at the top of the same file: `spawn` binds a `tokio::net::TcpListener` to `127.0.0.1:0`, serves `router(...)` on a spawned task, and returns the bound address.

**Which order does a download get?** This server has no MatchingID in the ES9+ flow yet — `AuthenticateClient`'s `ctxParams1` carries it, and this library does not read it. So `AuthenticateClient` uses the single `Available` order when there is exactly one, and fails with a `Failed` status naming the ambiguity when there is not. Say that in a comment: it is a real limitation, not an oversight, and it is what the admin API and `ctxParams1` parsing will later replace.

- [ ] **Step 2: Run the test to verify it fails**

```bash
cargo test -p smdp --test http
```

- [ ] **Step 3: Implement**

```bash
cd crates/smdp && cargo add axum tokio --features tokio/rt-multi-thread,tokio/macros,tokio/net
cargo add --dev reqwest --features json
```

`sessions.rs` holds the `Mutex<HashMap<..>>` with a creation timestamp per session and a sweep that drops anything older than ten minutes, called on each insert — an RSP session that never finishes must not pin memory forever.

`es9.rs` has one handler per route, each of them: decode, look the session up (or create one), call the wrapper, map `Ok` to a success body and `Err` to a `Failed` header, and always answer `200`. On `GetBoundProfilePackage` success it calls `set_state(order, Downloaded)`; on `AuthenticateClient` success it calls `bind_euicc` with the session's EID and the eUICC certificate.

`AuthenticateClient` needs `CERT.EUICC.ECDSA` to store. Part one's wrapper does not expose it, and `euicc-rsp` does not either — the session learns the public key but hands back no certificate. **Store the `authenticateServerResponse` bytes the LPA sent instead**, which contain the certificate, and note in a comment that a later change to `euicc-rsp` should hand back the certificate itself so a notification can be verified without re-parsing a whole `AuthenticateServerResponse`. Do not silently store nothing.

- [ ] **Step 4: Run the tests to verify they pass**

```bash
cargo test -p smdp
```

- [ ] **Step 5: Wire up `serve` and try it by hand**

Add the `serve` subcommand, then:

```bash
cargo run -p smdp --bin smdp -- serve --db /tmp/smdp.db --addr 127.0.0.1:8080 --server-address smdp.example.com
```

Expected: it starts and logs the address. Stop it with Ctrl-C.

- [ ] **Step 6: Commit**

```bash
git add -A && git commit -m "feat: three endpoints, and a download that crosses a socket"
```

---

### Task 5: TLS, and saying what is true

**Files:**
- Modify: `crates/smdp/src/bin/smdp.rs`, `crates/smdp/Cargo.toml`, `README.md`

- [ ] **Step 1: Add TLS to `serve`**

```bash
cd crates/smdp && cargo add axum-server --features tls-rustls
```

`--tls-cert FILE --tls-key FILE` together switch `serve` to HTTPS; neither one alone is accepted, and giving only one is an error naming the other. Without them it serves plain HTTP and says so on startup — SGP.22 section 6.1 requires TLS on ES9+, and a server that quietly speaks cleartext while looking like an SM-DP+ is worse than one that announces it.

- [ ] **Step 2: Prove it against a self-signed certificate**

```bash
openssl req -x509 -newkey rsa:2048 -keyout /tmp/k.pem -out /tmp/c.pem -days 1 -nodes -subj "/CN=localhost"
cargo run -p smdp --bin smdp -- serve --db /tmp/smdp.db --addr 127.0.0.1:8443 \
  --server-address smdp.example.com --tls-cert /tmp/c.pem --tls-key /tmp/k.pem &
sleep 2
curl -sk https://127.0.0.1:8443/gsma/rsp2/es9plus/initiateAuthentication \
  -H 'Content-Type: application/json' -d '{}' | head -c 200; echo
kill %1
```

Expected: a JSON body with a `Failed` status (the request is empty, so it should fail) — proving TLS terminated and the route answered.

- [ ] **Step 3: Update the README**

Replace "No HTTPS, no ES9+ endpoints, no database, no CLI" with what is now true, and state plainly what still is not: no ES2+, no admin API, no notifications, no `CancelSession`, and that the MatchingID is not yet read from `ctxParams1` so a server with more than one available order cannot tell which is wanted.

- [ ] **Step 4: Commit**

```bash
git add -A && git commit -m "feat: TLS, and a README that does not overclaim"
```

---

## What is still not here

- **Notifications.** The schema and the stored eUICC identity are in place for them; nothing collects or verifies one.
- **`CancelSession`.** The fifth ES9+ function.
- **ES2+ and an admin API.** The service seam exists so that adding one is not a restructuring.
- **`ctxParams1` parsing**, which is what would let a download name its own order by MatchingID.
- **`euicc-tools --server`**, the client that proves all of this against a physical eUICC. That is the last plan, and it is the one that turns "the tests pass" into "the card accepted it".
