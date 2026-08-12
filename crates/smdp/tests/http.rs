//! The recorded session, driven through a running server over HTTP.
//!
//! Nothing is stubbed: axum serves on a real socket, reqwest speaks to
//! it, and the Bound Profile Package that comes out is compared against
//! the one euicc-rsp recorded for the same inputs.

use std::sync::Arc;

use base64::{engine::general_purpose::STANDARD, Engine};
use serde_json::json;

use smdp::server::{router, Nonces, ServerConfig};
use smdp::store::{sqlite::SqliteStore, OrderState, Store};

const ICCID: [u8; 10] = [0x98, 0x00, 0x10, 0x32, 0x54, 0x76, 0x98, 0x10, 0x32, 0x14];
const ADDR: &str = "smdp.example.com";

fn fixture(name: &str) -> Vec<u8> {
    let p = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../vendor/euicc-rsp/testdata/session/"
    );
    std::fs::read(format!("{p}{name}")).expect("fixture missing -- run make session-fixtures")
}

fn b64(b: &[u8]) -> String {
    STANDARD.encode(b)
}

fn b64_decode(s: &str) -> Vec<u8> {
    STANDARD.decode(s).expect("not base64")
}

/// The values euicc-rsp's tools/session-fixtures used. The recorded
/// eUICC answers were signed over these, so only a server using them can
/// replay the session -- which is the whole point of the trait.
struct RecordedNonces;

impl Nonces for RecordedNonces {
    fn transaction_id(&self) -> [u8; 16] {
        fixture("transaction-id.bin").try_into().unwrap()
    }
    fn server_challenge(&self) -> [u8; 16] {
        fixture("server-challenge.bin").try_into().unwrap()
    }
    fn otsk_dp(&self) -> [u8; 32] {
        fixture("otsk-dp.bin").try_into().unwrap()
    }
}

/// Port 0, so the test never collides with anything.
async fn spawn(store: Arc<dyn Store>) -> String {
    let app = router(
        store,
        ServerConfig {
            server_address: ADDR.into(),
            nonces: Box::new(RecordedNonces),
        },
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap().to_string();
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    addr
}

async fn call(
    client: &reqwest::Client,
    addr: &str,
    function: &str,
    body: serde_json::Value,
) -> (reqwest::StatusCode, serde_json::Value) {
    let r = client
        .post(format!("http://{addr}/gsma/rsp2/es9plus/{function}"))
        .header("X-Admin-Protocol", "gsma/rsp/v2.6.0")
        .header("User-Agent", "gsma-rsp-lpad")
        .json(&body)
        .send()
        .await
        .unwrap();
    let status = r.status();
    (status, r.json().await.unwrap())
}

fn seeded() -> Arc<SqliteStore> {
    let store = Arc::new(SqliteStore::in_memory().unwrap());
    smdp::service::create_order(
        store.as_ref(),
        &ICCID,
        fixture("upp.der"),
        fixture("store-metadata.der"),
        Some("MATCH-1".into()),
    )
    .unwrap();
    store
}

#[tokio::test]
async fn the_recorded_session_downloads_through_the_server() {
    let store = seeded();
    let addr = spawn(store.clone()).await;
    let c = reqwest::Client::new();

    // 1 -- InitiateAuthentication
    let (status, r) = call(
        &c,
        &addr,
        "initiateAuthentication",
        json!({
            "euiccChallenge": b64(&fixture("euicc-challenge.bin")),
            "euiccInfo1": b64(&fixture("euicc-info1.der")),
            "smdpAddress": ADDR,
        }),
    )
    .await;
    assert_eq!(status, 200);
    assert_eq!(
        r["header"]["functionExecutionStatus"]["status"], "Executed-Success",
        "{r}"
    );
    let tid = r["transactionId"].as_str().unwrap().to_string();
    assert_eq!(tid, tid.to_uppercase(), "transactionId is uppercase hex");
    assert_eq!(tid, "0102030405060708090A0B0C0D0E0F10", "the recorded one");
    assert_eq!(tid.len(), 32, "16 bytes of transactionId");

    // 2 -- AuthenticateClient
    let (status, r) = call(
        &c,
        &addr,
        "authenticateClient",
        json!({
            "transactionId": tid,
            "authenticateServerResponse": b64(&fixture("auth-server-response.der")),
        }),
    )
    .await;
    assert_eq!(status, 200);
    assert_eq!(
        r["header"]["functionExecutionStatus"]["status"], "Executed-Success",
        "{r}"
    );

    // 3 -- GetBoundProfilePackage
    let (status, r) = call(
        &c,
        &addr,
        "getBoundProfilePackage",
        json!({
            "transactionId": tid,
            "prepareDownloadResponse": b64(&fixture("prepare-download-response.der")),
        }),
    )
    .await;
    assert_eq!(status, 200);
    assert_eq!(
        r["header"]["functionExecutionStatus"]["status"], "Executed-Success",
        "{r}"
    );
    let bpp = b64_decode(r["boundProfilePackage"].as_str().unwrap());
    assert_eq!(
        bpp,
        fixture("bound-profile-package.der"),
        "the served BPP differs from the one euicc-rsp recorded"
    );

    // The order remembers the eUICC -- the row a notification will need.
    let o = store.order_by_matching_id("MATCH-1").unwrap().unwrap();
    assert_eq!(o.state, OrderState::Downloaded);
    assert_eq!(
        o.eid.as_deref(),
        Some("89049032123451234512345678901235"),
        "the EID from CERT.EUICC.ECDSA's Subject"
    );
    assert!(o.euicc_cert.is_some());
}

#[tokio::test]
async fn a_wrong_smdp_address_fails_in_the_body_with_status_200() {
    // SGP.22 6.3: a synchronous function answers 200 whether it
    // succeeded or not.
    let addr = spawn(seeded()).await;
    let (status, v) = call(
        &reqwest::Client::new(),
        &addr,
        "initiateAuthentication",
        json!({
            "euiccChallenge": b64(&fixture("euicc-challenge.bin")),
            "euiccInfo1": b64(&fixture("euicc-info1.der")),
            "smdpAddress": "someone-else.example.com",
        }),
    )
    .await;
    assert_eq!(status, 200, "a refusal is still a 200");
    assert_eq!(v["header"]["functionExecutionStatus"]["status"], "Failed");
    assert_eq!(
        v["header"]["functionExecutionStatus"]["statusCodeData"]["reasonCode"], "3.8",
        "refused, not an execution error: {v}"
    );
}

#[tokio::test]
async fn a_case_only_difference_in_the_address_is_accepted() {
    let addr = spawn(seeded()).await;
    let (_, v) = call(
        &reqwest::Client::new(),
        &addr,
        "initiateAuthentication",
        json!({
            "euiccChallenge": b64(&fixture("euicc-challenge.bin")),
            "euiccInfo1": b64(&fixture("euicc-info1.der")),
            "smdpAddress": "SMDP.EXAMPLE.COM",
        }),
    )
    .await;
    assert_eq!(
        v["header"]["functionExecutionStatus"]["status"], "Executed-Success",
        "5.6.1 compares case-insensitively: {v}"
    );
}

#[tokio::test]
async fn an_unknown_transaction_id_is_refused() {
    let addr = spawn(seeded()).await;
    let (status, v) = call(
        &reqwest::Client::new(),
        &addr,
        "authenticateClient",
        json!({
            "transactionId": "AABBCCDD",
            "authenticateServerResponse": b64(&fixture("auth-server-response.der")),
        }),
    )
    .await;
    assert_eq!(status, 200);
    assert_eq!(v["header"]["functionExecutionStatus"]["status"], "Failed");
}

#[tokio::test]
async fn the_response_carries_the_admin_protocol_header() {
    // Section 6.2 requires it on the response as well as the request.
    let addr = spawn(seeded()).await;
    let r = reqwest::Client::new()
        .post(format!(
            "http://{addr}/gsma/rsp2/es9plus/initiateAuthentication"
        ))
        .json(&json!({
            "euiccChallenge": b64(&fixture("euicc-challenge.bin")),
            "euiccInfo1": b64(&fixture("euicc-info1.der")),
            "smdpAddress": ADDR,
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(
        r.headers().get("X-Admin-Protocol").unwrap(),
        "gsma/rsp/v2.6.0"
    );
}

#[tokio::test]
async fn a_half_finished_download_can_be_retried() {
    // AuthenticateClient marks an order Bound. If only Available orders
    // were offered, any failure after that step stranded the order for
    // good -- which is precisely what happens while bringing a card up,
    // and it happened on the first real card this project ever reached.
    let store = seeded();
    let o = store.order_by_matching_id("MATCH-1").unwrap().unwrap();
    store.set_state(o.id, OrderState::Bound).unwrap();

    let addr = spawn(store.clone()).await;
    let c = reqwest::Client::new();

    let (_, r) = call(
        &c,
        &addr,
        "initiateAuthentication",
        json!({
            "euiccChallenge": b64(&fixture("euicc-challenge.bin")),
            "euiccInfo1": b64(&fixture("euicc-info1.der")),
            "smdpAddress": ADDR,
        }),
    )
    .await;
    let tid = r["transactionId"].as_str().unwrap().to_string();

    let (_, r) = call(
        &c,
        &addr,
        "authenticateClient",
        json!({
            "transactionId": tid,
            "authenticateServerResponse": b64(&fixture("auth-server-response.der")),
        }),
    )
    .await;
    assert_eq!(
        r["header"]["functionExecutionStatus"]["status"], "Executed-Success",
        "a Bound order must still be offered: {r}"
    );
}

#[tokio::test]
async fn a_downloaded_order_is_not_offered_again() {
    let store = seeded();
    let o = store.order_by_matching_id("MATCH-1").unwrap().unwrap();
    store.set_state(o.id, OrderState::Downloaded).unwrap();

    let addr = spawn(store).await;
    let c = reqwest::Client::new();
    let (_, r) = call(
        &c,
        &addr,
        "initiateAuthentication",
        json!({
            "euiccChallenge": b64(&fixture("euicc-challenge.bin")),
            "euiccInfo1": b64(&fixture("euicc-info1.der")),
            "smdpAddress": ADDR,
        }),
    )
    .await;
    let tid = r["transactionId"].as_str().unwrap().to_string();

    let (_, r) = call(
        &c,
        &addr,
        "authenticateClient",
        json!({
            "transactionId": tid,
            "authenticateServerResponse": b64(&fixture("auth-server-response.der")),
        }),
    )
    .await;
    assert_eq!(
        r["header"]["functionExecutionStatus"]["status"], "Failed",
        "a Profile already handed out must not be handed out again: {r}"
    );
}

#[tokio::test]
async fn a_notification_is_taken_verified_and_kept() {
    // SGP.22 Table 57 gives HandleNotification the Notification MEP, and
    // section 6.3 says what that means: 204 with an empty body. There is
    // no functionExecutionStatus to answer in, which is right -- an LPA
    // has no key to verify with and nothing to do with a verdict.
    let store = seeded();

    // The server can only check a ProfileInstallationResult against the
    // certificate it kept when that ICCID was downloaded, so the
    // download has to have happened.
    let addr = spawn(store.clone()).await;
    let c = reqwest::Client::new();
    let (_, r) = call(
        &c,
        &addr,
        "initiateAuthentication",
        json!({
            "euiccChallenge": b64(&fixture("euicc-challenge.bin")),
            "euiccInfo1": b64(&fixture("euicc-info1.der")),
            "smdpAddress": ADDR,
        }),
    )
    .await;
    let tid = r["transactionId"].as_str().unwrap().to_string();
    call(
        &c,
        &addr,
        "authenticateClient",
        json!({
            "transactionId": tid,
            "authenticateServerResponse": b64(&fixture("auth-server-response.der")),
        }),
    )
    .await;

    let o = store.order_by_matching_id("MATCH-1").unwrap().unwrap();
    assert!(
        o.euicc_cert.is_some(),
        "the download must have kept a certificate"
    );

    let resp = c
        .post(format!(
            "http://{addr}/gsma/rsp2/es9plus/handleNotification"
        ))
        .json(&json!({ "pendingNotification": b64(&fixture("pending-notification.der")) }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 204, "the Notification MEP answers 204");
    assert!(
        resp.bytes().await.unwrap().is_empty(),
        "and with an empty body"
    );

    let kept = store.notifications().unwrap();
    assert_eq!(kept.len(), 1, "the verified notification was kept");
    assert_eq!(
        kept[0].order_id,
        Some(o.id),
        "matched to its order by ICCID"
    );
    assert_eq!(
        kept[0].installed,
        Some(true),
        "and it says the profile installed"
    );
    assert_eq!(
        kept[0].raw,
        fixture("pending-notification.der"),
        "kept as it arrived -- the eUICC signed over these bytes"
    );
}

#[tokio::test]
async fn a_notification_that_does_not_verify_is_still_answered_but_not_kept() {
    // Refusing would leave it on the eUICC forever, filling a queue that
    // SGP.22 section 3.5 has the card start refusing profile management
    // over. What a rejection does is leave nothing in the store, and
    // that absence is the record.
    let store = seeded();
    let addr = spawn(store.clone()).await;

    let mut tampered = fixture("pending-notification.der");
    let n = tampered.len();
    tampered[n - 20] ^= 0x01;

    let resp = reqwest::Client::new()
        .post(format!(
            "http://{addr}/gsma/rsp2/es9plus/handleNotification"
        ))
        .json(&json!({ "pendingNotification": b64(&tampered) }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 204, "an LPA is told nothing either way");
    assert!(
        store.notifications().unwrap().is_empty(),
        "but nothing unverified is kept"
    );
}
