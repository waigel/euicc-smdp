//! One handler per ES9+ function.
//!
//! Every one of them answers HTTP 200, whether the function succeeded or
//! not: SGP.22 v2.6 section 6.3 is explicit that a synchronous
//! request-response function does so "regardless whether the function
//! response is an error or a success". Failure is expressed in
//! functionExecutionStatus. RspError's Refused/NotReached distinction
//! still decides what goes in the body -- it just no longer picks a
//! status code.
//!
//! The euicc-rsp calls are synchronous and short (elliptic-curve work on
//! a few hundred bytes), so they run inline rather than on a blocking
//! pool. No await happens while the session mutex is held.

use std::sync::Arc;

use axum::{
    extract::State,
    http::{header, HeaderMap, HeaderValue, StatusCode},
    response::{IntoResponse, Response},
    Json,
};

use crate::es9::{
    AuthenticateClientRequest, AuthenticateClientResponse, FailureResponse,
    GetBoundProfilePackageRequest, GetBoundProfilePackageResponse,
    InitiateAuthenticationRequest, InitiateAuthenticationResponse, ResponseHeader, ADMIN_PROTOCOL,
};
use crate::rsp::{authenticate_fields, initiate_fields, DpSession, RspError};
use crate::store::OrderState;

use super::AppState;

/// Section 6.2 requires X-Admin-Protocol on the response as well as the
/// request.
fn ok_json<T: serde::Serialize>(body: T) -> Response {
    let mut h = HeaderMap::new();
    h.insert("X-Admin-Protocol", HeaderValue::from_static(ADMIN_PROTOCOL));
    h.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/json"),
    );
    (StatusCode::OK, h, Json(body)).into_response()
}

fn failed(subject: &str, reason: &str, message: &str) -> Response {
    ok_json(FailureResponse {
        header: ResponseHeader::failed(subject, reason, message),
    })
}

/// Status codes from SGP.22 sections 5.2.6.1 and 5.2.6.2. Only the few
/// this server can actually produce are named.
mod code {
    /// 8.1.1 -- the SM-DP+ address subject.
    pub const SMDP_ADDRESS: &str = "8.1.1";
    /// 8.10.1 -- the transactionId subject.
    pub const TRANSACTION_ID: &str = "8.10.1";
    /// 8.2.5 -- the Profile subject.
    pub const PROFILE: &str = "8.2.5";
    /// 3.8 -- refused.
    pub const REFUSED: &str = "3.8";
    /// 3.9 -- unknown / not found.
    pub const UNKNOWN: &str = "3.9";
    /// 4.2 -- execution error.
    pub const EXECUTION: &str = "4.2";
}

/// A refusal and an unreachable question are both a Failed status, but
/// they are not the same failure and the reason code says so.
fn from_rsp_error(e: RspError, subject: &str) -> Response {
    match e {
        RspError::Refused(what) => failed(subject, code::REFUSED, &format!("{what}: refused")),
        RspError::NotReached(what) => failed(
            subject,
            code::EXECUTION,
            &format!("{what}: could not be attempted"),
        ),
    }
}

pub async fn initiate_authentication(
    State(st): State<Arc<AppState>>,
    Json(req): Json<InitiateAuthenticationRequest>,
) -> Response {
    let challenge: [u8; 16] = match req.euicc_challenge.as_slice().try_into() {
        Ok(c) => c,
        Err(_) => {
            return failed(
                code::EXECUTION,
                code::EXECUTION,
                "euiccChallenge is not 16 bytes",
            )
        }
    };

    // Fresh random in production; a recorded session replays because
    // these come from the configured source rather than being drawn
    // here. See ServerConfig::nonces.
    let transaction_id = st.config.nonces.transaction_id();
    let server_challenge = st.config.nonces.server_challenge();

    let (session, resp) = match DpSession::initiate(
        &challenge,
        &req.euicc_info1,
        &transaction_id,
        &server_challenge,
        &st.config.server_address,
        Some(&req.smdp_address),
    ) {
        Ok(v) => v,
        Err(e) => return from_rsp_error(e, code::SMDP_ADDRESS),
    };

    let f = match initiate_fields(resp.as_slice()) {
        Ok(f) => f,
        Err(e) => return from_rsp_error(e, code::EXECUTION),
    };
    let body = InitiateAuthenticationResponse {
        header: ResponseHeader::success(),
        transaction_id: transaction_id.to_vec(),
        server_signed1: f.server_signed1.to_vec(),
        server_signature1: f.server_signature1.to_vec(),
        euicc_ci_pkid_to_be_used: f.euicc_ci_pkid.to_vec(),
        server_certificate: f.server_certificate.to_vec(),
    };

    st.sessions
        .lock()
        .unwrap()
        .insert(transaction_id.to_vec(), session);
    ok_json(body)
}

pub async fn authenticate_client(
    State(st): State<Arc<AppState>>,
    Json(req): Json<AuthenticateClientRequest>,
) -> Response {
    // Which order is this download for? AuthenticateClient's ctxParams1
    // carries the MatchingID, and euicc-rsp does not read it -- so with
    // more than one order available there is genuinely no way to tell
    // which is wanted. Refusing is honest; guessing would hand out the
    // wrong Profile. Parsing ctxParams1 is what replaces this.
    // Available *or* Bound. Bound only means an eUICC authenticated
    // against this order once; if the download did not finish, the
    // Profile is still here and still wanted. Filtering to Available
    // alone stranded an order permanently the first time any step after
    // AuthenticateClient failed -- which is exactly what happens while
    // bringing a card up. Downloaded and Failed are not offered: the
    // first has been handed out, and the second was refused by the
    // eUICC itself.
    let available: Vec<_> = match st.store.list_orders() {
        Ok(o) => o
            .into_iter()
            .filter(|o| {
                o.state == OrderState::Available || o.state == OrderState::Bound
            })
            .collect(),
        Err(e) => return failed(code::PROFILE, code::EXECUTION, &e.to_string()),
    };
    let order = match available.len() {
        1 => available.into_iter().next().unwrap(),
        0 => {
            return failed(
                code::PROFILE,
                code::UNKNOWN,
                "no order is available -- add one, or reset one that has \
                 already been downloaded (smdp order list shows their state)",
            )
        }
        n => {
            return failed(
                code::PROFILE,
                code::UNKNOWN,
                &format!(
                    "{n} orders are available and the MatchingID is not read from ctxParams1 yet, \
                     so this server cannot tell which is wanted"
                ),
            )
        }
    };

    let mut guard = st.sessions.lock().unwrap();
    let entry = match guard.get_mut(&req.transaction_id) {
        Some(e) => e,
        None => {
            return failed(
                code::TRANSACTION_ID,
                code::UNKNOWN,
                "no session with this transactionId",
            )
        }
    };

    let resp = match entry
        .session
        .authenticate_client(&req.authenticate_server_response, &order.metadata)
    {
        Ok(r) => r,
        Err(e) => return from_rsp_error(e, code::TRANSACTION_ID),
    };
    let eid = entry.session.eid().ok();
    entry.order_id = Some(order.id);
    drop(guard);

    let g = match authenticate_fields(resp.as_slice()) {
        Ok(g) => g,
        Err(e) => return from_rsp_error(e, code::EXECUTION),
    };
    let body = AuthenticateClientResponse {
        header: ResponseHeader::success(),
        transaction_id: req.transaction_id.clone(),
        profile_metadata: g.profile_metadata.to_vec(),
        smdp_signed2: g.smdp_signed2.to_vec(),
        smdp_signature2: g.smdp_signature2.to_vec(),
        smdp_certificate: g.smdp_certificate.to_vec(),
    };

    // Remember which eUICC this went to. A notification arrives with no
    // session and no EID, so this row is the only way to know whose
    // signature to check later.
    //
    // What is stored as the certificate is the whole
    // AuthenticateServerResponse, which contains CERT.EUICC.ECDSA:
    // euicc-rsp learns the public key but hands no certificate back, so
    // there is nothing better to store yet. A later change there should
    // return the certificate itself, and this should follow it.
    if let Some(eid) = eid {
        let _ = st
            .store
            .bind_euicc(order.id, &eid, &req.authenticate_server_response);
    }
    let _ = st.store.set_state(order.id, OrderState::Bound);

    ok_json(body)
}

pub async fn get_bound_profile_package(
    State(st): State<Arc<AppState>>,
    Json(req): Json<GetBoundProfilePackageRequest>,
) -> Response {
    let otsk_dp = st.config.nonces.otsk_dp();

    let mut guard = st.sessions.lock().unwrap();
    let entry = match guard.get_mut(&req.transaction_id) {
        Some(e) => e,
        None => {
            return failed(
                code::TRANSACTION_ID,
                code::UNKNOWN,
                "no session with this transactionId",
            )
        }
    };
    let order_id = entry.order_id;
    let upp = match order_id.and_then(|id| {
        st.store
            .list_orders()
            .ok()?
            .into_iter()
            .find(|o| o.id == id)
            .map(|o| o.upp)
    }) {
        Some(u) => u,
        None => {
            return failed(
                code::PROFILE,
                code::UNKNOWN,
                "this session has not authenticated against an order yet",
            )
        }
    };

    let bpp = match entry.session.get_bound_profile_package(
        &req.prepare_download_response,
        &upp,
        &otsk_dp,
    ) {
        Ok(b) => b,
        Err(e) => return from_rsp_error(e, code::TRANSACTION_ID),
    };
    let body = GetBoundProfilePackageResponse {
        header: ResponseHeader::success(),
        transaction_id: req.transaction_id.clone(),
        bound_profile_package: bpp.as_slice().to_vec(),
    };
    guard.remove(&req.transaction_id);
    drop(guard);

    if let Some(id) = order_id {
        let _ = st.store.set_state(id, OrderState::Downloaded);
    }
    ok_json(body)
}
