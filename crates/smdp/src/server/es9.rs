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
    GetBoundProfilePackageRequest, GetBoundProfilePackageResponse, HandleNotificationRequest,
    InitiateAuthenticationRequest, InitiateAuthenticationResponse, ResponseHeader, ADMIN_PROTOCOL,
};
use crate::rsp::{
    authenticate_fields, initiate_fields, notification_metadata, verify_notification, DpSession,
    RspError,
};
use crate::store::{NewNotification, OrderState};

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
            .filter(|o| o.state == OrderState::Available || o.state == OrderState::Bound)
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
    let cert = entry.session.euicc_cert().ok();
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
    // signature to check later -- a ProfileInstallationResult carries no
    // certificate of its own.
    if let (Some(eid), Some(cert)) = (eid, cert) {
        let _ = st.store.bind_euicc(order.id, &eid, &cert);
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

/// SGP.22 v2.6 Table 57 gives HandleNotification the Notification MEP,
/// not the synchronous one every other endpoint here uses. Section 6.3
/// is explicit about what that means: 204, with an empty body. There is
/// no functionExecutionStatus to put a verdict in, and no way to tell
/// the LPA anything at all -- which is correct. An LPA has no key to
/// verify with and nothing to do with the answer; it delivers, and on
/// 204 it removes the notification from the card.
///
/// So a notification this server cannot verify still gets a 204. The
/// alternative is worse: refusing would leave the notification on the
/// eUICC forever, filling a queue that SGP.22 section 3.5 has the card
/// start refusing profile management over. What a rejection does is
/// leave nothing in the store, and that absence is the record.
pub async fn handle_notification(
    State(st): State<Arc<AppState>>,
    Json(req): Json<HandleNotificationRequest>,
) -> Response {
    // A notification carries no EID and no transactionId, so the only
    // way to know whose signature to check is the ICCID -- and the
    // certificate this server kept when that ICCID was downloaded.
    // Reading it proves nothing and is not treated as if it did: it only
    // decides which certificate the real question gets asked with.
    let iccid = notification_metadata(&req.pending_notification)
        .ok()
        .and_then(|n| n.iccid);

    let order = iccid.and_then(|i| st.store.order_by_iccid(&i).ok().flatten());
    let cert = order.as_ref().and_then(|o| o.euicc_cert.clone());

    let verified = verify_notification(cert.as_deref(), &req.pending_notification).ok();

    // Everything that arrives is kept, verified or not. 204 is the only
    // answer the Notification MEP has, so by the time this runs the LPA
    // has already removed it from the eUICC -- which keeps no second
    // copy. Discarding an unverified one would destroy the only copy in
    // existence, and an earlier version of this handler did exactly
    // that: five real notifications from a real card, gone.
    let meta = notification_metadata(&req.pending_notification).ok();
    if let Some(m) = verified.or(meta) {
        let _ = st.store.record_notification(NewNotification {
            verified: verified.is_some(),
            order_id: order.as_ref().map(|o| o.id),
            seq_number: m.seq_number,
            operation: m.operation,
            iccid: m.iccid,
            installed: (verified.is_some() && m.is_installation_result).then_some(m.installed),
            raw: req.pending_notification.clone(),
        });
    }
    // Only a verified notification moves an order. An unverified one is
    // a stranger's claim about somebody else's Profile.
    if let (Some(v), Some(o)) = (verified, order.as_ref()) {
        if v.is_installation_result {
            let _ = st.store.set_state(
                o.id,
                if v.installed {
                    OrderState::Downloaded
                } else {
                    OrderState::Failed
                },
            );
        }
    }

    let mut h = HeaderMap::new();
    h.insert("X-Admin-Protocol", HeaderValue::from_static(ADMIN_PROTOCOL));
    (StatusCode::NO_CONTENT, h).into_response()
}
