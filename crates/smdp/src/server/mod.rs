//! The ES9+ endpoints of SGP.22, over HTTP.

pub mod es9;
pub mod sessions;

use std::sync::{Arc, Mutex};

use axum::{routing::post, Router};

use crate::store::Store;
use sessions::Sessions;

/// The three values a session draws rather than receives.
///
/// euicc-rsp made exactly this argument one level down, and the same
/// reasoning applies here: "production passes fresh random, a test
/// passes a fixed value, and that difference is the entire reason a
/// recorded session can be replayed". The eUICC signs over the
/// transactionId and serverChallenge it was sent, so a recorded
/// AuthenticateServerResponse only verifies against the session that
/// used those exact values.
///
/// There is no internal fallback: a server is constructed with a source
/// or it is not constructed, so no test path can ship by accident.
pub trait Nonces: Send + Sync {
    fn transaction_id(&self) -> [u8; 16];
    fn server_challenge(&self) -> [u8; 16];
    fn otsk_dp(&self) -> [u8; 32];
}

/// What production uses: the OS CSPRNG, fresh every time.
pub struct OsNonces;

impl OsNonces {
    fn fill<const N: usize>() -> [u8; N] {
        let mut b = [0u8; N];
        getrandom::fill(&mut b).expect("the OS CSPRNG is unavailable");
        b
    }
}

impl Nonces for OsNonces {
    fn transaction_id(&self) -> [u8; 16] {
        Self::fill()
    }
    fn server_challenge(&self) -> [u8; 16] {
        Self::fill()
    }
    fn otsk_dp(&self) -> [u8; 32] {
        Self::fill()
    }
}

pub struct ServerConfig {
    /// This SM-DP+'s own address. Signed into serverSigned1, and what
    /// the smdpAddress an LPA sends is checked against (section 5.6.1).
    pub server_address: String,
    pub nonces: Box<dyn Nonces>,
}

impl ServerConfig {
    /// The ordinary constructor: a real address and real randomness.
    pub fn new(server_address: impl Into<String>) -> Self {
        ServerConfig {
            server_address: server_address.into(),
            nonces: Box::new(OsNonces),
        }
    }
}

pub struct AppState {
    pub store: Arc<dyn Store>,
    pub sessions: Mutex<Sessions>,
    pub config: ServerConfig,
}

pub fn router(store: Arc<dyn Store>, config: ServerConfig) -> Router {
    let state = Arc::new(AppState {
        store,
        sessions: Mutex::new(Sessions::default()),
        config,
    });
    // Paths from SGP.22 v2.6 Table 57.
    Router::new()
        .route(
            "/gsma/rsp2/es9plus/initiateAuthentication",
            post(es9::initiate_authentication),
        )
        .route(
            "/gsma/rsp2/es9plus/authenticateClient",
            post(es9::authenticate_client),
        )
        .route(
            "/gsma/rsp2/es9plus/getBoundProfilePackage",
            post(es9::get_bound_profile_package),
        )
        .route(
            "/gsma/rsp2/es9plus/handleNotification",
            post(es9::handle_notification),
        )
        .with_state(state)
}
