//! The SM-DP+ of SGP.22, standing on euicc-rsp.
//!
//! Everything protocol-shaped lives in [`rsp`], which wraps the C
//! library. The server built on top of it does not exist yet.
pub mod es9;
pub mod rsp;
pub mod server;
pub mod service;
pub mod store;
