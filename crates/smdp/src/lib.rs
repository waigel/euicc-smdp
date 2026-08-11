//! The SM-DP+ of SGP.22, standing on euicc-rsp.
//!
//! Everything protocol-shaped lives in [`rsp`], which wraps the C
//! library. The server built on top of it does not exist yet.
pub mod rsp;
pub mod store;
