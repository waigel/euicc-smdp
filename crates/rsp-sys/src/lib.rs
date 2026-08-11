//! Raw FFI for euicc-rsp, the SM-DP+ role of SGP.22 as a C library.
//!
//! Generated from `vendor/euicc-rsp/include/rsp.h` at build time rather
//! than carried by hand: that header is still changing, and a
//! hand-maintained copy would drift silently.
//!
//! Nothing here is safe to call. The wrapper in the `smdp` crate is what
//! turns these into something with lifetimes and a `Result` that keeps
//! the library's own two failure kinds apart.
#![allow(non_upper_case_globals, non_camel_case_types, non_snake_case)]
include!(concat!(env!("OUT_DIR"), "/bindings.rs"));
