mod error;
mod owned;

pub use error::{Result, RspError};
pub use owned::OwnedDer;

use std::ffi::CString;
use std::ptr;

/// One RSP session's server-side state, from InitiateAuthentication to
/// GetBoundProfilePackage.
///
/// There is no lock around the C calls any more. There used to be:
/// euicc-rsp kept its signing RNG in an unsynchronised singleton, and
/// its vendored mbedTLS was built without MBEDTLS_THREADING_C. Both are
/// fixed upstream, and `tests/session.rs` measures it -- 20 runs of
/// eight threads, no crash.
///
/// Dropping it calls `rsp_dp_session_free`, which zeroizes rather than
/// merely freeing -- the SCP03t session keys land in here.
pub struct DpSession {
    raw: *mut rsp_sys::rsp_dp_session_t,
}

impl Drop for DpSession {
    fn drop(&mut self) {
        unsafe { rsp_sys::rsp_dp_session_free(self.raw) }
    }
}

impl DpSession {
    /// SGP.22 v2.6 section 5.6.1, `InitiateAuthentication`.
    ///
    /// `transaction_id` and `server_challenge` are the caller's to
    /// supply, with no internal fallback: production passes fresh
    /// random, a test passes a fixed value, and that is what makes a
    /// recorded session replayable.
    ///
    /// `requested_address` is the `smdpAddress` the LPA sent. When it is
    /// `Some`, section 5.6.1 has the SM-DP+ compare it against its own
    /// case-insensitively, and a mismatch is [`RspError::Refused`].
    pub fn initiate(
        euicc_challenge: &[u8; 16],
        euicc_info1: &[u8],
        transaction_id: &[u8; 16],
        server_challenge: &[u8; 16],
        server_address: &str,
        requested_address: Option<&str>,
    ) -> Result<(DpSession, OwnedDer)> {
        const WHAT: &str = "InitiateAuthentication";

        // A NUL inside an address means the question was never asked,
        // not that the library said no.
        let own = CString::new(server_address).map_err(|_| RspError::NotReached(WHAT))?;
        let req = match requested_address {
            Some(a) => Some(CString::new(a).map_err(|_| RspError::NotReached(WHAT))?),
            None => None,
        };

        let mut sess: *mut rsp_sys::rsp_dp_session_t = ptr::null_mut();
        let mut resp: *mut u8 = ptr::null_mut();
        let mut resp_len: usize = 0;

        let rc = unsafe {
            rsp_sys::rsp_dp_initiate_authentication(
                euicc_challenge.as_ptr(),
                euicc_challenge.len(),
                euicc_info1.as_ptr(),
                euicc_info1.len(),
                transaction_id.as_ptr(),
                server_challenge.as_ptr(),
                own.as_ptr(),
                req.as_ref().map_or(ptr::null(), |c| c.as_ptr()),
                &mut sess,
                &mut resp,
                &mut resp_len,
            )
        };
        if rc != 0 {
            // The library leaves both out-parameters untouched on
            // failure, so there is nothing to free here.
            return Err(RspError::from_code(rc, WHAT));
        }
        Ok((DpSession { raw: sess }, unsafe {
            OwnedDer::from_raw(resp, resp_len)
        }))
    }
}

impl std::fmt::Debug for DpSession {
    /// Deliberately opaque: this holds session keys once
    /// GetBoundProfilePackage has run, and a derived Debug would be a
    /// way for them to reach a log.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("DpSession(..)")
    }
}

impl DpSession {
    /// SGP.22 v2.6 section 5.6.3, `AuthenticateClient`.
    ///
    /// `metadata` is an encoded `StoreMetadataRequest`. This library has
    /// no Profile order database to learn a Profile's ICCID or name
    /// from, so the caller supplies it -- and the same value is reused
    /// for [`Self::get_bound_profile_package`], rather than two that
    /// could drift.
    pub fn authenticate_client(
        &mut self,
        auth_server_resp: &[u8],
        metadata: &[u8],
    ) -> Result<OwnedDer> {
        const WHAT: &str = "AuthenticateClient";
        let mut out: *mut u8 = ptr::null_mut();
        let mut out_len: usize = 0;
        let rc = unsafe {
            rsp_sys::rsp_dp_authenticate_client(
                self.raw,
                auth_server_resp.as_ptr(),
                auth_server_resp.len(),
                metadata.as_ptr(),
                metadata.len(),
                &mut out,
                &mut out_len,
            )
        };
        if rc != 0 {
            return Err(RspError::from_code(rc, WHAT));
        }
        Ok(unsafe { OwnedDer::from_raw(out, out_len) })
    }

    /// SGP.22 v2.6 section 5.6.2, `GetBoundProfilePackage`.
    ///
    /// `otsk_dp` is caller-supplied for the same reason the transaction
    /// id and server challenge are: a fixed value makes the session
    /// replayable.
    pub fn get_bound_profile_package(
        &mut self,
        prepare_download_resp: &[u8],
        upp: &[u8],
        otsk_dp: &[u8; 32],
    ) -> Result<OwnedDer> {
        const WHAT: &str = "GetBoundProfilePackage";
        let mut bpp: *mut u8 = ptr::null_mut();
        let mut bpp_len: usize = 0;
        let rc = unsafe {
            rsp_sys::rsp_dp_get_bound_profile_package(
                self.raw,
                prepare_download_resp.as_ptr(),
                prepare_download_resp.len(),
                upp.as_ptr(),
                upp.len(),
                otsk_dp.as_ptr(),
                &mut bpp,
                &mut bpp_len,
            )
        };
        if rc != 0 {
            return Err(RspError::from_code(rc, WHAT));
        }
        Ok(unsafe { OwnedDer::from_raw(bpp, bpp_len) })
    }

    /// The EID [`Self::authenticate_client`] learned from
    /// CERT.EUICC.ECDSA's own Subject `serialNumber` -- decimal digits,
    /// and never NUL-terminated by the C side.
    pub fn eid(&self) -> Result<String> {
        const WHAT: &str = "session EID";
        let mut buf = [0u8; 64];
        let mut len: usize = 0;
        let rc =
            unsafe { rsp_sys::rsp_dp_session_eid(self.raw, buf.as_mut_ptr(), buf.len(), &mut len) };
        if rc != 0 {
            return Err(RspError::from_code(rc, WHAT));
        }
        String::from_utf8(buf[..len].to_vec()).map_err(|_| RspError::NotReached(WHAT))
    }
}

/// The five fields of `InitiateAuthenticationOkEs9` the ES9+ JSON
/// binding names (SGP.22 v2.6 section 6.5.2.6), each the complete TLV.
#[derive(Debug)]
pub struct InitiateFields<'a> {
    pub transaction_id: &'a [u8],
    pub server_signed1: &'a [u8],
    pub server_signature1: &'a [u8],
    pub euicc_ci_pkid: &'a [u8],
    pub server_certificate: &'a [u8],
}

/// The five fields of `AuthenticateClientOk` (section 6.5.2.8).
#[derive(Debug)]
pub struct AuthenticateFields<'a> {
    pub transaction_id: &'a [u8],
    pub profile_metadata: &'a [u8],
    pub smdp_signed2: &'a [u8],
    pub smdp_signature2: &'a [u8],
    pub smdp_certificate: &'a [u8],
}

/// Cut, not decoded and re-encoded: what a server base64-encodes is then
/// what the library signed.
///
/// The C accessor hands back borrowed views into `resp`. Tying the
/// returned lifetime to `resp` is what turns that from a documented
/// promise into a checked one.
pub fn initiate_fields(resp: &[u8]) -> Result<InitiateFields<'_>> {
    const WHAT: &str = "InitiateAuthentication fields";
    let mut f = std::mem::MaybeUninit::<rsp_sys::rsp_dp_initiate_fields_t>::zeroed();
    let rc = unsafe { rsp_sys::rsp_dp_initiate_fields(resp.as_ptr(), resp.len(), f.as_mut_ptr()) };
    if rc != 0 {
        return Err(RspError::from_code(rc, WHAT));
    }
    let f = unsafe { f.assume_init() };
    // Safety: on a 0 return every pair points inside resp, which outlives
    // the returned struct by this function's signature.
    unsafe {
        Ok(InitiateFields {
            transaction_id: std::slice::from_raw_parts(f.transaction_id, f.transaction_id_len),
            server_signed1: std::slice::from_raw_parts(f.server_signed1, f.server_signed1_len),
            server_signature1: std::slice::from_raw_parts(
                f.server_signature1,
                f.server_signature1_len,
            ),
            euicc_ci_pkid: std::slice::from_raw_parts(f.euicc_ci_pkid, f.euicc_ci_pkid_len),
            server_certificate: std::slice::from_raw_parts(
                f.server_certificate,
                f.server_certificate_len,
            ),
        })
    }
}

/// The `AuthenticateClient` counterpart of [`initiate_fields`]. Its input
/// is one level deeper -- an `AuthenticateClientResponseEs9` CHOICE, tag
/// `BF3B` -- which the C side steps through.
pub fn authenticate_fields(resp: &[u8]) -> Result<AuthenticateFields<'_>> {
    const WHAT: &str = "AuthenticateClient fields";
    let mut g = std::mem::MaybeUninit::<rsp_sys::rsp_dp_authenticate_fields_t>::zeroed();
    let rc =
        unsafe { rsp_sys::rsp_dp_authenticate_fields(resp.as_ptr(), resp.len(), g.as_mut_ptr()) };
    if rc != 0 {
        return Err(RspError::from_code(rc, WHAT));
    }
    let g = unsafe { g.assume_init() };
    unsafe {
        Ok(AuthenticateFields {
            transaction_id: std::slice::from_raw_parts(g.transaction_id, g.transaction_id_len),
            profile_metadata: std::slice::from_raw_parts(
                g.profile_metadata,
                g.profile_metadata_len,
            ),
            smdp_signed2: std::slice::from_raw_parts(g.smdp_signed2, g.smdp_signed2_len),
            smdp_signature2: std::slice::from_raw_parts(g.smdp_signature2, g.smdp_signature2_len),
            smdp_certificate: std::slice::from_raw_parts(
                g.smdp_certificate,
                g.smdp_certificate_len,
            ),
        })
    }
}

// Safety: rsp_dp_session_t is a plain heap struct that euicc-rsp only
// ever touches through the pointer it is handed; the library keeps no
// thread-local state for it, and every function taking one takes it as a
// parameter. Moving one between threads is therefore sound, which is
// what an axum handler needs.
//
// Send only -- deliberately never Sync. Two threads inside one session
// at once is not something the C side promises anything about, which is
// why every session lives behind a Mutex.
unsafe impl Send for DpSession {}
