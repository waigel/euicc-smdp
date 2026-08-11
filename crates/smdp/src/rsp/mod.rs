mod error;
mod owned;

pub use error::{Result, RspError};
pub use owned::OwnedDer;

use std::ffi::CString;
use std::ptr;

/// One RSP session's server-side state, from InitiateAuthentication to
/// GetBoundProfilePackage.
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
