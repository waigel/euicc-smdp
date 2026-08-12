//! The ES9+ JSON binding, SGP.22 v2.6 section 6.5.
//!
//! Four things about it are easy to get wrong, and all four are decided
//! here rather than in a handler:
//!
//!  - **Requests carry no header.** Section 6.5.1.1: "HTTP messages for
//!    ES9+ and ES11 SHALL not contain the <JSON requestHeader>". Only
//!    responses have one.
//!  - **The HTTP status code carries no function-level meaning.** Section
//!    6.3: a synchronous function answers 200 "regardless whether the
//!    function response is an error or a success". Failure lives in
//!    functionExecutionStatus.
//!  - **transactionId is uppercase hex**, every other payload field is
//!    base64-encoded DER.
//!  - Request and response both carry `X-Admin-Protocol` and
//!    `Content-Type: application/json` (section 6.2).

pub mod wire;

use serde::{Deserialize, Serialize};

/// The version this server claims in X-Admin-Protocol: "the highest
/// version of SGP.22 supported by the sender" (section 6.2).
pub const ADMIN_PROTOCOL: &str = "gsma/rsp/v2.6.0";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ExecutionStatus {
    #[serde(rename = "Executed-Success")]
    ExecutedSuccess,
    #[serde(rename = "Executed-WithWarning")]
    ExecutedWithWarning,
    Failed,
    Expired,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct StatusCodeData {
    pub subject_code: String,
    pub reason_code: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub subject_identifier: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FunctionExecutionStatus {
    pub status: ExecutionStatus,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status_code_data: Option<StatusCodeData>,
}

/// Every ES9+ *response* carries this. Requests do not.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ResponseHeader {
    pub function_execution_status: FunctionExecutionStatus,
}

impl ResponseHeader {
    pub fn success() -> Self {
        ResponseHeader {
            function_execution_status: FunctionExecutionStatus {
                status: ExecutionStatus::ExecutedSuccess,
                status_code_data: None,
            },
        }
    }

    /// subject and reason are the OIDs of sections 5.2.6.1 and 5.2.6.2.
    pub fn failed(subject: &str, reason: &str, message: &str) -> Self {
        ResponseHeader {
            function_execution_status: FunctionExecutionStatus {
                status: ExecutionStatus::Failed,
                status_code_data: Some(StatusCodeData {
                    subject_code: subject.into(),
                    reason_code: reason.into(),
                    subject_identifier: None,
                    message: Some(message.into()),
                }),
            },
        }
    }
}

/// A body that is nothing but a failure report. Every endpoint can
/// answer with one, whichever function was asked for.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FailureResponse {
    pub header: ResponseHeader,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct InitiateAuthenticationRequest {
    #[serde(with = "wire::b64_field")]
    pub euicc_challenge: Vec<u8>,
    #[serde(with = "wire::b64_field")]
    pub euicc_info1: Vec<u8>,
    pub smdp_address: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct InitiateAuthenticationResponse {
    pub header: ResponseHeader,
    #[serde(with = "wire::hex_field")]
    pub transaction_id: Vec<u8>,
    #[serde(with = "wire::b64_field")]
    pub server_signed1: Vec<u8>,
    #[serde(with = "wire::b64_field")]
    pub server_signature1: Vec<u8>,
    /// Spelled out rather than left to rename_all: the specification
    /// writes this one `euiccCiPKIdToBeUsed`, and camelCase of the Rust
    /// name produces `euiccCiPkidToBeUsed`, which no LPA looks for. The
    /// acronym is the whole difference and it is invisible at a glance.
    #[serde(rename = "euiccCiPKIdToBeUsed", with = "wire::b64_field")]
    pub euicc_ci_pkid_to_be_used: Vec<u8>,
    #[serde(with = "wire::b64_field")]
    pub server_certificate: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AuthenticateClientRequest {
    #[serde(with = "wire::hex_field")]
    pub transaction_id: Vec<u8>,
    #[serde(with = "wire::b64_field")]
    pub authenticate_server_response: Vec<u8>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub use_matching_id_for_acr: Option<bool>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AuthenticateClientResponse {
    pub header: ResponseHeader,
    #[serde(with = "wire::hex_field")]
    pub transaction_id: Vec<u8>,
    #[serde(with = "wire::b64_field")]
    pub profile_metadata: Vec<u8>,
    #[serde(with = "wire::b64_field")]
    pub smdp_signed2: Vec<u8>,
    #[serde(with = "wire::b64_field")]
    pub smdp_signature2: Vec<u8>,
    #[serde(with = "wire::b64_field")]
    pub smdp_certificate: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GetBoundProfilePackageRequest {
    #[serde(with = "wire::hex_field")]
    pub transaction_id: Vec<u8>,
    #[serde(with = "wire::b64_field")]
    pub prepare_download_response: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GetBoundProfilePackageResponse {
    pub header: ResponseHeader,
    #[serde(with = "wire::hex_field")]
    pub transaction_id: Vec<u8>,
    #[serde(with = "wire::b64_field")]
    pub bound_profile_package: Vec<u8>,
}

#[cfg(test)]
mod tests {
    use super::wire::*;
    use super::*;

    #[test]
    fn a_transaction_id_is_uppercase_hex_not_base64() {
        let req = GetBoundProfilePackageRequest {
            transaction_id: vec![0x01, 0xab, 0xff],
            prepare_download_response: vec![0x30, 0x00],
        };
        let v: serde_json::Value = serde_json::to_value(&req).unwrap();
        assert_eq!(v["transactionId"], "01ABFF");
        assert_eq!(v["prepareDownloadResponse"], "MAA=");
    }

    #[test]
    fn the_ci_key_id_keeps_the_specification_s_own_spelling() {
        // SGP.22 v2.6 section 6.5.2.6 writes euiccCiPKIdToBeUsed.
        // rename_all = "camelCase" turns the Rust name into
        // euiccCiPkidToBeUsed, which is a different field as far as any
        // LPA is concerned -- and it looks right until one reads it
        // letter by letter. euicc-tools' client found this by failing.
        let body = InitiateAuthenticationResponse {
            header: ResponseHeader::success(),
            transaction_id: vec![0x01],
            server_signed1: vec![0x30],
            server_signature1: vec![0x30],
            euicc_ci_pkid_to_be_used: vec![0x04],
            server_certificate: vec![0x30],
        };
        let v: serde_json::Value = serde_json::to_value(&body).unwrap();
        assert!(
            v.get("euiccCiPKIdToBeUsed").is_some(),
            "the field the specification names is missing; keys are {:?}",
            v.as_object().unwrap().keys().collect::<Vec<_>>()
        );
        assert!(
            v.get("euiccCiPkidToBeUsed").is_none(),
            "the mangled spelling survived"
        );
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
    fn a_failed_response_says_so_in_the_body() {
        let r = FailureResponse {
            header: ResponseHeader::failed("8.1.1", "3.9", "the address is not this server's"),
        };
        let v: serde_json::Value = serde_json::to_value(&r).unwrap();
        assert_eq!(v["header"]["functionExecutionStatus"]["status"], "Failed");
        assert_eq!(
            v["header"]["functionExecutionStatus"]["statusCodeData"]["subjectCode"],
            "8.1.1"
        );
    }

    #[test]
    fn a_success_header_carries_no_status_code_data() {
        let v: serde_json::Value = serde_json::to_value(ResponseHeader::success()).unwrap();
        assert_eq!(v["functionExecutionStatus"]["status"], "Executed-Success");
        assert!(v["functionExecutionStatus"].get("statusCodeData").is_none());
    }

    #[test]
    fn hex_round_trips_and_rejects_rubbish() {
        assert_eq!(to_hex_upper(&[0x0a, 0xf0]), "0AF0");
        assert_eq!(from_hex("0af0").unwrap(), vec![0x0a, 0xf0]);
        assert!(from_hex("zz").is_err());
        assert!(
            from_hex("abc").is_err(),
            "an odd number of digits is not bytes"
        );
    }

    #[test]
    fn a_recorded_response_survives_the_json_round_trip_unchanged() {
        // The bytes the C library signed must still be those bytes after
        // going out through JSON and coming back.
        let resp = std::fs::read(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../vendor/euicc-rsp/testdata/session/initiate-response.der"
        ))
        .unwrap();
        let f = crate::rsp::initiate_fields(&resp).unwrap();
        let body = InitiateAuthenticationResponse {
            header: ResponseHeader::success(),
            transaction_id: vec![0x01, 0x02],
            server_signed1: f.server_signed1.to_vec(),
            server_signature1: f.server_signature1.to_vec(),
            euicc_ci_pkid_to_be_used: f.euicc_ci_pkid.to_vec(),
            server_certificate: f.server_certificate.to_vec(),
        };
        let s = serde_json::to_string(&body).unwrap();
        let back: InitiateAuthenticationResponse = serde_json::from_str(&s).unwrap();
        assert_eq!(back.server_signed1, f.server_signed1);
        assert_eq!(back.server_signature1, f.server_signature1);
        assert_eq!(back.server_certificate, f.server_certificate);
    }
}
