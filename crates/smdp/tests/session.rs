use smdp::rsp::{DpSession, RspError};

/// The fixtures are read out of the submodule rather than copied in.
/// euicc-rsp writes them with `make session-fixtures`, and a second copy
/// here would be free to drift from the one the C tests pin.
fn fixture(name: &str) -> Vec<u8> {
    let p = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../vendor/euicc-rsp/testdata/session/"
    );
    std::fs::read(format!("{p}{name}"))
        .unwrap_or_else(|e| panic!("fixture {name} is missing ({e}) -- run make session-fixtures"))
}

fn arr16(name: &str) -> [u8; 16] {
    fixture(name).try_into().expect("expected exactly 16 bytes")
}

const ADDR: &str = "smdp.example.com";

#[test]
fn a_session_opens_from_the_recorded_bytes() {
    let (_s, resp) = DpSession::initiate(
        &arr16("euicc-challenge.bin"),
        &fixture("euicc-info1.der"),
        &arr16("transaction-id.bin"),
        &arr16("server-challenge.bin"),
        ADDR,
        Some(ADDR),
    )
    .expect("the recorded session opens");

    // Not merely "it returned 0": the bytes Rust got back are the bytes
    // the C tool recorded for these same inputs.
    assert_eq!(
        resp.as_slice(),
        fixture("initiate-response.der").as_slice(),
        "the response differs from the one euicc-rsp recorded"
    );
}

#[test]
fn a_mismatched_address_is_refused_not_broken() {
    let err = DpSession::initiate(
        &arr16("euicc-challenge.bin"),
        &fixture("euicc-info1.der"),
        &arr16("transaction-id.bin"),
        &arr16("server-challenge.bin"),
        ADDR,
        Some("other.example.com"),
    )
    .expect_err("a different address must be refused");
    assert!(
        matches!(err, RspError::Refused(_)),
        "an address mismatch is the library saying no, not failing to ask: {err:?}"
    );
}

#[test]
fn a_case_only_difference_is_not_a_mismatch() {
    DpSession::initiate(
        &arr16("euicc-challenge.bin"),
        &fixture("euicc-info1.der"),
        &arr16("transaction-id.bin"),
        &arr16("server-challenge.bin"),
        ADDR,
        Some("SMDP.EXAMPLE.COM"),
    )
    .expect("SGP.22 5.6.1 compares case-insensitively");
}

#[test]
fn a_malformed_euicc_info1_never_reaches_the_question() {
    let err = DpSession::initiate(
        &arr16("euicc-challenge.bin"),
        b"not an EUICCInfo1",
        &arr16("transaction-id.bin"),
        &arr16("server-challenge.bin"),
        ADDR,
        None,
    )
    .expect_err("garbage input must not open a session");
    assert!(
        matches!(err, RspError::NotReached(_)),
        "malformed input is a question never reached: {err:?}"
    );
}
