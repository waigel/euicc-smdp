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

#[test]
fn the_whole_session_runs_and_yields_a_bound_profile_package() {
    let (mut s, init_resp) = DpSession::initiate(
        &arr16("euicc-challenge.bin"),
        &fixture("euicc-info1.der"),
        &arr16("transaction-id.bin"),
        &arr16("server-challenge.bin"),
        ADDR,
        Some(ADDR),
    )
    .expect("the session opens");

    // The five fields the ES9+ JSON binding names (section 6.5.2.6),
    // borrowed from the response rather than rebuilt from a decode.
    let f = smdp::rsp::initiate_fields(init_resp.as_slice()).expect("fields slice out");
    assert_eq!(
        f.transaction_id[0], 0x80,
        "transactionId is [0] implicit -- rsp-2.5.asn is AUTOMATIC TAGS"
    );
    assert_eq!(&f.server_signature1[..2], &[0x5f, 0x37], "[APPLICATION 55]");
    assert!(
        f.server_signed1.as_ptr() < f.server_signature1.as_ptr(),
        "the walk is positional: serverSigned1 comes first"
    );

    let ac = s
        .authenticate_client(
            &fixture("auth-server-response.der"),
            &fixture("store-metadata.der"),
        )
        .expect("the recorded eUICC authenticates");
    assert_eq!(
        ac.as_slice(),
        fixture("authenticate-response.der").as_slice(),
        "the AuthenticateClient response differs from the recorded one"
    );

    let g = smdp::rsp::authenticate_fields(ac.as_slice()).expect("fields slice out");
    assert_eq!(
        &g.profile_metadata[..2],
        &[0xbf, 0x25],
        "profileMetaData is [37]"
    );
    assert_eq!(
        g.smdp_signature2.len(),
        67,
        "'5F 37 40' and 64 of signature"
    );

    let eid = s.eid().expect("the session learned an EID");
    assert!(
        eid.len() == 32 && eid.chars().all(|c| c.is_ascii_digit()),
        "an EID is 32 decimal digits: {eid}"
    );

    let otsk_dp: [u8; 32] = fixture("otsk-dp.bin").try_into().expect("32 bytes");
    let bpp = s
        .get_bound_profile_package(
            &fixture("prepare-download-response.der"),
            &fixture("upp.der"),
            &otsk_dp,
        )
        .expect("a Bound Profile Package comes back");
    assert_eq!(
        bpp.as_slice(),
        fixture("bound-profile-package.der").as_slice(),
        "the BPP differs from the one euicc-rsp recorded"
    );
}

#[test]
fn a_truncated_response_is_refused_by_the_accessors() {
    let resp = fixture("initiate-response.der");
    let err = smdp::rsp::initiate_fields(&resp[..resp.len() / 2])
        .expect_err("half a response is not a response");
    assert!(matches!(err, RspError::Refused(_)), "{err:?}");
}

#[test]
fn many_threads_may_open_sessions_at_once() {
    // euicc-rsp was not thread-safe, for two independent reasons: its
    // signing RNG was an unsynchronised lazy singleton, and its vendored
    // mbedTLS was built without MBEDTLS_THREADING_C. Fixing either alone
    // left it crashing. Both are fixed upstream now, and this test is
    // what keeps a two-request server from finding out otherwise.
    let challenge = arr16("euicc-challenge.bin");
    let info1 = fixture("euicc-info1.der");
    let tid = arr16("transaction-id.bin");
    let sc = arr16("server-challenge.bin");
    let expected = fixture("initiate-response.der");

    let threads: Vec<_> = (0..8)
        .map(|_| {
            let (info1, expected) = (info1.clone(), expected.clone());
            std::thread::spawn(move || {
                for _ in 0..8 {
                    let (_s, resp) =
                        DpSession::initiate(&challenge, &info1, &tid, &sc, ADDR, Some(ADDR))
                            .expect("a session opens");
                    assert_eq!(resp.as_slice(), expected.as_slice());
                }
            })
        })
        .collect();
    for t in threads {
        t.join().expect("no thread may die");
    }
}
