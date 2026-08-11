# euicc-smdp: an SM-DP+ that answers over the network

Design, 2026-08-11.

This document is written in `euicc-rsp` because that is where the
conversation happened and where one of the three changes lands. It moves
into `euicc-smdp` once that repository exists.

## Where this starts

`euicc-rsp` runs the SM-DP+ role of SGP.22 as a library, and it runs it
well enough that a real eUICC accepts what it builds: a profile has been
installed, enabled, disabled and deleted on a physical card, and the
`ProfileInstallationResult` that came back was checked against the eUICC's
own signature rather than believed.

What it is not, and says so in its own README, is a server. No HTTPS, no
ES2+, no SM-DS, no activation code, no Profile order database. Every
session so far has lived inside a single `euicc-tools` process that held
both roles at once: it asked the card questions and answered them itself.

That arrangement has now hit its limit in a specific, diagnosable way.
Notifications were the intended next step, and working through them
surfaced the reason they cannot be done well from where we stand:

- A real LPA never verifies a notification. It has no key to verify with
  and no reason to. It reads `notificationAddress` out of the metadata,
  POSTs the `PendingNotification` to that address unchanged, and deletes
  it from the card only once the server has confirmed. The signature
  exists for the SM-DP+.
- The SM-DP+ receives that notification with no session behind it.
  `NotificationMetadata` carries `seqNumber`, the operation, the address
  and an OPTIONAL ICCID -- and **no EID**. To know whose signature to
  check, the server must have remembered, at download time, which eUICC
  received which ICCID, and kept `CERT.EUICC.ECDSA` from back then.

That memory is the Profile order database the library deliberately does
not have. It does not belong in the library. It belongs in a server that
uses it.

So notifications are deferred, and this design builds the thing they were
waiting on.

## Goal

A standalone SM-DP+ binary that speaks ES9+ over HTTPS, persists what has
to outlive a process, and can complete a real profile download onto a
physical eUICC across a network socket.

## Non-goals

Named so they are decisions rather than omissions:

- **Notifications.** `HandleNotification`, the three ES10b commands, and
  the delivery cycle. This design puts the schema and the stored
  certificate in place for them; it does not implement them.
- **`CancelSession`.** The fifth ES9+ function.
- **ES2+.** The operator-facing interface. Orders are seeded by CLI.
- **An admin API.** Deliberately deferred, but the code is shaped so that
  adding it later is not a restructuring -- see "The service seam".
- **SM-DS, activation-code redemption.** `order add` prints an activation
  code because it costs nothing; nothing consumes one yet.
- **Production credentials.** SGP.26 test material only. A production
  eUICC rejects it, by design.

## Architecture

Five repositories, each with one role:

| Repository | Role |
| --- | --- |
| `euicc-schema` | the vocabulary |
| `euicc-rsp` | the protocol (SM-DP+ role, as a C library) |
| `euicc-lpa` | the card side (LPA role, as a C library) |
| `euicc-tools` | the command |
| `euicc-smdp` | **the server** (new) |

`euicc-smdp` is a Rust workspace that vendors `euicc-rsp` as a submodule,
the same way `euicc-tools` vendors `euicc-lpa`.

```
euicc-smdp/
  Cargo.toml              workspace
  crates/
    rsp-sys/              raw FFI; build.rs runs euicc-rsp's make, bindgen over include/rsp.h
    smdp/                 safe wrapper, store, service, server, CLI
  vendor/euicc-rsp/       submodule
```

Two crates, not four. The `-sys` split is real -- generated bindings and
hand-written safety belong apart -- but the store does not need its own
crate until a second provider exists.

### The FFI layer

`rsp-sys` generates bindings with `bindgen` in `build.rs` rather than
carrying them by hand: `include/rsp.h` is still changing, and a
hand-maintained copy would drift silently. The header includes only
`stddef.h` and `stdint.h`, so nothing generated has to exist first.
`build.rs` invokes the existing Makefile, then links `librsp.a` and the
generated codec objects.

The safe wrapper in `smdp` preserves the library's own failure
distinction rather than flattening it:

```rust
enum RspError {
    /// -1: the question was asked and the answer is no.
    Refused(Refusal),
    /// -2: the question was never reached.
    NotReached(&'static str),
}
```

This is not a style preference. `include/rsp.h` argues for that split at
every declaration that has it, and the CLI's exit-code contract (0 done,
1 a real negative answer, 2 could not answer) is built on it. A `Result`
that collapses both into one error throws away exactly what the library
was careful to provide -- and the HTTP layer needs it too: a refusal is a
4xx with a meaningful ES9+ status, an unreached question is a 5xx.

Every `malloc`'d buffer the library hands back gets a Rust owner that
frees it.

### The store

```rust
trait Store {
    fn order_by_matching_id(&self, id: &str) -> Result<Option<Order>>;
    fn order_by_iccid(&self, iccid: &[u8; 10]) -> Result<Option<Order>>;
    fn bind_euicc(&self, order: OrderId, eid: &str, cert_euicc: &[u8]) -> Result<()>;
    fn set_state(&self, order: OrderId, state: OrderState) -> Result<()>;
    fn add_order(&self, new: NewOrder) -> Result<Order>;
    fn list_orders(&self) -> Result<Vec<Order>>;
}
```

An `Order` holds its MatchingID, ICCID, the UPP bytes, the
`StoreMetadataRequest` DER, and a state: `Available`, `Bound`,
`Downloaded`, `Failed`.

SQLite via `rusqlite` is the default and, for now, only provider. The
trait exists because a second one is expected, not because one is being
written.

`bind_euicc` is the row notifications will later stand on: it is where
the EID and `CERT.EUICC.ECDSA` learned during `AuthenticateClient` are
stored, so that a future `HandleNotification` can verify a signature
without a session. Storing them now costs one column each and removes
the reason notifications were blocked.

### Sessions

`rsp_dp_session_t` offers no serialization, so sessions are **not**
persisted. They live in a `HashMap<TransactionId, DpSession>` in the
process, with a TTL and periodic eviction.

Stated as a consequence, not hidden as an implementation detail: one
process, no horizontal scaling, and a restart aborts every download in
flight. For what this server is for, that is the right trade -- but it
is a trade.

### The service seam

CLI handlers contain no logic. `order add` and `order list` call
functions in a service module that takes `&dyn Store`; the CLI is a thin
argument parser over it. When the admin API arrives, its HTTP handlers
call the same functions.

This is the one place where the design builds ahead of what is being
built, and it is justified by the next step already being named rather
than imagined. It stops there: no client crate, no transport
abstraction, no trait for something that has one implementation.

### The ES9+ endpoints

`axum`, with TLS terminated in-process by `rustls`. Three routes, taken
from Table 57: `/gsma/rsp2/es9plus/initiateAuthentication`,
`/gsma/rsp2/es9plus/authenticateClient`,
`/gsma/rsp2/es9plus/getBoundProfilePackage`. Each is a thin adapter --
decode the request, find or create the session, call one `euicc-rsp`
function, encode the answer.

The binding is the JSON binding of section 6.5, read out of the
specification rather than recalled. What it actually says, including the
four points where an earlier draft of this design was wrong:

- **Requests carry no header.** Section 6.5.1.1: "HTTP messages for ES9+
  and ES11 SHALL not contain the `<JSON requestHeader>`". An ES9+ request
  body is the bare function body. Only responses carry a header, and it
  holds `functionExecutionStatus`.
- **The HTTP status code carries no function-level meaning.** Section
  6.3: a synchronous request-response function answers `200` "regardless
  whether the function response is an error or a success". Failures live
  in `functionExecutionStatus.status` (`Executed-Success`,
  `Executed-WithWarning`, `Failed`, `Expired`) with `statusCodeData`
  carrying `subjectCode` and `reasonCode` as OIDs from sections 5.2.6.1
  and 5.2.6.2. `RspError`'s distinction still decides what goes in the
  body -- it just does not decide the status code. (`204` with an empty
  body is for the Notification MEP, which is `handleNotification`, not
  built here.)
- **`transactionId` is uppercase hex, not base64** -- pattern
  `^[0-9,A-F]{2,32}$`. Every other payload field is base64-encoded DER.
- **Headers**: `X-Admin-Protocol: gsma/rsp/v<x.y.z>` on request and
  response, `Content-Type: application/json`, and `User-Agent:
  gsma-rsp-lpad` on the request (section 6.2).

Field names, confirmed from sections 6.5.2.6 to 6.5.2.8:

| Function | Request | Response |
| --- | --- | --- |
| `initiateAuthentication` | `euiccChallenge`, `euiccInfo1`, `smdpAddress` | `transactionId`, `serverSigned1`, `serverSignature1`, `euiccCiPKIdToBeUsed`, `serverCertificate` |
| `authenticateClient` | `transactionId`, `authenticateServerResponse`, `useMatchingIdForAcr` (optional) | `transactionId`, `profileMetadata`, `smdpSigned2`, `smdpSignature2`, `smdpCertificate` |
| `getBoundProfilePackage` | `transactionId`, `prepareDownloadResponse` | `transactionId`, `boundProfilePackage` |

The ASN.1 binding of section 6.6 -- one path, `/gsma/rsp2/asn1`, DER in
and DER out -- is a conformant alternative and would fit the library's
current return shapes more closely. It is not chosen: real SM-DP+
servers and LPAs use the JSON binding in practice, and a server that
only speaks ASN.1 could not be pointed at by anything but our own
client.

On TLS: section 6.1 mandates TLS 1.2 and, on ES9+, server
authentication only -- mutual TLS is required on ES2+, ES12 and ES15,
not here. A production SM-DP+'s TLS certificate chains to the GSMA CI;
the only client here is our own `euicc-tools`, so the server runs with a
certificate the client is told to trust explicitly. The DP signing
credentials remain SGP.26 test material, unchanged.

### The CLI

One binary, subcommands, `serve` among them -- the shape Ory Hydra uses.

```
smdp serve       --db smdp.db --addr 0.0.0.0:8443 --tls-cert FILE --tls-key FILE
smdp order add   --upp FILE --iccid 89… --profile-name NAME --sp-name NAME [--class C]
smdp order list
```

`order add` prints the MatchingID and an activation code
(`LPA:1$host$MATCHINGID`). Nothing redeems one yet; it names where this
leads and costs nothing to emit.

## Changes in the other two repositories

This project spans three repositories. Both changes outside `euicc-smdp`
are small and neither can be made from inside it.

### `euicc-rsp`: two changes, both forced by the binding

**A real `serverAddress`, and the check that comes with it.**
`src/rsp_es9.c:191` signs the fixed placeholder
`"smdp-address-placeholder.invalid"` because no parameter can carry a
real value -- the README lists this as open. Reading section 5.6.1 shows
this is not one value but two. The SM-DP+ "SHALL" also "[c]heck if the
received address matches its own SM-DP+ address, where the comparison
SHALL be case-insensitive", and `InitiateAuthenticationRequest` carries
`smdpAddress [3] UTF8String` for exactly that.

So `rsp_dp_initiate_authentication` takes both: the server's own address,
which goes into `serverSigned1.serverAddress`, and the address the LPA
sent, which is compared against it case-insensitively. A mismatch is a
genuine refusal -- `InitiateAuthenticationError.invalidDpAddress(1)` --
which means this function moves into the group that splits `-1` ("asked,
answered no") from `-2` ("never reached"). It has a flat `-1` today
because it had nothing to refuse.

**Accessors for the response fields.** The JSON binding needs five named
fields; the library returns one DER blob. Worse, the two functions do not
even return blobs at the same level: `rsp_dp_initiate_authentication`
encodes `InitiateAuthenticationOkEs9`, the inner SEQUENCE, while
`rsp_dp_authenticate_client` encodes `AuthenticateClientResponseEs9`, the
CHOICE.

The protocol knowledge stays in the library rather than being
reconstructed by a TLV walker on the Rust side: each of the two functions
gains a way to hand back its fields individually. The alternative --
having the server re-open the DER the library just wrote -- would put the
same structural knowledge in two places, free to drift.

The level inconsistency itself is **not** straightened out, contrary to
what an earlier draft of this section said. Changing what either function
returns would change bytes that `euicc-lpa`'s `PrepareDownload`
repacking already consumes, for no benefit this design needs. The two
accessors absorb the difference and the header documents it.

### `euicc-tools`: `euicc card install --server URL`

A minimal HTTPS client so the download actually crosses a socket.

Its purpose is evidence. Without it the server is exercisable only by
`curl` and replay fixtures, and this project's standard is that the card
answered -- not that the code looks plausible. `--server` is what makes a
real download onto real hardware the proof that this design works.

A flag for the certificate to trust (`--server-ca`, or an explicit
pinned certificate) comes with it, since the server's certificate does
not chain to a public root.

## Testing

- **Store**: unit tests against an in-memory SQLite.
- **FFI**: tests that each wrapper maps `-1` to `Refused` and `-2` to
  `NotReached`, driven by inputs that produce each -- a signature that
  does not verify versus a null argument.
- **End to end, no hardware**: the server started in-process, driven by
  the card recordings already in the repositories. This keeps the
  existing property that everything is provable with nothing attached.
- **On hardware**: a real download over HTTPS onto the physical eUICC,
  recorded as a fixture so the run is replayable afterwards.

## Order of work

1. ~~Read the binding out of SGP.22.~~ Done; the results are in "The
   ES9+ endpoints" and in the two `euicc-rsp` changes above.
2. `euicc-rsp`: the address parameter pair, the `invalidDpAddress`
   refusal, and the `-1`/`-2` split it brings.
3. `euicc-rsp`: field accessors for the two response types.
4. `euicc-smdp` skeleton: workspace, `rsp-sys` with bindgen and a
   working link against `librsp.a`.
5. The safe wrapper and its error type.
6. Store trait, SQLite provider, schema, service module.
7. CLI: `order add`, `order list`.
8. The three ES9+ endpoints and `serve`.
9. `euicc-tools`: `--server`.
10. The hardware download.

Step 4 now carries the most risk: a build that has to reach across a
language boundary into an existing Makefile. It is early on purpose.
Steps 2 and 3 are in C, in a repository with an existing test suite, and
should be provable there before any Rust exists.
