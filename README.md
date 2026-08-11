# euicc-smdp

The SM-DP+ of SGP.22, as a server. It stands on
[euicc-rsp](https://github.com/waigel/euicc-rsp), which runs the protocol
itself, and adds the two things a library deliberately does not have: a
network, and a memory of which eUICC was given which Profile.

It now has both. The three ES9+ functions answer over HTTP — with TLS when
given a certificate — and orders live in SQLite, which is also where the
EID and eUICC certificate of a completed download are remembered.

What has been proven, and how: a whole session driven over a real socket
returns a Bound Profile Package **byte-identical** to the one `euicc-rsp`
records for the same inputs. Not "the call succeeded" — the same bytes.
No card is involved, and none is needed for that claim.

```sh
smdp order add --db smdp.db --upp profile.der \
  --metadata vendor/euicc-rsp/testdata/session/store-metadata.der \
  --iccid 98001032547698103214 --host smdp.example.com
smdp serve --db smdp.db --addr 0.0.0.0:8443 --server-address smdp.example.com \
  --tls-cert cert.pem --tls-key key.pem
```

Without `--tls-cert`/`--tls-key` it serves cleartext and says so on
startup: SGP.22 section 6.1 requires TLS on ES9+, and a server that
quietly speaks HTTP while looking like an SM-DP+ is worse than one that
announces it.

| Repository | Role |
| --- | --- |
| [asn1c-vn](https://github.com/waigel/asn1c-vn) | the language |
| [euicc-schema](https://github.com/waigel/euicc-schema) | the vocabulary |
| [euicc-rsp](https://github.com/waigel/euicc-rsp) | the protocol |
| [euicc-lpa](https://github.com/waigel/euicc-lpa) | the card side |
| [euicc-tools](https://github.com/waigel/euicc-tools) | the command |
| `euicc-smdp` (this one) | the server |

## Build

```sh
git clone --recurse-submodules git@github.com:waigel/euicc-smdp.git
cd euicc-smdp
cargo test
```

No card reader is needed, and none will be: everything here is provable
against recorded bytes. `vendor/euicc-rsp/testdata/session/` holds one
whole RSP session, written by that repository's `make session-fixtures`
and byte-for-byte reproducible, which is what a test replays instead of
talking to hardware.

The build runs `euicc-rsp`'s own Makefile, so its prerequisites are this
repository's too — in particular `asn1c` 0.9.29 or newer, which generates
the RSP codec. See that repository's README for the version floor and how
to satisfy it on Debian and Ubuntu.

`bindgen` needs `libclang`. On macOS the Command Line Tools provide it; if
it is not found, point `LIBCLANG_PATH` at
`/Library/Developer/CommandLineTools/usr/lib`.

## What is not here yet

- **Notifications.** `HandleNotification` and the ES10b commands behind
  it. The schema is ready for them — a completed download stores the EID
  and the eUICC's own bytes, which is what lets a notification be
  verified with no session behind it — but nothing collects or checks one.
- **`CancelSession`**, the fifth ES9+ function.
- **ES2+ and an admin API.** Orders go in through the CLI. The logic
  already sits in a service module rather than in the CLI handlers, so
  adding an API is not a restructuring.
- **`ctxParams1` parsing.** The MatchingID an LPA sends is carried there,
  and this server does not read it — so it serves the single available
  order and refuses, naming the reason, when more than one exists.
- **Encoding a `StoreMetadataRequest`.** `order add` takes a pre-encoded
  one as a file rather than offering `--profile-name` flags it cannot
  honour.
- **A physical eUICC.** Every claim here is against recorded bytes. What
  turns "the tests pass" into "the card accepted it" is a client, and
  that lives in `euicc-tools`.

## A constraint worth knowing

`euicc-rsp`'s vendored mbedTLS is built without `MBEDTLS_THREADING_C`, so
the C library is not thread-safe. This crate serializes every call into it
behind one process-wide lock, at the boundary rather than in the server,
so a second consumer cannot forget. `crates/smdp/tests/session.rs` pins
it: remove the lock and that test segfaults.

The cost is that cryptographic work does not run in parallel. Enabling
`MBEDTLS_THREADING_C` upstream would be the way to stop paying it.

## License

MIT. The SGP.26 test credentials reached through `euicc-rsp` are published
GSMA **test** material — they work on test eUICCs and nowhere else.
