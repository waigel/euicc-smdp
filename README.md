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
# The metadata comes from euicc-tools, which reads the ICCID out of the
# Profile itself -- and this reads it back out of the metadata, so it is
# stated once and cannot disagree with what the eUICC will check.
euicc metadata profile.der -o meta.der
smdp order add --db smdp.db --upp profile.der --metadata meta.der \
  --host smdp.example.com
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
  honour. `euicc metadata` in `euicc-tools` writes it, from the Profile
  itself.
- **A physical eUICC.** Every claim here is against recorded bytes. What
  turns "the tests pass" into "the card accepted it" is a client, and
  that lives in `euicc-tools`.

## Threads

There is no lock around the C library. There used to be, and removing it
took two fixes in `euicc-rsp`, neither of which sufficed alone: its
signing RNG was an unsynchronised lazy singleton, and its vendored
mbedTLS was built without `MBEDTLS_THREADING_C`.

`crates/smdp/tests/session.rs` holds it — eight threads opening sessions
concurrently, 20 runs with no crash, where the same test failed in five
of twelve before.

One trap is worth knowing if you build the chain by hand: mbedTLS's
Makefile tracks source mtimes, not the flags it was given. Changing those
flags leaves a stale archive beside freshly compiled objects, and since
they add mutex members to mbedTLS contexts, the two disagree about struct
sizes — silent memory corruption rather than a link error. `euicc-rsp`'s
Makefile now deletes the objects whenever its stamp is out of date, so a
plain `cargo test` is safe.

## License

MIT. The SGP.26 test credentials reached through `euicc-rsp` are published
GSMA **test** material — they work on test eUICCs and nowhere else.
