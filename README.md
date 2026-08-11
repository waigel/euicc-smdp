# euicc-smdp

The SM-DP+ of SGP.22, as a server. It stands on
[euicc-rsp](https://github.com/waigel/euicc-rsp), which runs the protocol
itself, and adds the two things a library deliberately does not have: a
network, and a memory of which eUICC was given which Profile.

Right now it has neither. What exists is the protocol, reachable from
Rust: a whole SM-DP+ session — `InitiateAuthentication`,
`AuthenticateClient`, `GetBoundProfilePackage` — runs against recorded
eUICC bytes and produces a Bound Profile Package byte-identical to the one
`euicc-rsp` produces for the same inputs. No card, no network, no
database. That is the claim this repository currently makes, and the tests
are what make it.

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

No HTTPS, no ES9+ endpoints, no database, no CLI. The design and the plan
for those live in `euicc-rsp` under `docs/superpowers/`, and they are
written down rather than built: this file will say so until it is untrue.

## License

MIT. The SGP.26 test credentials reached through `euicc-rsp` are published
GSMA **test** material — they work on test eUICCs and nowhere else.
