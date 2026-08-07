# euicc-lpa

The LPA role of SGP.22, as a C library. The LPA sits between an eUICC and an
RSP server: this library holds the card side of that, on top of
[euicc-rsp](https://github.com/waigel/euicc-rsp) for crypto, PKI and the
generated ASN.1 codec.

## Build

```sh
git clone --recurse-submodules https://github.com/waigel/euicc-lpa.git
cd euicc-lpa
make
make check
```

`vendor/euicc-rsp`'s own submodules (its mbedTLS) need to be initialised
recursively too, which `--recurse-submodules` above does; if you already
have a checkout without it:

```sh
git submodule update --init --recursive
```

`make check` needs no card reader. `make check-card` (below) is the one
exception.

**PC/SC.** macOS ships PC/SC as a system framework, so nothing extra is
needed there. Linux needs the `pcsc-lite` headers installed first
(`libpcsclite-dev` on Debian/Ubuntu, `pcsc-lite-devel` on the equivalent
distribution) — the same dependency euicc-rsp itself asks for.

## `make check-card`

The one target that is not provable without hardware: it needs a real card
reader with a test eUICC in it, over PC/SC. It is not part of `make check`
and CI never runs it, for the same reason euicc-rsp excludes its own: there
is no reader attached to a CI runner.
