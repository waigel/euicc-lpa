# Card recordings

A recording is a text log of one session with a physical eUICC in a card
reader: every command APDU sent and every response APDU received, in the
exact order they crossed the wire. `rsp_record_open` (see `include/rsp.h`
and `src/rsp_transport.c`) writes one while talking to real hardware;
`rsp_replay_open` reads one back and answers the command layer exactly as
the card did, so the same code path runs in CI with no reader attached.

The format is plain text on purpose, not a binary capture:

- a line beginning `> ` is a command APDU, in hex
- a line beginning `< ` is the response, in hex, including its two
  trailing status bytes
- `#` and blank lines are comments
- whitespace inside a hex line is insignificant

That is what lets a recording be read directly in a code review, diffed
meaningfully when it changes, and hand-edited into the failure cases a
healthy card will not itself produce -- a wrong status word, a truncated
response, a segment out of order. `tests/test_recording.c` is itself an
example of a hand-written recording used this way.

Replay expects the recorded sequence strictly: a command that does not
match what comes next, or a command sent after the recording is
exhausted, is refused. A committed recording is a pin on the bytes that
crossed the wire, not a lenient stub that answers whatever it is asked.

## What is safe to commit

This round only reads a card: selecting applets, listing profiles,
fetching public identifiers such as the EID. None of that is secret, and
a recording of it is public data, safe to commit and safe to paste into
an issue or a review comment.

That said, a recording made against real hardware -- `omnikey-info.log`
below, unlike the hand-built `synthetic-*.log` files above it -- carries a
real device's identity: its actual EID, and the SubjectKeyIdentifiers of
the certificate issuers that actual card trusts. Not secret, in the sense
that a card readily hands both to anything that asks. But it is one real
eUICC's own identity, not an invented placeholder, and worth remembering
that before treating every recording in this directory as equally
disposable.

That stops being true the moment a recording covers a *write* session --
loading a profile, or any exchange that carries SCP03t-protected
segments, session keys, or profile content. Those recordings carry
protected material by construction, the same material `rsp_session_t`
and `rsp_credential_t` elsewhere in this library exist to keep off
`stdout`/`stderr`/logs. A recording like that must not be pasted into an
issue, a chat message, or a bug report unexamined -- read what it
actually contains first, the same as you would before sharing a core
dump.

## The synthetic `EUICCInfo2`/`GetEuiccDataResponse` DER

`synthetic-info-direct-select.log`'s two ES10 response payloads are not
hand-invented: `tests/test_es10.c` needs a recording whose `EUICCInfo2`
and `GetEuiccDataResponse` payloads are real DER, and a hand-invented blob
that the generated decoder happens to accept would prove nothing about the
decoder -- it would prove only that two mistakes agree. So those two
payloads were produced by the generated *encoder* instead, with the
following throwaway program (compiled and run once, not part of the
build):

```c
/* Throwaway program: fills an EUICCInfo2 and a GetEuiccDataResponse with the
 * generated types from ~/git/waigel/euicc-rsp/dist and encodes each with the
 * generated der_encode, then prints the result as hex. The output is pasted
 * into testdata/cards/synthetic-info-direct-select.log -- see
 * testdata/cards/README.md.
 *
 * Not part of the build: compiled and run once by hand.
 *
 *   cd ~/git/waigel/euicc-rsp
 *   cc -std=c99 -Wall -idirafter dist -Idist \
 *       /path/to/gen_synthetic_info.c dist/*.o -o /tmp/gen_synthetic_info
 *   /tmp/gen_synthetic_info
 */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "EUICCInfo2.h"
#include "GetEuiccDataResponse.h"

static void print_hex(const uint8_t *b, size_t n) {
    for (size_t i = 0; i < n; i++) printf("%02X", b[i]);
    printf("\n");
}

static int collect(const void *buf, size_t n, void *key) {
    struct { uint8_t *p; size_t len; } *o = key;
    memcpy(o->p + o->len, buf, n);
    o->len += n;
    return 0;
}

static void set_version(VersionType_t *v, uint8_t a, uint8_t b, uint8_t c) {
    uint8_t bytes[3] = { a, b, c };
    OCTET_STRING_fromBuf(v, (const char *)bytes, 3);
}

static void set_bits(BIT_STRING_t *b, uint8_t byte) {
    b->buf = malloc(1);
    b->buf[0] = byte;
    b->size = 1;
    b->bits_unused = 0;
}

int main(void) {
    EUICCInfo2_t info;
    memset(&info, 0, sizeof info);

    set_version(&info.profileVersion, 2, 1, 0);
    set_version(&info.svn, 2, 2, 0);           /* "2.2.0", what the test asserts */
    set_version(&info.euiccFirmwareVer, 6, 0, 0);
    OCTET_STRING_fromBuf(&info.extCardResource, "\x81\x02\x01\x00\x82\x02\x01\x00", 8);
    set_bits(&info.uiccCapability, 0x00);
    set_bits(&info.rspCapability, 0x00);

    /* Two Certificate Issuer identifiers "supported for verification" --
     * SubjectKeyIdentifier is a bare OCTET_STRING with no length fixed by
     * either the module (SGP.22's SubjectKeyIdentifier ::= KeyIdentifier
     * ::= OCTET STRING) or by RFC 5280 section 4.2.1.2, which names two
     * common constructions (a 160-bit SHA-1 hash, or a 4-bit type field
     * plus the low 60 bits of that hash -- 8 bytes) and then says other
     * methods are acceptable too. 20 bytes here is simply the common
     * case (the first of those two constructions), not a length either
     * specification requires -- rsp_card_read_info (src/rsp_es10.c)
     * accepts whatever length a real card sends, as long as every entry
     * in the list agrees with the others. */
    static const uint8_t ci_a[20] = {
        0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0A,
        0x0B,0x0C,0x0D,0x0E,0x0F,0x10,0x11,0x12,0x13,0x14
    };
    static const uint8_t ci_b[20] = {
        0xAA,0xBB,0xCC,0xDD,0xEE,0xFF,0x11,0x22,0x33,0x44,
        0x55,0x66,0x77,0x88,0x99,0x00,0xA1,0xB2,0xC3,0xD4
    };
    SubjectKeyIdentifier_t *ski_a = calloc(1, sizeof *ski_a);
    OCTET_STRING_fromBuf(ski_a, (const char *)ci_a, sizeof ci_a);
    ASN_SEQUENCE_ADD(&info.euiccCiPKIdListForVerification.list, ski_a);
    SubjectKeyIdentifier_t *ski_b = calloc(1, sizeof *ski_b);
    OCTET_STRING_fromBuf(ski_b, (const char *)ci_b, sizeof ci_b);
    ASN_SEQUENCE_ADD(&info.euiccCiPKIdListForVerification.list, ski_b);

    /* One identifier for signing -- distinct from the verification pair
     * above, so nothing downstream could confuse the two lists. */
    static const uint8_t ci_sign[20] = {
        0x99,0x98,0x97,0x96,0x95,0x94,0x93,0x92,0x91,0x90,
        0x89,0x88,0x87,0x86,0x85,0x84,0x83,0x82,0x81,0x80
    };
    SubjectKeyIdentifier_t *ski_sign = calloc(1, sizeof *ski_sign);
    OCTET_STRING_fromBuf(ski_sign, (const char *)ci_sign, sizeof ci_sign);
    ASN_SEQUENCE_ADD(&info.euiccCiPKIdListForSigning.list, ski_sign);

    set_version(&info.ppVersion, 2, 1, 0);
    OCTET_STRING_fromBuf(&info.sasAcreditationNumber, "", 0);
    /* ts102241Version, globalplatformVersion, euiccCategory,
       forbiddenProfilePolicyRules, certificationDataObject: left NULL,
       all OPTIONAL in the module (rsp-2.5.asn). */

    uint8_t buf1[1024];
    struct { uint8_t *p; size_t len; } o1 = { buf1, 0 };
    asn_enc_rval_t r1 = der_encode(&asn_DEF_EUICCInfo2, &info, collect, &o1);
    if (r1.encoded < 0) { fprintf(stderr, "EUICCInfo2 encode failed\n"); return 1; }

    printf("# EUICCInfo2, %zu bytes\n", o1.len);
    print_hex(o1.p, o1.len);

    GetEuiccDataResponse_t eid;
    memset(&eid, 0, sizeof eid);
    static const uint8_t eidval[16] = {
        0x89,0x03,0x30,0x12,0x11,0x22,0x33,0x44,
        0x55,0x66,0x77,0x88,0x99,0x00,0x11,0xFF
    };
    OCTET_STRING_fromBuf(&eid.eidValue, (const char *)eidval, sizeof eidval);

    uint8_t buf2[64];
    struct { uint8_t *p; size_t len; } o2 = { buf2, 0 };
    asn_enc_rval_t r2 = der_encode(&asn_DEF_GetEuiccDataResponse, &eid, collect, &o2);
    if (r2.encoded < 0) { fprintf(stderr, "GetEuiccDataResponse encode failed\n"); return 1; }

    printf("# GetEuiccDataResponse, %zu bytes\n", o2.len);
    print_hex(o2.p, o2.len);

    ASN_STRUCT_RESET(asn_DEF_EUICCInfo2, &info);
    ASN_STRUCT_RESET(asn_DEF_GetEuiccDataResponse, &eid);
    return 0;
}
```

Its output, byte-for-byte what `synthetic-info-direct-select.log` carries
for those two exchanges:

```
# EUICCInfo2, 113 bytes
BF226E810302010082030202008303060000840881020100820201008502000088020000A92C04140102030405060708090A0B0C0D0E0F10111213140414AABBCCDDEEFF11223344556677889900A1B2C3D4AA160414999897969594939291908988878685848382818004030201000C00
# GetEuiccDataResponse, 21 bytes
BF3E125A10890330121122334455667788990011FF
```

The STORE DATA framing (CLA/INS/P1/P2/Lc/Le) around each ES10 request and
response is hand-assembled in `synthetic-info-direct-select.log` itself,
per the citations in `src/rsp_es10.c`'s file header -- only the two ES10
payloads above needed the generated encoder, since those are the only two
fields a
hand-written blob could get subtly wrong without the decoder noticing.
`svn` is `02 02 00`, decoding to "2.2.0"; the EID and both CI identifier
lists are otherwise arbitrary synthetic bytes, not tied to any real card
or issuer.

To regenerate: save the program above, compile and run it exactly as its
own header comment says, then splice its two hex lines into
`synthetic-info-direct-select.log` in place of the current `EUICCInfo2`/
`GetEuiccDataResponse` response lines (keep the trailing ` 9000` each
already carries).

## The SELECT exchange: real hardware, not an assumption

An earlier revision of this directory carried a second fixture,
`synthetic-info.log`, whose purpose was to pin a real card's SELECT
response -- `61 21` ("33 more bytes waiting"), not a bare `9000` -- after
fix round 2 found `rsp_card_select_isdr` treating anything but an exact
`9000` as a refusal and so never sending the GET RESPONSE that status
actually calls for:

```
SELECT ISD-R -> 6121
GET RESPONSE -> 6F1F 8410 A0000005591010FFFFFFFF8900000100 A504 9F6501FF E005 82030202 00 9000
```

(the FCI here is itself informative -- `84 10 <AID>` echoes the AID just
selected, and `E0 05 82 03 02 02 00` is the card's own SGP.22 version,
"2.2.0"). That fixture became redundant the moment `omnikey-info.log`,
below, started carrying the exact same real-hardware SELECT/GET RESPONSE
pair as part of a whole captured session, and `tests/test_es10.c` moved
its main assertions to that recording -- so `synthetic-info.log` was
removed rather than kept as a second copy of coverage `omnikey-info.log`
already provides. This section stays to record why that shape matters at
all, and to explain what `synthetic-info-direct-select.log`, below, is a
deliberate exception to.

`synthetic-info-direct-select.log` keeps the OTHER shape ISO/IEC 7816-4
also permits -- SELECT answering `9000` directly, no FCI at all -- as a
secondary fixture, so that path (no GET RESPONSE needed) stays covered
too. It is not what this project's own card does, and `tests/test_es10.c`
does not drive its main assertions against it for that reason; the
realistic, real-hardware shape is what the main flow now uses, from
`omnikey-info.log`.

## `omnikey-info.log`

This one is not synthetic at all, and not a single exchange hand-copied
from a probe either: it is a whole session, every command and response,
captured straight off the wire by wrapping the PC/SC transport in
`rsp_record_open` (Task 5). `tests/test_card.c` takes an optional first
argument for exactly this: given a path, it records the session it reads
to that file as well as printing it. It was produced with:

```
cd ~/git/waigel/euicc-rsp
make tests/run-card
./tests/run-card testdata/cards/omnikey-info.log
```

against the OMNIKEY AG Smart Card Reader USB and this project's own test
eUICC. The card answered:

```
EID  89049032123451234512345678901235
SVN  2.2.0
issuers 2
CI[0] C0BC70BA36929D43B467FF57570530E57AB8FCD8
CI[1] F54172BDF98A95D65CBEB88A38A1C11D800A85C3
```

`tests/test_es10.c` now drives its main assertions against this recording,
and asserts that exact EID, `"2.2.0"`, and an issuer count of 2 -- the
real card's own answer, not an invented one. `synthetic-info-direct-select.log`
stays in the tree and in the suite for the reason given above: the direct
SELECT (`9000`, no FCI) shape it covers is one this particular card does
not itself produce, and losing that coverage to gain realism elsewhere
would be a poor trade.

Two lines are deliberately absent from this file even though the same
run printed them to the terminal: PC/SC's own protocol-negotiation
messages ("asking for T0|T1 failed... fell back to asking for T0 alone",
"connected, negotiated protocol T=0"). Those come from `rsp_pcsc_open`,
which runs and finishes before `rsp_record_open` ever wraps the
resulting transport, so nothing about the negotiation is or could be
part of the recorded exchange; the file begins directly with the ISD-R
SELECT.

This recording also settles the question the whole round existed to
answer: does this card trust the GSMA SGP.26 test CI our test DPauth/DPpb
credentials chain to?

```
openssl x509 -in testdata/sgp26/ci.der -inform DER -noout -text | grep -A1 "Subject Key Identifier"
```

reports `F5:41:72:BD:F9:8A:95:D6:5C:BE:B8:8A:38:A1:C1:1D:80:0A:85:C3`,
byte-for-byte `CI[1]` above with the colons removed. It does: this card's
own trust list carries our test CI. `CI[0]` is a second, distinct trusted
issuer this recording does not otherwise identify; the identifier's shape
is consistent with GSMA's production root CI, but that is a probable
identification from context, not something this recording or this round
confirms on its own.

## `omnikey-profiles.log`

`rsp_card_read_profiles`'s own recording, captured the same way
`omnikey-info.log` was, now that `tests/test_card.c` takes a second
optional argument for the separate ProfileInfoList session:

```
cd ~/git/waigel/euicc-rsp
make tests/run-card
./tests/run-card /tmp/info.log testdata/cards/omnikey-profiles.log
```

This project's own test eUICC turns out to have no profiles installed at
all: the ISD-R answers `BF2D00` (an unrestricted ProfileInfoListRequest,
searching for "every profile") with `BF2D02A0009000` -- `profileInfoListOk`,
an empty `SEQUENCE OF ProfileInfo`. That is a real and complete answer
(`rsp_card_read_profiles` returns 0 with `*out_count == 0`), not this
function failing to find anything, and `tests/test_profiles.c` asserts
exactly that.

Captured twice, independently, to rule out the desync this project's
shared reader has shown before (see the top-level task brief this round
worked from): both captures agreed byte for byte before this file was
committed. A third and fourth capture, produced by this same
`tests/run-card` invocation while writing this section, agreed with the
first two as well.

Because the real card has nothing installed, this recording alone cannot
exercise a populated list or the error variant -- the next two sections
cover both by hand.

## `synthetic-profiles.log`

Two `ProfileInfo` entries, hand-built the same way
`synthetic-info-direct-select.log`'s `EUICCInfo2`/`GetEuiccDataResponse`
payloads were: with the generated types and `der_encode`, not
hand-invented DER, since a hand-invented blob the decoder happens to
accept would prove nothing about the decoder. The SELECT ISD-R exchange
above the `BF2D00` response is this card's own real FCI, copied from
`omnikey-info.log` -- only the profile list itself is synthetic.

```c
/* Throwaway program: builds a ProfileInfoListResponse with two ProfileInfo
 * entries and encodes it with the generated der_encode. Output is pasted
 * into testdata/cards/synthetic-profiles.log's one response line. Not
 * part of the build: compiled and run once by hand.
 *
 *   cd ~/git/waigel/euicc-rsp
 *   cc -std=c99 -Wall -idirafter dist -Idist \
 *       /path/to/gen_profiles_fixture.c dist/*.o -o /tmp/gen_profiles_fixture
 *   /tmp/gen_profiles_fixture
 */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "ProfileInfoListResponse.h"
#include "ProfileInfo.h"

static void print_hex(const uint8_t *b, size_t n) {
    for (size_t i = 0; i < n; i++) printf("%02X", b[i]);
    printf("\n");
}

static int collect(const void *buf, size_t n, void *key) {
    struct { uint8_t *p; size_t len; } *o = key;
    memcpy(o->p + o->len, buf, n);
    o->len += n;
    return 0;
}

static OCTET_STRING_t *mkoctet(const uint8_t *b, size_t n) {
    OCTET_STRING_t *o = calloc(1, sizeof *o);
    OCTET_STRING_fromBuf(o, (const char *)b, (int)n);
    return o;
}

static long *mklong(long v) {
    long *p = malloc(sizeof *p);
    *p = v;
    return p;
}

int main(void) {
    ProfileInfoListResponse_t resp;
    memset(&resp, 0, sizeof resp);
    resp.present = ProfileInfoListResponse_PR_profileInfoListOk;

    /* Profile A: every field rsp_card_read_profiles reports, present. */
    ProfileInfo_t *a = calloc(1, sizeof *a);
    static const uint8_t iccid_a[10] = {
        0x89, 0x44, 0x05, 0x89, 0x25, 0x00, 0x12, 0x34, 0x56, 0x7F
    };
    a->iccid = mkoctet(iccid_a, sizeof iccid_a);
    static const uint8_t aid_a[16] = {
        0xA0, 0x00, 0x00, 0x05, 0x59, 0x10, 0x10, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01
    };
    a->isdpAid = mkoctet(aid_a, sizeof aid_a);
    a->profileState = mklong(1); /* enabled */
    a->profileNickname = mkoctet((const uint8_t *)"My SIM", 6);
    a->serviceProviderName = mkoctet((const uint8_t *)"Test Telco", 10);
    a->profileName = mkoctet((const uint8_t *)"Test Telco Postpaid", 20);
    a->profileClass = mklong(2); /* operational */
    ASN_SEQUENCE_ADD(&resp.choice.profileInfoListOk.list, a);

    /* Profile B: only iccid and profileState -- every other field this
       project decodes is genuinely OPTIONAL in rsp-2.5.asn, and a real
       card is free to omit any of them. */
    ProfileInfo_t *b = calloc(1, sizeof *b);
    static const uint8_t iccid_b[10] = {
        0x89, 0x44, 0x05, 0x89, 0x25, 0x00, 0x98, 0x76, 0x54, 0x3F
    };
    b->iccid = mkoctet(iccid_b, sizeof iccid_b);
    b->profileState = mklong(0); /* disabled */
    ASN_SEQUENCE_ADD(&resp.choice.profileInfoListOk.list, b);

    uint8_t buf[1024];
    struct { uint8_t *p; size_t len; } o = { buf, 0 };
    asn_enc_rval_t r = der_encode(&asn_DEF_ProfileInfoListResponse, &resp, collect, &o);
    if (r.encoded < 0) { fprintf(stderr, "encode failed\n"); return 1; }

    printf("# ProfileInfoListResponse, %zu bytes\n", o.len);
    print_hex(o.p, o.len);

    ASN_STRUCT_RESET(asn_DEF_ProfileInfoListResponse, &resp);
    return 0;
}
```

Its output, spliced into `synthetic-profiles.log`'s one `BF2D00` response
line (ahead of the trailing ` 9000` the STORE DATA framing itself adds):

```
# ProfileInfoListResponse, 104 bytes
BF2D65A063E34F5A0A8944058925001234567F4F10A00000055910100000000000000000019F70010190064D792053494D910A546573742054656C636F9214546573742054656C636F20506F73747061696400950102E3105A0A8944058925009876543F9F700100
```

`tests/test_profiles.c` asserts every field of both entries against
exactly the bytes above, not merely that "a list came back."

## `omnikey-profiles-error.log`

A hand-edited copy of `omnikey-profiles.log`, its one STORE DATA response
changed from `profileInfoListOk` (`A0 00`, an empty `SEQUENCE OF`) to
`profileInfoListError` (`81 01 01` -- tag `81`, the IMPLICIT INTEGER
`ProfileInfoListError`, value 1, `incorrectInputValues`). A healthy
ISD-R has no reason to refuse an unrestricted `ProfileInfoListRequest`
("give me every profile"), so this is not a case real hardware can be
made to produce; it exists to prove `rsp_card_read_profiles` reports a
decoded error as -1 (a real refusal) rather than -2 (could not be asked)
or a false success, the one path `tests/test_profiles.c` cannot reach
any other way.

## `synthetic-profiles-bad-request.log`

A deliberately mutated copy of `synthetic-profiles.log`: one byte of the
STORE DATA request's data field changed from `BF2D00` to `BF2E00`.
`rsp_card_read_profiles` always sends the real bytes, so replaying this
file must refuse the exchange by name (`tests/test_profiles.c`'s
`test_wrong_request_is_refused`) rather than hand back an answer for a
request nobody actually sent -- replay is a pin on the wire, not a
lenient stub, the same property `tests/test_recording.c` already covers
in general and this asserts again against this round's own request.

## `synthetic-profiles-hostile-text.log`

One `ProfileInfo` whose card-chosen text carries every character a JSON
string cannot hold raw. `profileNickname`, `serviceProviderName` and
`profileName` are `UTF8String` in `rsp-2.5.asn`, and SGP.22 v2.6 section
5.7.15 has the eUICC return them verbatim -- the card picks their
content, this project does not. Every other recording in this directory
happens to hold nothing but plain ASCII letters and spaces, so without
this one a decoder that mangled anything unusual, or a formatter that
escaped nothing at all, would pass the entire suite.

Synthetic for the same reason `synthetic-profiles.log` is: this
project's test eUICC has no profiles installed, so there is no real card
to capture such a nickname from. Produced by the same throwaway
generator, with a different `main` -- only the `BF2D00` response is
synthetic, the SELECT ISD-R exchange above it is this card's own real
FCI.

| field | content | what it catches |
| --- | --- | --- |
| `profileNickname` | `He said "hi" \n is not a newline` + TAB + `0x01` | a quote, a backslash, a tab, and a C0 control with no short JSON escape of its own. The literal backslash-n catches a formatter that turns it into a real newline, or one that leaves it alone while the tab beside it needs escaping. |
| `serviceProviderName` | `Acme` + LF + `Telco` | an actual newline, which ends a JSON string early if it is not escaped |
| `profileName` | u-umlaut, eszett and two CJK characters | multi-byte UTF-8 needs no escaping and must come back unmangled; a formatter working one byte at a time corrupts it |

Two suites read this file, and they assert different things:

- `tests/test_profiles.c` (this repository) pins the decoded bytes
  themselves -- that `rsp_card_read_profiles` hands the card's text back
  exactly as it arrived, NUL-terminated at the right length.
- euicc-tools' `tests/run-tests` pins the escaping, against
  `euicc card profiles --json`. Escaping belongs to whoever formats the
  output, not to this library, which is why the proof is split.

The one `main` differs from `synthetic-profiles.log`'s in the fields it
sets; everything else (the helpers, the `der_encode` call, the compile
line) is unchanged:

```c
    ProfileInfo_t *a = calloc(1, sizeof *a);
    static const uint8_t iccid_a[10] = {
        0x89, 0x44, 0x05, 0x89, 0x25, 0x00, 0x11, 0x11, 0x11, 0x1F
    };
    a->iccid = mkoctet(iccid_a, sizeof iccid_a);
    a->profileState = mklong(1);

    static const uint8_t nick[] = {
        'H','e',' ','s','a','i','d',' ','"','h','i','"',
        ' ','\\','n',' ','i','s',' ','n','o','t',' ','a',' ','n','e','w',
        'l','i','n','e', 0x09, 0x01
    };
    a->profileNickname = mkoctet(nick, sizeof nick);

    static const uint8_t spn[] = { 'A','c','m','e', 0x0A, 'T','e','l','c','o' };
    a->serviceProviderName = mkoctet(spn, sizeof spn);

    static const uint8_t pname[] = {
        'G','r', 0xC3,0xBC, 0xC3,0x9F, 'e', ' ',
        0xE6,0x97,0xA5, 0xE6,0x9C,0xAC
    };
    a->profileName = mkoctet(pname, sizeof pname);
    a->profileClass = mklong(2);
    ASN_SEQUENCE_ADD(&resp.choice.profileInfoListOk.list, a);
```

It prints 90 bytes; the recording wraps them in the usual `61 5A` /
`GET RESPONSE` pair and appends `9000`.
