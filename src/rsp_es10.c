/*
 * rsp_es10.c -- one ES10 request driven to the ISD-R and the whole answer
 * collected back, chaining outward in blocks and inward through 61xx/GET
 * RESPONSE.
 *
 * SGP.22 v2.6 section 5.7.2 "Transport Command" states: "One generic APDU
 * is used on the interfaces ES10a, ES10b and ES10c to transport all command
 * request and command response data. All functions use the command message
 * STORE DATA as defined in GlobalPlatform Card Specification [8] with the
 * specific coding defined below" (Table 47):
 *
 *     CLA   '80'-'83' or 'C0'-'CF'   (GPCS [8] section 11.1.4)
 *     INS   'E2'                     STORE DATA
 *     P1    '11' or '91'             see Table 48
 *     P2    'xx'                     Block number
 *     Lc    Var.
 *     Data  the DER-encoded ES10 command/response data object
 *     Le    '00'
 *
 * Table 48 gives P1's bits: b8 is "More blocks/Last block" (0/1); the
 * fixed bits below it (b7b6='00' no general encryption info, b5b4='10'
 * BER-TLV data, b1='1' ISO case 4) are the same for every ES10 exchange,
 * so the two P1 values actually used are '11' (more blocks follow) and
 * '91' (this is the last block) -- exactly GPCS's own STORE DATA P1
 * table (section 11.11.2.1, Table 11-89) restricted to those two shapes.
 * P2 is "Block number"; GPCS section 11.11.2.2 pins the concrete rule
 * SGP.22 only names: "coded sequentially from '00' to 'FF'", reset at the
 * start of a session -- SGP.22 v2.6 section 2.5.5 says the same for a BPP
 * segment ("At the beginning of each segment the block number of the
 * STORE DATA commands SHALL be reset"). This code resets it to 0 for
 * every call, since one rsp_es10_send call is exactly one such session.
 *
 * The CLA byte's range leaves room for a logical channel number in its
 * low bits (GPCS section 11.1.4.1, Table 11-11: '80'-'83' is "GlobalPlatform
 * command, no secure messaging", channel 0-3 in b2b1); this library has no
 * notion of a logical channel, so it always uses channel 0, CLA '80'.
 *
 * The maximum block size is not restated in section 5.7.2 itself, but
 * SGP.22 v2.6 section 2.5.5 ("Segmented Bound Profile Package") and
 * section 5.7.6 (LoadBoundProfilePackage) both give it for the same STORE
 * DATA mechanism: "Each segment ... that is up to 255 bytes is transported
 * in one APDU. Larger TLVs are sent in blocks of 255 bytes for the first
 * blocks and a last block that MAY be shorter." This matches GPCS section
 * 11.1.5: "All GlobalPlatform APDU command messages (excluding the APDU
 * header) are limited to 255 bytes in length" -- an Lc that is one byte
 * wide, the short-APDU form Table 47 uses (Lc 'Var.', no extended length
 * anywhere in this clause).
 *
 * For the answer, section 5.7.2 continues: "if the size of the response is
 * bigger than 256 bytes, the chaining of the commands SHALL be done as
 * defined in ISO/IEC 7816-4 [14]. The responses SHALL be retrieved by the
 * Device using several GET RESPONSE commands" -- the same rule GPCS section
 * 11.1.5.2 "Response Chaining" states for any GlobalPlatform command:
 * "the chaining mechanism defined in [ISO 7816-4], using the '61xx' status
 * word and multiple GET RESPONSE commands, should be used." GET RESPONSE's
 * own encoding (CLA '00', INS 'C0', P1 '00', P2 '00', Le = the SW2 that
 * accompanied '61xx') is ISO/IEC 7816-4's, which neither SGP.22 nor GPCS
 * restates; this is the ordinary GET RESPONSE any ISO 7816-4 reader issues
 * after a '61xx' procedure byte.
 *
 * Section 5.7.2's "Processing State Returned in the Response Message"
 * gives the status words that end an exchange successfully: "A successful
 * execution of the APDU command SHALL be indicated by the status bytes
 * '90 00' if no proactive command is pending and by '91 XX' if a proactive
 * command (e.g., REFRESH) is pending." This function's contract (see
 * lpa.h) only treats a bare '90 00' as the terminal success and anything
 * that is not '90 00' or '61xx' as a refusal reported through *sw -- so a
 * '91 XX' (a real, spec-defined success that also signals a pending
 * proactive command) reads as a refusal here. That is narrower than
 * section 5.7.2 allows; deciding what to do about a pending proactive
 * command is left to whichever caller needs it, not this function.
 *
 * What an intermediate block's response must look like is section 5.7.6's,
 * not GPCS's: SGP.22 v2.6 section 5.7.6 (LoadBoundProfilePackage),
 * "Response Data": "The data presence in the response message depends on
 * the block status: For an intermediate block of data of a BPP TLV, the
 * response message SHALL not contain data field." (GPCS section 11.1.5.1
 * states a same-shaped rule for its own "more commands" chaining, but that
 * clause opens by naming exactly which commands it governs -- DELETE,
 * INSTALL and PUT KEY -- and STORE DATA is not one of them, so it is not
 * this rule's source.) A bare '90 00' is therefore the only response an
 * intermediate block may legitimately receive; a '90 00' that arrives
 * with a data field anyway is the card breaking that rule, not a status
 * this function's caller can reason about through *sw the way lpa.h
 * documents it (a genuine refusal status) -- so that case is reported as
 * -2, same as any other exchange that could not happen, not as -1 with
 * *sw holding the paradox of "refused, status 9000".
 *
 * The inward response-collection loop is bounded in both directions a
 * non-terminating chain could otherwise exploit: GPCS section 11.1.5
 * caps what one exchange can carry ("a maximum length of 256 bytes of
 * response data") and caps every other length field in the spec at a
 * 3-byte BER-TLV encoding ("3 bytes for a length up to 65535, except
 * where otherwise stated") -- so 65535 bytes total and, since reaching
 * that many bytes at 256 per round trip takes at most 256 round trips,
 * 256 GET RESPONSE round trips are the ceiling this function accepts
 * before refusing to keep chaining. Both bounds exist because a card (or
 * a hand-edited recording) that keeps answering '61xx' forever is the
 * same failure the brief warns about elsewhere -- "a card that simply
 * stops answering" -- wearing a different hat: a card that never stops
 * *promising* an answer hangs this function exactly as badly as one that
 * never answers at all, unless something here refuses to keep waiting.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "lpa.h"
#include "rsp_internal.h"

#include "EUICCInfo2.h"
#include "GetEuiccDataResponse.h"
#include "ProfileInfoListResponse.h"
#include "ProfileInfoListError.h"
#include "ProfileInfo.h"
#include "GetEuiccChallengeResponse.h"
#include "DeleteProfileResponse.h"

#define ES10_MAX_BLOCK 255u  /* SGP.22 v2.6 section 2.5.5 / 5.7.6 */

#define ES10_CLA     0x80u   /* GPCS section 11.1.4.1: channel 0, no SM */
#define ES10_INS     0xE2u   /* STORE DATA */
#define ES10_P1_MORE 0x11u   /* SGP.22 v2.6 section 5.7.2, Table 48 */
#define ES10_P1_LAST 0x91u

#define GETRESP_CLA 0x00u
#define GETRESP_INS 0xC0u    /* GET RESPONSE, ISO/IEC 7816-4 */

/* P2 (the block number) is one byte -- GPCS section 11.11.2.2 codes it
 * "sequentially from '00' to 'FF'" -- so a request needing more than 256
 * blocks has no representable P2 for its later blocks; refuse it outright
 * rather than silently wrapping block_no back to 0 and sending two blocks
 * under the same P2. */
#define ES10_MAX_BLOCKS 256u

/* Bounds on the inward response-collection loop (iso_collect_response,
 * below): GPCS section 11.1.5 caps one exchange's response data at 256
 * bytes and every other length field in the spec at a 3-byte BER-TLV
 * encoding, i.e. 65535 -- the largest total response that loop
 * accumulates before giving up. Reaching that many bytes at 256 per round
 * trip takes at most 256 GET RESPONSE calls, so more than that -- with or
 * without data arriving on each one -- is a chain that is not
 * terminating, not a legitimately large answer. Named CHAIN_ rather than
 * ES10_: this loop is shared with rsp_card_select_isdr's plain SELECT, not
 * exclusive to STORE DATA -- see iso_collect_response's own comment. */
#define CHAIN_MAX_RESPONSE 65535u
#define CHAIN_MAX_GETRESP  256u

/* The inward accumulator below used to be a fourth hand-rolled growable
 * buffer (started at 64, freed without wiping) alongside src/rsp_bpp.c's
 * two -- and had already drifted from them before anyone noticed. It is
 * now rsp_growbuf_t from rsp_internal.h: same growth, but zeroized on
 * free, which matters the day this accumulates a ProfileInstallationResult
 * instead of an EID or an EUICCInfo2 answer. See that header's own
 * top comment for the full account.
 *
 * Collects the full response to one APDU exchange that may be chained
 * through ISO/IEC 7816-4's '61xx'/GET RESPONSE mechanism (see the
 * top-of-file comment for the citations: SGP.22 v2.6 section 5.7.2 for an
 * ES10 STORE DATA response, GPCS section 11.1.5.2 restating the same rule
 * for any GlobalPlatform command, ISO/IEC 7816-4 itself for GET RESPONSE's
 * own encoding). This is the one piece rsp_es10_send's STORE DATA framing
 * and rsp_card_select_isdr's plain SELECT actually share: both send a
 * single APDU (the last STORE DATA block, or the SELECT itself) and then
 * face exactly the same inward chaining rule on whatever comes back. The
 * two callers' outward framing does not share anything to factor -- STORE
 * DATA's block splitting and SELECT's fixed AID payload are genuinely
 * different wire shapes -- so only this inward half is a single copy;
 * writing it twice would have been the "two implementations of one rule"
 * duplication this project's first half already had to unpick once.
 *
 * On entry, n is t->transceive's return value for the exchange the caller
 * already sent, and resp/resp_cap is the buffer that answer landed in --
 * the same buffer this function goes on reusing for every GET RESPONSE it
 * sends. Returns 0 with *out (malloc'ed, the caller's) and *out_len set to
 * the accumulated data with its status bytes stripped; -1 if the chain
 * ended in a real refusal (a status other than 9000/61xx, with *sw set to
 * it) or if the transport itself already said the card's answer was
 * unusable; -2 if the exchange could not happen at all, or the chain would
 * not terminate within CHAIN_MAX_RESPONSE/CHAIN_MAX_GETRESP.
 *
 * transceive's own -1/-2 is not re-decided here, it is passed straight
 * through: n < 0 is exactly what the transport already concluded (lpa.h's
 * struct comment on transceive), and re-deciding it as a flat -2 -- as
 * this used to do -- would erase the one distinction include/lpa.h
 * documents for this function's caller (-1 "the card said no" vs. -2 "we
 * could not ask"), the same distinction rsp_transport.c's three transceive
 * implementations were just made to agree on. Only a positive-but-short
 * answer (fewer than 2 bytes -- no room for a status word) is this
 * function's own call to make, and it reads as -1: an answer that arrived
 * and made no sense is "the card said no" in the same sense a bad status
 * word is, not "the exchange could not happen." */
static int iso_collect_response(rsp_transport_t *t, long n,
                                uint8_t *resp, size_t resp_cap,
                                uint8_t **out, size_t *out_len, unsigned *sw)
{
    rsp_growbuf_t acc = {0};
    unsigned getresp_count = 0;

    for (;;) {
        if (n < 0) {
            rsp_growbuf_free(&acc);
            return (int)n;
        }
        if (n < 2) {
            rsp_growbuf_free(&acc);
            return -1;
        }

        unsigned this_sw = (unsigned)((resp[(size_t)n - 2] << 8) |
                                      resp[(size_t)n - 1]);
        size_t data_len = (size_t)n - 2;

        if ((this_sw & 0xFF00u) == 0x6100u) {
            if (rsp_growbuf_append(&acc, resp, data_len) != 0) {
                rsp_growbuf_free(&acc);
                return -2;
            }
            if (acc.len > CHAIN_MAX_RESPONSE) {
                fprintf(stderr, "rsp_es10: response exceeds %u bytes, "
                                "refusing to keep chaining\n",
                        CHAIN_MAX_RESPONSE);
                rsp_growbuf_free(&acc);
                return -2;
            }
            if (++getresp_count > CHAIN_MAX_GETRESP) {
                fprintf(stderr, "rsp_es10: %u GET RESPONSE round trips "
                                "without the chain ending, refusing to "
                                "keep waiting\n", getresp_count - 1);
                rsp_growbuf_free(&acc);
                return -2;
            }
            uint8_t gr[5] = {
                (uint8_t)GETRESP_CLA, (uint8_t)GETRESP_INS,
                0x00, 0x00, (uint8_t)(this_sw & 0xFFu)
            };
            n = t->transceive(t, gr, sizeof gr, resp, resp_cap);
            continue;
        }

        if (this_sw == 0x9000u) {
            if (rsp_growbuf_append(&acc, resp, data_len) != 0) {
                rsp_growbuf_free(&acc);
                return -2;
            }
            *out = acc.buf;
            *out_len = acc.len;
            return 0;
        }

        rsp_growbuf_free(&acc);
        *sw = this_sw;
        return -1;
    }
}

int rsp_es10_send(rsp_transport_t *t, const uint8_t *req, size_t req_len,
                  uint8_t **out, size_t *out_len, unsigned *sw)
{
    if (!t || !t->transceive || !out || !out_len || !sw) return -2;

    *out = NULL;
    *out_len = 0;
    *sw = 0;

    /* A block count that would need a P2 past 'FF' has no way to be sent
       at all -- see ES10_MAX_BLOCKS's comment. */
    size_t needed_blocks = req_len ?
        (req_len + ES10_MAX_BLOCK - 1) / ES10_MAX_BLOCK : 1;
    if (needed_blocks > ES10_MAX_BLOCKS) return -2;

    uint8_t cmd[6 + ES10_MAX_BLOCK]; /* CLA,INS,P1,P2,Lc + up to 255 data + Le */
    uint8_t resp[258]; /* up to 256 bytes of data plus the two status bytes */

    size_t sent = 0;
    unsigned block_no = 0;

    for (;;) {
        size_t remain = req_len - sent;
        size_t chunk = remain > ES10_MAX_BLOCK ? ES10_MAX_BLOCK : remain;
        int last = (sent + chunk >= req_len);

        cmd[0] = (uint8_t)ES10_CLA;
        cmd[1] = (uint8_t)ES10_INS;
        cmd[2] = (uint8_t)(last ? ES10_P1_LAST : ES10_P1_MORE);
        cmd[3] = (uint8_t)(block_no & 0xFFu);
        cmd[4] = (uint8_t)chunk;
        if (chunk) memcpy(cmd + 5, req + sent, chunk);
        cmd[5 + chunk] = 0x00; /* Le */

        long n = t->transceive(t, cmd, 5 + chunk + 1, resp, sizeof resp);
        sent += chunk;
        block_no++;

        if (!last) {
            /* An intermediate block's response must not carry a data
             * field (SGP.22 v2.6 section 5.7.6, "Response Data": "For an
             * intermediate block of data of a BPP TLV, the response
             * message SHALL not contain data field") -- see the
             * top-of-file comment for why this is 5.7.6's rule, not
             * GPCS's. Nothing has been accumulated yet at this point (the
             * accumulator lives inside iso_collect_response, entered only
             * once the last block is sent below), so there is nothing to
             * free on any of these early returns.
             *
             * n < 0 is passed straight through, the same as
             * iso_collect_response does and for the same reason: it is
             * already transceive's own -1 ("the card answered something
             * unusable") or -2 ("the exchange could not happen"), not
             * something this function should re-decide as a flat -2. Only
             * a positive-but-short answer (no room for a status word) is
             * this function's own call, and it reads as -1 for the same
             * reason iso_collect_response's does. */
            if (n < 0) {
                return (int)n;
            }
            if (n < 2) {
                return -1;
            }
            unsigned isw = (unsigned)((resp[(size_t)n - 2] << 8) |
                                      resp[(size_t)n - 1]);
            if (isw != 0x9000u) {
                /* A real refusal, whatever bytes came with it. */
                *sw = isw;
                return -1;
            }
            if (n != 2) {
                /* The card said success but attached a data field
                 * anyway -- section 5.7.6 forbids that for an
                 * intermediate block, so this is the card breaking the
                 * protocol, not a status lpa.h's *sw contract can carry
                 * ("*sw set to that status" only applies to the -1 case,
                 * a genuine refusal). Reporting -1 with *sw = 0x9000
                 * would read as "refused, status: success", which the
                 * caller cannot reason about; -2 says the exchange did
                 * not go as an ES10 exchange can, same as any other
                 * case this function gives up on. */
                fprintf(stderr, "rsp_es10_send: intermediate block %u's "
                                "response carried %zu bytes of data; "
                                "section 5.7.6 forbids that\n",
                        block_no - 1, (size_t)n - 2);
                return -2;
            }
            continue;
        }

        /* The last block was just sent: collect the (possibly chained)
         * response that follows it -- the same inward chaining
         * rsp_card_select_isdr's plain SELECT also faces, so it is one
         * shared function rather than a second copy of this loop. */
        return iso_collect_response(t, n, resp, sizeof resp, out, out_len, sw);
    }
}

/*
 * rsp_card_select_isdr / rsp_card_read_info / rsp_card_info_free /
 * rsp_card_trusts -- the three read-only ES10 commands this round asks of a
 * card, plus the yes/no question the round exists to answer.
 *
 * The ISD-R AID below (A0 00 00 05 59 10 10 FF FF FF FF 89 00 00 01 00) is
 * the one the eUICC card-reading task brief gives; it must be selected
 * before any ES10 STORE DATA exchange, since ES10 commands are ISD-R
 * application commands, not commands the card answers on whatever applet
 * happened to be selected before. SELECT itself is plain ISO/IEC 7816-4
 * (CLA '00', INS 'A4', P1 '04' select-by-name, P2 '00' first-or-only
 * occurrence), not part of SGP.22 or GPCS's STORE DATA mechanism above, so
 * its outward framing does not go through rsp_es10_send.
 *
 * Its inward half is a different matter. Fix round 2, real hardware: this
 * project's own eUICC answers SELECT of the ISD-R with '61 21' -- ISO/IEC
 * 7816-4 response chaining, "33 more bytes are waiting", the card's FCI
 * carrying its AID and SGP.22 version back -- not a bare '9000'. The first
 * version of this function treated anything but an exact '9000' as a
 * refusal and never sent the GET RESPONSE that '61xx' asks for, so it
 * could not get past the very first exchange against a real card. That
 * chaining is exactly what iso_collect_response already implements for
 * rsp_es10_send's STORE DATA responses, so SELECT calls the same function
 * rather than a second, narrower copy of the same rule -- this project's
 * first half already had to unpick two implementations of one thing once.
 * SELECT's FCI data itself is not used by anything above and is freed
 * unread; only the chaining, and the final status word, matter here.
 */

#define ISDR_AID_LEN 16

static const uint8_t isdr_aid[ISDR_AID_LEN] = {
    0xA0, 0x00, 0x00, 0x05, 0x59, 0x10, 0x10, 0xFF,
    0xFF, 0xFF, 0xFF, 0x89, 0x00, 0x00, 0x01, 0x00
};

/* Select the ISD-R. Returns 0, -1 if the card refused (a non-9000,
   non-61xx status, whatever it carries -- there is no *sw out-parameter
   here since nothing above needs to distinguish one refusal from another
   for a SELECT), -2 if the exchange could not happen at all, including a
   chain that would not terminate within iso_collect_response's own
   bounds. */
static int rsp_card_select_isdr(rsp_transport_t *t)
{
    uint8_t cmd[5 + ISDR_AID_LEN + 1];
    uint8_t resp[258];

    cmd[0] = 0x00; /* CLA */
    cmd[1] = 0xA4; /* INS: SELECT */
    cmd[2] = 0x04; /* P1: select by name (DF name / AID) */
    cmd[3] = 0x00; /* P2: first or only occurrence, no FCI return requested */
    cmd[4] = (uint8_t)ISDR_AID_LEN; /* Lc */
    memcpy(cmd + 5, isdr_aid, ISDR_AID_LEN);
    cmd[5 + ISDR_AID_LEN] = 0x00; /* Le */

    long n = t->transceive(t, cmd, sizeof cmd, resp, sizeof resp);

    uint8_t *fci = NULL;
    size_t fci_len = 0;
    unsigned sw = 0;
    int rc = iso_collect_response(t, n, resp, sizeof resp, &fci, &fci_len, &sw);
    free(fci); /* the FCI template: unread, nothing above needs it */
    return rc;
}

/* Both requests are the fixed, argument-less encodings the brief gives
   directly from rsp-2.5.asn, so they are written out here rather than
   assembled through the generated encoder -- there is nothing for an
   encoder to get wrong about three and six constant bytes. */
static const uint8_t es10_info2_req[] = { 0xBF, 0x22, 0x00 };
static const uint8_t es10_eid_req[]   = { 0xBF, 0x3E, 0x03, 0x5C, 0x01, 0x5A };

int rsp_card_read_info(rsp_transport_t *t, rsp_card_info_t *out, int *no_isdr)
{
    if (no_isdr) *no_isdr = 0;
    if (!t || !t->transceive || !out) return -2;
    memset(out, 0, sizeof *out);

    int rc = rsp_card_select_isdr(t);
    if (rc != 0) {
        if (rc == -1 && no_isdr) *no_isdr = 1;
        return rc;
    }

    uint8_t *resp = NULL;
    size_t resp_len = 0;
    unsigned sw = 0;

    rc = rsp_es10_send(t, es10_info2_req, sizeof es10_info2_req,
                       &resp, &resp_len, &sw);
    if (rc != 0) return rc;

    EUICCInfo2_t *info2 = NULL;
    asn_dec_rval_t dr = ber_decode(NULL, &asn_DEF_EUICCInfo2, (void **)&info2,
                                   resp, resp_len);
    free(resp);
    if (dr.code != RC_OK) {
        if (info2) ASN_STRUCT_FREE(asn_DEF_EUICCInfo2, info2);
        return -2;
    }

    /* VersionType_constraint() (dist/VersionType.c) is the module's own
       SIZE(3) check on this field, and ber_decode never calls it -- the
       same gap src/rsp_bpp.c's own comment records for der_encode. So a
       3-byte svn is not guaranteed by "the decode succeeded"; it must be
       checked here, and treated the same as the non-uniform ci_ids list
       below: a card whose answer does not fit what this function returns
       is a case this function cannot make sense of (-2), not a success
       with an empty string standing in for a version nobody sent. */
    if (info2->svn.size != 3) {
        ASN_STRUCT_FREE(asn_DEF_EUICCInfo2, info2);
        return -2;
    }
    snprintf(out->svn, sizeof out->svn, "%u.%u.%u",
             info2->svn.buf[0], info2->svn.buf[1], info2->svn.buf[2]);

    /* uiccCapability. A BIT STRING carries its own count of unused
       trailing bits, so the declared length is 8 * size - bits_unused;
       that number matters, because a card claims nothing about the bits
       it did not send. Anything longer than uicc_capability holds is an
       answer this struct cannot represent, and gets the same -2 as the
       non-uniform ci_ids list below rather than a silent truncation --
       truncating would turn capabilities a future card does claim into
       capabilities it appears to lack, which is the one direction this
       field must never fail in. */
    {
        const BIT_STRING_t *cap = (const BIT_STRING_t *)&info2->uiccCapability;
        if (cap->size > sizeof out->uicc_capability ||
            (size_t)cap->bits_unused > 7 ||
            (cap->size == 0 && cap->bits_unused != 0)) {
            ASN_STRUCT_FREE(asn_DEF_EUICCInfo2, info2);
            return -2;
        }
        if (cap->buf && cap->size > 0) {
            memcpy(out->uicc_capability, cap->buf, cap->size);
            out->uicc_capability_bits =
                (size_t)cap->size * 8 - (size_t)cap->bits_unused;
            out->have_uicc_capability = 1;
        }
    }

    size_t n = (size_t)info2->euiccCiPKIdListForVerification.list.count;
    if (n > 0) {
        /* rsp_card_info_t's own contract (include/lpa.h) is a single
           ci_id_len for every entry in ci_ids; a card whose list is not
           actually uniform cannot be represented that way, so that shape
           is treated the same as any other answer this function cannot
           make sense of: -2, not a silent truncation to the entries that
           happen to fit. */
        size_t id_len = info2->euiccCiPKIdListForVerification.list.array[0]->size;

        /* n * id_len below cannot overflow in practice -- both come from
           one decoded response, and rsp_es10_send bounds how much data an
           exchange can accumulate (see its CHAIN_MAX_RESPONSE) -- but the
           multiplication's operands are not re-checked at the point of
           use, so guard it directly rather than trust a bound enforced
           two calls away. */
        if (id_len != 0 && n > SIZE_MAX / id_len) {
            ASN_STRUCT_FREE(asn_DEF_EUICCInfo2, info2);
            return -2;
        }
        size_t bytes = n * id_len;

        /* malloc(0) is not what "id_len == 0" should mean here: some
           implementations answer it with NULL, which the check below
           would then misreport as an allocation failure (-2, could not
           be asked) rather than "the card listed id_len == 0 issuers" (an
           odd but decodable answer). rsp_transport.c's parse_hexline
           guards the same malloc(0) case for the same reason. */
        uint8_t *ids = malloc(bytes ? bytes : 1);
        if (!ids) {
            ASN_STRUCT_FREE(asn_DEF_EUICCInfo2, info2);
            return -2;
        }
        int uniform = 1;
        for (size_t i = 0; i < n; i++) {
            SubjectKeyIdentifier_t *ski =
                info2->euiccCiPKIdListForVerification.list.array[i];
            if (ski->size != id_len) { uniform = 0; break; }
            /* ski->buf may be NULL when id_len is 0 (an empty OCTET
               STRING decodes that way); memcpy's arguments must be valid
               pointers even for a zero-length copy, so skip the call
               entirely rather than pass a NULL source. */
            if (id_len) memcpy(ids + i * id_len, ski->buf, id_len);
        }
        if (!uniform) {
            free(ids);
            ASN_STRUCT_FREE(asn_DEF_EUICCInfo2, info2);
            return -2;
        }
        out->ci_ids = ids;
        out->ci_count = n;
        out->ci_id_len = id_len;
    }

    ASN_STRUCT_FREE(asn_DEF_EUICCInfo2, info2);

    resp = NULL;
    resp_len = 0;
    sw = 0;
    rc = rsp_es10_send(t, es10_eid_req, sizeof es10_eid_req,
                       &resp, &resp_len, &sw);
    if (rc != 0) {
        free(out->ci_ids);
        out->ci_ids = NULL;
        out->ci_count = 0;
        out->ci_id_len = 0;
        return rc;
    }

    GetEuiccDataResponse_t *eidresp = NULL;
    dr = ber_decode(NULL, &asn_DEF_GetEuiccDataResponse, (void **)&eidresp,
                    resp, resp_len);
    free(resp);
    if (dr.code != RC_OK || eidresp->eidValue.size != 16) {
        if (eidresp) ASN_STRUCT_FREE(asn_DEF_GetEuiccDataResponse, eidresp);
        free(out->ci_ids);
        out->ci_ids = NULL;
        out->ci_count = 0;
        out->ci_id_len = 0;
        return -2;
    }

    memcpy(out->eid, eidresp->eidValue.buf, 16);
    out->have_eid = 1;
    ASN_STRUCT_FREE(asn_DEF_GetEuiccDataResponse, eidresp);

    return 0;
}

void rsp_card_info_free(rsp_card_info_t *i)
{
    if (!i) return;
    free(i->ci_ids);
    i->ci_ids = NULL;
    i->ci_count = 0;
    i->ci_id_len = 0;
    i->have_eid = 0;
}

int rsp_card_trusts(const rsp_card_info_t *i, const uint8_t *id, size_t id_len)
{
    if (!i || !id || id_len != i->ci_id_len) return 0;

    /* Plain memcmp, not mbedtls_ct_memcmp: both operands are public
       identifiers (a Certificate Issuer's SubjectKeyIdentifier -- the hash
       of a public key, not a secret), and this project's constant-time
       rule exists for comparisons where a timing side channel could leak
       something an attacker should not learn. Nothing compared here is
       secret, so there is nothing for a timing channel to leak. */
    for (size_t k = 0; k < i->ci_count; k++) {
        if (memcmp(i->ci_ids + k * i->ci_id_len, id, id_len) == 0) return 1;
    }
    return 0;
}

int rsp_card_supports(const rsp_card_info_t *i, unsigned bit)
{
    if (!i || !i->have_uicc_capability) return -1;
    /* Past what the card declared: a complete answer that does not claim
       this capability, not an unanswered question -- see lpa.h. */
    if ((size_t)bit >= i->uicc_capability_bits) return 0;
    /* BIT STRING numbering: bit 0 is the most significant bit of the
       first octet. */
    return (i->uicc_capability[bit / 8] >> (7 - (bit % 8))) & 1;
}

/*
 * rsp_card_read_profiles / rsp_card_profiles_free -- GetProfilesInfo
 * (ES10c, SGP.22 v2.6 section 5.7.15 -- 5.7.16 is EnableProfile, a write
 * command this round does not implement), the same shape as GetEUICCInfo2
 * above: one fixed, argument-less request (every ProfileInfoListRequest
 * member is OPTIONAL, and an absent searchCriteria means "every
 * profile"), one CHOICE response to decode.
 *
 * The CHOICE is what makes this different from rsp_card_read_info's
 * EUICCInfo2, which has no error variant of its own: ProfileInfoListResponse
 * can carry profileInfoListError instead of the list, a genuine "the card
 * said no" that this function reports as -1 (with *err set), not -2 --
 * the request reached the ISD-R and was answered, the answer just was not
 * the list asked for.
 */

static const uint8_t es10_profile_list_req[] = { 0xBF, 0x2D, 0x00 };

/* NUL-terminates a UTF8String_t/OCTET_STRING_t's bytes into a fresh
   malloc'ed buffer. Returns NULL on allocation failure, the same
   convention every other caller in this file uses for "could not be
   asked" rather than "the field held nothing" (an empty string, size 0,
   still returns a valid one-byte "\0" buffer, distinct from NULL). */
static char *dup_utf8string(const OCTET_STRING_t *s)
{
    char *p = malloc(s->size + 1);
    if (!p) return NULL;
    if (s->size) memcpy(p, s->buf, s->size);
    p[s->size] = '\0';
    return p;
}

/* Fills one rsp_profile_info_t from one decoded ProfileInfo. Returns 0,
   or -1 if src carries something dst has no way to represent (an iccid
   whose length is not exactly 10, an isdpAid of length 0 or more than 16
   -- both violate OctetTo16's own SIZE(1..16), so a card sending one is
   itself the malformed answer, not a gap in this function) or an
   allocation failed partway through. Either way, dst is left in a state
   rsp_card_profiles_free(dst, 1) can safely release: every string
   pointer is either a completed allocation or still NULL. */
static int fill_profile_info(rsp_profile_info_t *dst, const ProfileInfo_t *src)
{
    memset(dst, 0, sizeof *dst);

    if (src->iccid) {
        if (src->iccid->size != sizeof dst->iccid) return -1;
        memcpy(dst->iccid, src->iccid->buf, sizeof dst->iccid);
        dst->have_iccid = 1;
    }
    if (src->isdpAid) {
        if (src->isdpAid->size == 0 || src->isdpAid->size > sizeof dst->isdp_aid) {
            return -1;
        }
        memcpy(dst->isdp_aid, src->isdpAid->buf, src->isdpAid->size);
        dst->isdp_aid_len = (size_t)src->isdpAid->size;
        dst->have_isdp_aid = 1;
    }
    /* A dereference until euicc-rsp's codec started being generated with
       -fwide-types (see that project's Makefile for why it has to be): an
       unconstrained INTEGER is an INTEGER_t now, not a long, so the value
       comes out through asn_INTEGER2long. A refusal is a value that does
       not fit a long, which is one more thing "dst has no way to
       represent" -- the -1 this function's own comment already describes,
       not a new outcome. */
    if (src->profileState) {
        if (asn_INTEGER2long(src->profileState, &dst->profile_state) != 0) {
            return -1;
        }
        dst->have_profile_state = 1;
    }
    if (src->profileNickname) {
        dst->profile_nickname = dup_utf8string(src->profileNickname);
        if (!dst->profile_nickname) return -1;
    }
    if (src->serviceProviderName) {
        dst->service_provider_name = dup_utf8string(src->serviceProviderName);
        if (!dst->service_provider_name) return -1;
    }
    if (src->profileName) {
        dst->profile_name = dup_utf8string(src->profileName);
        if (!dst->profile_name) return -1;
    }
    if (src->profileClass) {
        if (asn_INTEGER2long(src->profileClass, &dst->profile_class) != 0) {
            return -1;
        }
        dst->have_profile_class = 1;
    }
    return 0;
}

int rsp_card_read_profiles(rsp_transport_t *t, rsp_profile_info_t **out,
                            size_t *out_count, long *err, int *no_isdr)
{
    if (no_isdr) *no_isdr = 0;
    if (err) *err = 0;
    if (!t || !t->transceive || !out || !out_count) return -2;
    *out = NULL;
    *out_count = 0;

    int rc = rsp_card_select_isdr(t);
    if (rc != 0) {
        if (rc == -1 && no_isdr) *no_isdr = 1;
        return rc;
    }

    uint8_t *resp = NULL;
    size_t resp_len = 0;
    unsigned sw = 0;
    rc = rsp_es10_send(t, es10_profile_list_req, sizeof es10_profile_list_req,
                       &resp, &resp_len, &sw);
    if (rc != 0) return rc;

    ProfileInfoListResponse_t *pl = NULL;
    asn_dec_rval_t dr = ber_decode(NULL, &asn_DEF_ProfileInfoListResponse,
                                   (void **)&pl, resp, resp_len);
    free(resp);
    if (dr.code != RC_OK || !pl) {
        if (pl) ASN_STRUCT_FREE(asn_DEF_ProfileInfoListResponse, pl);
        return -2;
    }

    if (pl->present == ProfileInfoListResponse_PR_profileInfoListError) {
        /* An INTEGER_t since euicc-rsp's codec started being generated
           with -fwide-types; a refusal to fit a long means the eUICC's
           own error code is one this function cannot report, which is
           "could not make sense of the answer" (-2), not the eUICC
           answering "no" (-1) with a code the caller could act on. */
        long code = 0;
        int fit = asn_INTEGER2long(&pl->choice.profileInfoListError, &code);
        if (fit == 0 && err) *err = code;
        ASN_STRUCT_FREE(asn_DEF_ProfileInfoListResponse, pl);
        return fit == 0 ? -1 : -2;
    }

    if (pl->present != ProfileInfoListResponse_PR_profileInfoListOk) {
        /* Neither branch of the CHOICE: an extension this module does not
           name, or a decode that left `present` at _PR_NOTHING. Either way
           this function has nothing to report a list or an error from. */
        ASN_STRUCT_FREE(asn_DEF_ProfileInfoListResponse, pl);
        return -2;
    }

    size_t n = (size_t)pl->choice.profileInfoListOk.list.count;
    rsp_profile_info_t *arr = NULL;
    if (n > 0) {
        arr = calloc(n, sizeof *arr);
        if (!arr) {
            ASN_STRUCT_FREE(asn_DEF_ProfileInfoListResponse, pl);
            return -2;
        }
        for (size_t k = 0; k < n; k++) {
            ProfileInfo_t *pi = pl->choice.profileInfoListOk.list.array[k];
            if (fill_profile_info(&arr[k], pi) != 0) {
                rsp_card_profiles_free(arr, k + 1);
                ASN_STRUCT_FREE(asn_DEF_ProfileInfoListResponse, pl);
                return -2;
            }
        }
    }

    ASN_STRUCT_FREE(asn_DEF_ProfileInfoListResponse, pl);
    *out = arr;
    *out_count = n;
    return 0;
}

void rsp_card_profiles_free(rsp_profile_info_t *profiles, size_t count)
{
    if (!profiles) return;
    for (size_t k = 0; k < count; k++) {
        free(profiles[k].profile_nickname);
        free(profiles[k].service_provider_name);
        free(profiles[k].profile_name);
    }
    free(profiles);
}

/*
 * rsp_card_get_challenge -- ES10b GetEUICCChallenge, SGP.22 v2.6 section
 * 5.7.7. GetEuiccChallengeRequest is an empty SEQUENCE, so the request is
 * three constant bytes and there is nothing for an encoder to get wrong.
 * The response is one Octet16, which the eUICC generated at random and
 * will sign later; this function only carries it back.
 */

static const uint8_t es10_challenge_req[] = { 0xBF, 0x2E, 0x00 };

int rsp_card_get_challenge(rsp_transport_t *t, uint8_t out[16], int *no_isdr)
{
    if (no_isdr) *no_isdr = 0;
    if (!t || !t->transceive || !out) return -2;

    int rc = rsp_card_select_isdr(t);
    if (rc != 0) {
        if (rc == -1 && no_isdr) *no_isdr = 1;
        return rc;
    }

    uint8_t *resp = NULL;
    size_t resp_len = 0;
    unsigned sw = 0;
    rc = rsp_es10_send(t, es10_challenge_req, sizeof es10_challenge_req,
                       &resp, &resp_len, &sw);
    if (rc != 0) return rc;

    GetEuiccChallengeResponse_t *r = NULL;
    asn_dec_rval_t dr = ber_decode(NULL, &asn_DEF_GetEuiccChallengeResponse,
                                   (void **)&r, resp, resp_len);
    free(resp);
    if (dr.code != RC_OK || !r) {
        if (r) ASN_STRUCT_FREE(asn_DEF_GetEuiccChallengeResponse, r);
        return -2;
    }

    /* Octet16 is SIZE(16), but ber_decode does not enforce SIZE
       constraints (see this file's own note on EUICCInfo2's svn), so the
       length is checked here rather than assumed. A short challenge that
       silently left the rest of out uninitialised would be signed by the
       card and rejected by nothing until much later. */
    if (r->euiccChallenge.size != 16) {
        ASN_STRUCT_FREE(asn_DEF_GetEuiccChallengeResponse, r);
        return -2;
    }
    memcpy(out, r->euiccChallenge.buf, 16);
    ASN_STRUCT_FREE(asn_DEF_GetEuiccChallengeResponse, r);
    return 0;
}

/*
 * rsp_card_delete_profile -- ES10c DeleteProfile, SGP.22 v2.6 section
 * 5.7.18. DeleteProfileRequest is a CHOICE of isdpAid or iccid; this
 * always sends the iccid alternative, since that is what a person types
 * and what `euicc card profiles` prints. The response carries a single
 * INTEGER, and the difference between its values is the whole point --
 * "not found" and "still enabled" send a reader to entirely different
 * places, so the caller gets the value rather than a flattened failure.
 */

int rsp_card_delete_profile(rsp_transport_t *t, const uint8_t iccid[10],
                            long *result, int *no_isdr)
{
    if (no_isdr) *no_isdr = 0;
    if (result) *result = 0;
    if (!t || !t->transceive || !iccid) return -2;

    int rc = rsp_card_select_isdr(t);
    if (rc != 0) {
        if (rc == -1 && no_isdr) *no_isdr = 1;
        return rc;
    }

    /* BF 33 0C 5A 0A <10 bytes>: the [51] CHOICE wrapper, then Iccid's own
       APPLICATION 26 tag '5A' and its ten octets. Written out rather than
       assembled through the generated encoder for the same reason the two
       fixed requests above are -- there is nothing an encoder could get
       right that fifteen constant-shaped bytes get wrong. */
    uint8_t req[15];
    req[0] = 0xBF; req[1] = 0x33; req[2] = 0x0C;
    req[3] = 0x5A; req[4] = 0x0A;
    memcpy(req + 5, iccid, 10);

    uint8_t *resp = NULL;
    size_t resp_len = 0;
    unsigned sw = 0;
    rc = rsp_es10_send(t, req, sizeof req, &resp, &resp_len, &sw);
    if (rc != 0) return rc;

    DeleteProfileResponse_t *r = NULL;
    asn_dec_rval_t dr = ber_decode(NULL, &asn_DEF_DeleteProfileResponse,
                                   (void **)&r, resp, resp_len);
    free(resp);
    if (dr.code != RC_OK || !r) {
        if (r) ASN_STRUCT_FREE(asn_DEF_DeleteProfileResponse, r);
        return -2;
    }

    /* An INTEGER_t since euicc-rsp's codec started being generated with
       -fwide-types; a result that does not fit a long is an answer this
       function cannot decode, which is its own -2. */
    long v = 0;
    int fit = asn_INTEGER2long(&r->deleteResult, &v);
    ASN_STRUCT_FREE(asn_DEF_DeleteProfileResponse, r);

    if (fit != 0) return -2;
    if (v == 0) return 0;
    if (result) *result = v;
    return -1;
}

/*
 * The three ES10b exchanges whose request this library does not build.
 *
 * AuthenticateServer (SGP.22 v2.6 section 5.7.13) and PrepareDownload
 * (section 5.7.5) both carry a structure the SM-DP+ produced and signed --
 * ServerSigned1 with its signature and certificate, SmdpSigned2 with
 * hers. The LPA's job is to carry them to the card and carry the answer
 * back, not to understand them: it cannot check those signatures (it has
 * no key to check them against) and it must not alter a byte, because
 * the card verifies exactly what was signed. So these two take the
 * encoded request as given and hand back the encoded response.
 *
 * That is also why they have no *no_isdr out-parameter of their own
 * beyond the shared one: by the time either is called the ISD-R has
 * already answered a challenge, so a refusal here is about the exchange,
 * not about finding the applet.
 */

static int es10_passthrough(rsp_transport_t *t,
                             const uint8_t *req, size_t req_len,
                             uint8_t **out, size_t *out_len, int *no_isdr)
{
    if (no_isdr) *no_isdr = 0;
    if (!t || !t->transceive || !req || req_len == 0 || !out || !out_len) {
        return -2;
    }
    *out = NULL;
    *out_len = 0;

    int rc = rsp_card_select_isdr(t);
    if (rc != 0) {
        if (rc == -1 && no_isdr) *no_isdr = 1;
        return rc;
    }

    unsigned sw = 0;
    return rsp_es10_send(t, req, req_len, out, out_len, &sw);
}

int rsp_card_authenticate_server(rsp_transport_t *t,
                                  const uint8_t *req, size_t req_len,
                                  uint8_t **out, size_t *out_len,
                                  int *no_isdr)
{
    return es10_passthrough(t, req, req_len, out, out_len, no_isdr);
}

int rsp_card_prepare_download(rsp_transport_t *t,
                               const uint8_t *req, size_t req_len,
                               uint8_t **out, size_t *out_len,
                               int *no_isdr)
{
    return es10_passthrough(t, req, req_len, out, out_len, no_isdr);
}

/*
 * rsp_card_get_info1 -- ES10b GetEUICCInfo (SGP.22 v2.6 section 5.7.8),
 * the euiccInfo1 half. GetEuiccInfo1Request is an empty SEQUENCE, so the
 * request is three constant bytes.
 *
 * The response is handed back encoded rather than decoded, because its
 * only consumer is InitiateAuthentication, which needs the bytes as the
 * card sent them: euiccInfo1 goes into what the SM-DP+ signs, and a
 * decode-then-re-encode round trip is exactly the kind of thing that
 * changes a byte and breaks a signature for no visible reason.
 */

static const uint8_t es10_info1_req[] = { 0xBF, 0x20, 0x00 };

int rsp_card_get_info1(rsp_transport_t *t, uint8_t **out, size_t *out_len,
                       int *no_isdr)
{
    return es10_passthrough(t, es10_info1_req, sizeof es10_info1_req,
                            out, out_len, no_isdr);
}

/*
 * rsp_card_cancel_session -- ES10b CancelSession, SGP.22 v2.6 section
 * 5.7.14. This is the way out of a failed install: section 5.5.1 has the
 * eUICC reject InitialiseSecureChannel while an RSP session is already
 * ongoing, so without this one botched attempt blocks every later one.
 * CancelSessionReason has loadBppExecutionError(5) for exactly that case.
 *
 * The eUICC verifies that the transactionId is the one it is holding and
 * answers invalidTransactionId otherwise, which is why this cannot clear
 * a session stranded by a crash: a fresh run does not know the id. That
 * limit is real and belongs in whatever documents the command.
 */

int rsp_card_cancel_session(rsp_transport_t *t,
                             const uint8_t transaction_id[16], long reason,
                             int *no_isdr)
{
    if (no_isdr) *no_isdr = 0;
    if (!t || !t->transceive || !transaction_id) return -2;
    if (reason < 0 || reason > 127) return -2;

    /* BF 41 15 80 10 <16 bytes> 81 01 <reason>: the [65] SEQUENCE, then
       transactionId and reason under AUTOMATIC TAGS' [0] and [1]. */
    uint8_t req[24];
    req[0] = 0xBF; req[1] = 0x41; req[2] = 0x15;
    req[3] = 0x80; req[4] = 0x10;
    memcpy(req + 5, transaction_id, 16);
    req[21] = 0x81; req[22] = 0x01; req[23] = (uint8_t)reason;

    uint8_t *resp = NULL;
    size_t resp_len = 0;
    int rc = es10_passthrough(t, req, sizeof req, &resp, &resp_len, no_isdr);
    /* The response carries a signed structure the SM-DP+ would want in a
       real cancellation flow; this round only needs the session gone, so
       it is freed unread -- the same way rsp_card_select_isdr discards a
       SELECT's FCI. Whoever adds ES9+.CancelSession will want it. */
    free(resp);
    return rc;
}

/*
 * rsp_card_load_bpp -- ES10b LoadBoundProfilePackage, SGP.22 v2.6
 * section 5.7.6, with the segmentation section 2.5.5 requires.
 *
 * This is not "send the BPP in 255-byte chunks". Section 2.5.5 lists the
 * segments by name, and they follow the package's own TLV structure:
 *
 *     the BoundProfilePackage tag and length, plus the whole
 *       initialiseSecureChannelRequest TLV
 *     the firstSequenceOf87 tag and length, plus the first '87' TLV
 *     the sequenceOf88 tag and length
 *     each '88' TLV, one segment each
 *     the secondSequenceOf87 tag and length, plus the first '87' TLV
 *     the sequenceOf86 tag and length
 *     each '86' TLV, one segment each
 *
 * A segment of 255 bytes or less goes in one APDU; a larger one is split
 * into 255-byte blocks with a possibly-shorter last one. And the rule
 * that is easiest to miss and impossible to diagnose from the card's
 * answer: "At the beginning of each segment the block number of the
 * STORE DATA commands SHALL be reset." So P2 counts within a segment,
 * not across the package -- which is why rsp_es10_send, whose counter
 * runs the length of one request, cannot be reused here.
 *
 * P1 marks the last block of each segment, not only the last block of
 * the package: section 5.7.6 has an intermediate block answer without a
 * data field, and the last block of a BPP TLV answer with a Profile
 * Installation Result "present or absent as specified in section 2.5.6".
 * In practice the result arrives after the final '86'; this function
 * accumulates whatever data any block returns and hands back the last
 * non-empty answer, which is that result.
 *
 * Returns 0 with *out carrying the ProfileInstallationResult (malloc'ed,
 * the caller's) -- note that 0 means the card took the package and had
 * something to say about it, not that the install succeeded: the result
 * itself carries that, and the caller must decode it. -1 when the card
 * refused a block outright with a status word. -2 when the exchange
 * could not happen, or the BPP's own structure could not be walked.
 */

/* One BER header: the tag (one or two bytes here -- BF36 and BF23 are the
   only two-byte tags a BPP carries) and its length octets. Returns the
   header's own size and sets *val_len, or 0 if it does not parse within
   n. Only the definite forms a BPP uses are accepted; an indefinite
   length (0x80) is refused rather than guessed at. */
static size_t bpp_header(const uint8_t *p, size_t n, size_t *val_len)
{
    size_t i = 0;
    if (n < 2) return 0;

    /* A tag whose low five bits are all set continues into a second
       byte. BF36 and BF23 are exactly that shape; everything else in a
       BPP ('87', '88', '86', 'A0'..'A3') is one byte. */
    if ((p[0] & 0x1F) == 0x1F) {
        i = 2;
        if (n < 3) return 0;
    } else {
        i = 1;
    }

    uint8_t l = p[i];
    if (l < 0x80) {
        *val_len = l;
        return i + 1;
    }
    if (l == 0x80) return 0;  /* indefinite: not a DER BPP */
    size_t nl = l & 0x7Fu;
    if (nl > 4 || i + 1 + nl > n) return 0;
    size_t v = 0;
    for (size_t k = 0; k < nl; k++) v = (v << 8) | p[i + 1 + k];
    *val_len = v;
    return i + 1 + nl;
}

/* Send one segment: blocks of at most 255 bytes, P2 counting from zero
   for THIS segment (section 2.5.5's reset rule), P1 marking the segment's
   own last block. Any data the card returns is appended to acc, so the
   Profile Installation Result the final segment produces is what a caller
   ends up with. Returns 0, -1 or -2 on this file's usual convention. */
static int bpp_send_segment(rsp_transport_t *t, const uint8_t *seg,
                             size_t seg_len, rsp_growbuf_t *acc)
{
    uint8_t cmd[6 + ES10_MAX_BLOCK];
    uint8_t resp[258];
    size_t sent = 0;
    unsigned block_no = 0;

    if (seg_len == 0) return -2;

    for (;;) {
        size_t remain = seg_len - sent;
        size_t chunk = remain > ES10_MAX_BLOCK ? ES10_MAX_BLOCK : remain;
        int last = (sent + chunk >= seg_len);

        if (block_no > 0xFFu) return -2;

        cmd[0] = (uint8_t)ES10_CLA;
        cmd[1] = (uint8_t)ES10_INS;
        cmd[2] = (uint8_t)(last ? ES10_P1_LAST : ES10_P1_MORE);
        cmd[3] = (uint8_t)block_no;
        cmd[4] = (uint8_t)chunk;
        memcpy(cmd + 5, seg + sent, chunk);
        cmd[5 + chunk] = 0x00;

        long n = t->transceive(t, cmd, 5 + chunk + 1, resp, sizeof resp);
        sent += chunk;
        block_no++;

        if (n < 0) return (int)n;
        if (n < 2) return -1;

        unsigned sw = ((unsigned)resp[n - 2] << 8) | resp[n - 1];
        if (sw != 0x9000u && (sw & 0xFF00u) != 0x6100u) return -1;

        /* 61xx: the card has more to say. Collect it the same way every
           other ES10 answer in this file is collected. */
        if ((sw & 0xFF00u) == 0x6100u) {
            uint8_t *chained = NULL;
            size_t chained_len = 0;
            unsigned csw = 0;
            int rc = iso_collect_response(t, n, resp, sizeof resp,
                                          &chained, &chained_len, &csw);
            if (rc != 0) return rc;
            if (chained_len &&
                rsp_growbuf_append(acc, chained, chained_len) != 0) {
                free(chained);
                return -2;
            }
            free(chained);
        } else if ((size_t)n > 2) {
            if (rsp_growbuf_append(acc, resp, (size_t)n - 2) != 0) return -2;
        }

        if (last) return 0;
    }
}

int rsp_card_load_bpp(rsp_transport_t *t, const uint8_t *bpp, size_t bpp_len,
                      uint8_t **out, size_t *out_len, int *no_isdr)
{
    if (no_isdr) *no_isdr = 0;
    if (!t || !t->transceive || !bpp || !out || !out_len) return -2;
    *out = NULL;
    *out_len = 0;

    int rc = rsp_card_select_isdr(t);
    if (rc != 0) {
        if (rc == -1 && no_isdr) *no_isdr = 1;
        return rc;
    }

    /* Walk the package once, sending as we go. Every offset below is
       checked against bpp_len before it is used: a BPP whose own lengths
       do not agree with its size is refused (-2), not read past. */
    size_t outer_val = 0;
    size_t outer_hdr = bpp_header(bpp, bpp_len, &outer_val);
    if (outer_hdr == 0 || outer_hdr + outer_val > bpp_len) return -2;

    size_t pos = outer_hdr;
    const size_t end = outer_hdr + outer_val;

    rsp_growbuf_t acc = {0};

    /* Segment 1: the outer header plus the whole ISC request. */
    {
        size_t isc_val = 0;
        size_t isc_hdr = bpp_header(bpp + pos, end - pos, &isc_val);
        if (isc_hdr == 0 || pos + isc_hdr + isc_val > end) return -2;
        size_t seg_len = outer_hdr + isc_hdr + isc_val;
        rc = bpp_send_segment(t, bpp, seg_len, &acc);
        if (rc != 0) goto fail;
        pos += isc_hdr + isc_val;
    }

    /* The four SEQUENCE OF wrappers, in the order section 2.5.4 fixes
       them: A0, A1, A2 (optional), A3. For A0 and A2 the wrapper header
       travels with the first element; for A1 and A3 it travels alone. */
    while (pos < end) {
        size_t w_val = 0;
        size_t w_hdr = bpp_header(bpp + pos, end - pos, &w_val);
        if (w_hdr == 0 || pos + w_hdr + w_val > end) { rc = -2; goto fail; }

        uint8_t wrapper = bpp[pos];
        int header_rides_with_first = (wrapper == 0xA0 || wrapper == 0xA2);

        size_t inner = pos + w_hdr;
        const size_t inner_end = inner + w_val;
        int first = 1;

        if (!header_rides_with_first) {
            rc = bpp_send_segment(t, bpp + pos, w_hdr, &acc);
            if (rc != 0) goto fail;
        }

        while (inner < inner_end) {
            size_t e_val = 0;
            size_t e_hdr = bpp_header(bpp + inner, inner_end - inner, &e_val);
            if (e_hdr == 0 || inner + e_hdr + e_val > inner_end) {
                rc = -2; goto fail;
            }
            if (first && header_rides_with_first) {
                rc = bpp_send_segment(t, bpp + pos, w_hdr + e_hdr + e_val,
                                      &acc);
            } else {
                rc = bpp_send_segment(t, bpp + inner, e_hdr + e_val, &acc);
            }
            if (rc != 0) goto fail;
            inner += e_hdr + e_val;
            first = 0;
        }

        pos = inner_end;
    }

    *out = acc.buf;
    *out_len = acc.len;
    return 0;

fail:
    rsp_growbuf_free(&acc);
    return rc;
}
