/*
 * lpa_install.c -- the nine-step exchange that installs a profile.
 *
 * This is the LPA's actual job. Neither side of the conversation can
 * run it: the SM-DP+ never touches the card, and the card never reaches
 * the server. Something has to sit between them and carry each answer to
 * the other in the right order, which is what SGP.22 calls the LPAd and
 * what this file is.
 *
 * The order is not a matter of taste. It follows the data:
 *
 *   1  card    GetEUICCInfo        5.7.8   euiccInfo1
 *   2  card    GetEUICCChallenge   5.7.7   sixteen random bytes
 *   3  server  InitiateAuthentication 5.6.1  transactionId, serverSigned1
 *   4  card    AuthenticateServer  5.7.13  euiccSigned1, CERT.EUICC
 *   5  server  AuthenticateClient  5.6.3   smdpSigned2, CERT.DPpb
 *   6  card    PrepareDownload     5.7.5   otPK.EUICC.ECKA
 *   7  server  GetBoundProfilePackage 5.6.2  the BPP
 *   8  card    LoadBoundProfilePackage 5.7.6  ProfileInstallationResult
 *   9  local   verify euiccSignPIR    2.5.6   is that report the card's?
 *
 * Step 9 talks to nobody. It is here because step 8's answer is a claim
 * about what the card did, signed by the card, and believing it unchecked
 * would make every outcome above only as trustworthy as the last message
 * -- which arrives over the same unauthenticated transport as everything
 * else.
 *
 * Step 6 is the hinge. The session keys come from ECDH between the
 * server's one-time key and otPK.EUICC.ECKA, and the card does not
 * produce that key until then -- so nothing cryptographic about the BPP
 * can exist before step 7. That is why the four placeholders in
 * InitialiseSecureChannelRequest could not be filled in before this
 * exchange existed: they are its outputs, not its inputs.
 *
 * The ES9+ boundary here is a data boundary, not a network one. Steps 3,
 * 5 and 7 are direct calls into euicc-rsp, and every one of them takes
 * and returns DER exactly as SGP.22 defines it. Section 6.5 binds ES9+
 * as JSON over HTTPS with base64 ASN.1 inside; that envelope is the one
 * layer left out, and adding it later changes nothing here.
 *
 * On any failure from step 3 onward the card is holding an open RSP
 * session, and section 5.5.1 has it reject the next
 * InitialiseSecureChannel while one is ongoing. So this cancels before
 * returning -- otherwise one failed attempt blocks every later one and
 * the only way back is re-seating the card.
 */
#include <stdlib.h>
#include <string.h>

#include "lpa.h"
#include "rsp.h"
#include "rsp_internal.h"
#include "InitiateAuthenticationOkEs9.h"
#include "AuthenticateServerRequest.h"
#include "AuthenticateClientResponseEs9.h"
#include "PrepareDownloadRequest.h"
#include "mbedtls/platform_util.h"

/* Frees everything the flow allocates. Written once rather than at each
   of the seven early returns, because seven copies of a cleanup list is
   how one of them ends up missing an entry. */
struct install_scratch {
    uint8_t *info1;
    uint8_t *auth_req;
    uint8_t *auth_resp;
    uint8_t *prep_req;
    uint8_t *prep_resp;
    uint8_t *bpp;
    size_t   bpp_len;
};

static void scratch_free(struct install_scratch *g)
{
    free(g->info1);
    free(g->auth_req);
    free(g->auth_resp);
    free(g->prep_req);
    free(g->prep_resp);
    /* The BPP is the one piece here that carries the profile under the
       session keys. rsp_bpp_build's own caller-obligation note applies:
       wipe rather than merely free. */
    if (g->bpp) mbedtls_platform_zeroize(g->bpp, g->bpp_len);
    free(g->bpp);
    memset(g, 0, sizeof *g);
}


/* Steps 3 and 4 do not speak the same language, and this is where that
   gets fixed. rsp_dp_initiate_authentication answers with an
   InitiateAuthenticationOkEs9 -- the ES9+ *response*. The card expects an
   AuthenticateServerRequest, tag 'BF38' -- the ES10b *request*. Four of
   the five fields are the same and carry the tags AuthenticateServerRequest
   defines for them already (Table 36, NOTE 1), so they move across
   untouched: they are part of what the SM-DP+ signed, and re-deriving any
   of them would break a signature the card is about to check.

   What changes is the two ends. transactionId is dropped -- the card
   already learned it from the session. ctxParams1 is added, and it is the
   LPA's own contribution: nothing in the ES9+ answer can supply it.

   Its content here is deliberately minimal. matchingId and imei are
   OPTIONAL and left out; imei especially, since an invented one in a
   public repository is a number somebody could later mistake for real.
   deviceCapabilities is an empty SEQUENCE and tac is an obviously fake
   constant, because this is a build tool and not a handset: the eUICC
   does not judge these values, it signs them into euiccSigned1 for an
   SM-DP+ to read, and here that SM-DP+ is us. If a card ever does refuse
   over them, that refusal is the evidence that would justify making them
   configurable -- guessing at it beforehand would be designing for a
   requirement nobody has shown. */
/* der_encode wants a callback; rsp_growbuf_t wants an append. */
static int growbuf_sink(const void *buf, size_t n, void *key)
{
    return rsp_growbuf_append((rsp_growbuf_t *)key, buf, n);
}

int rsp_lpa_repack_authenticate_server(const uint8_t *es9, size_t es9_len,
                                       uint8_t **out, size_t *out_len)
{
    InitiateAuthenticationOkEs9_t *in = NULL;
    AuthenticateServerRequest_t req;
    static const uint8_t fake_tac[4] = { 0x35, 0x29, 0x00, 0x00 };
    int ret = -2;

    asn_dec_rval_t dr = ber_decode(NULL, &asn_DEF_InitiateAuthenticationOkEs9,
                                   (void **)&in, es9, es9_len);
    if (dr.code != RC_OK || !in) {
        if (in) ASN_STRUCT_FREE(asn_DEF_InitiateAuthenticationOkEs9, in);
        return -2;
    }

    memset(&req, 0, sizeof req);
    /* Shallow: these four borrow their storage from `in`, which outlives
       the encode below. req is never ASN_STRUCT_FREE'd for that reason --
       it does not own what it points at. */
    req.serverSigned1       = in->serverSigned1;
    req.serverSignature1    = in->serverSignature1;
    req.euiccCiPKIdToBeUsed = in->euiccCiPKIdToBeUsed;
    req.serverCertificate   = in->serverCertificate;

    req.ctxParams1.present = CtxParams1_PR_ctxParamsForCommonAuthentication;
    if (OCTET_STRING_fromBuf(
            &req.ctxParams1.choice.ctxParamsForCommonAuthentication
                 .deviceInfo.tac,
            (const char *)fake_tac, sizeof fake_tac) != 0) {
        goto out;
    }

    {
        rsp_growbuf_t g = {0};
        asn_enc_rval_t er = der_encode(&asn_DEF_AuthenticateServerRequest,
                                        &req, growbuf_sink, &g);
        if (er.encoded < 0) { rsp_growbuf_free(&g); goto out; }
        *out = g.buf;
        *out_len = g.len;
        ret = 0;
    }

out:
    ASN_STRUCT_FREE_CONTENTS_ONLY(
        asn_DEF_OCTET_STRING,
        &req.ctxParams1.choice.ctxParamsForCommonAuthentication
             .deviceInfo.tac);
    ASN_STRUCT_FREE(asn_DEF_InitiateAuthenticationOkEs9, in);
    return ret;
}

/* Steps 5 and 6 do not speak the same language either, for the same
   reason steps 3 and 4 do not. rsp_dp_authenticate_client answers with an
   AuthenticateClientResponseEs9, tag 'BF3B' -- the ES9+ *response*. The
   card expects a PrepareDownloadRequest, tag 'BF21' -- the ES10b
   *request*. Sending the ES9+ answer through unchanged is what a real
   eUICC answered '6A88' to, "referenced data not found": it was handed a
   data object it has no ES10b function for.

   Three of AuthenticateClientOk's five fields are exactly
   PrepareDownloadRequest's, with the same types and the same tags, so
   they move across untouched -- smdpSignature2 covers smdpSigned2, and
   re-encoding either would break the signature the card is about to
   check. The two that are dropped are the two the card already has:
   transactionId (from the session) and profileMetaData (which the SM-DP+
   sent for the LPA to show a user, not for the eUICC).

   hashCc stays absent. It is OPTIONAL and carries the hash of a
   Confirmation Code; this library never sends one, and SmdpSigned2's own
   ccRequiredFlag from the SM-DP+ side is false to match. */
int rsp_lpa_repack_prepare_download(const uint8_t *es9, size_t es9_len,
                                    uint8_t **out, size_t *out_len)
{
    AuthenticateClientResponseEs9_t *in = NULL;
    PrepareDownloadRequest_t req;
    int ret = -2;

    asn_dec_rval_t dr = ber_decode(NULL,
                                    &asn_DEF_AuthenticateClientResponseEs9,
                                    (void **)&in, es9, es9_len);
    if (dr.code != RC_OK || !in) {
        if (in) ASN_STRUCT_FREE(asn_DEF_AuthenticateClientResponseEs9, in);
        return -2;
    }
    /* The authenticateClientError arm cannot reach here: step 5 returned
       0, and rsp_dp_authenticate_client only emits the Ok arm when it
       does. Refused as -2 rather than trusted, because "cannot make sense
       of it" is exactly what an impossible shape is. */
    if (in->present != AuthenticateClientResponseEs9_PR_authenticateClientOk) {
        ASN_STRUCT_FREE(asn_DEF_AuthenticateClientResponseEs9, in);
        return -2;
    }

    memset(&req, 0, sizeof req);
    /* Shallow, exactly as repack_authenticate_server above: these three
       borrow their storage from `in`, which outlives the encode below, so
       req is never ASN_STRUCT_FREE'd -- it does not own what it points
       at. */
    req.smdpSigned2     = in->choice.authenticateClientOk.smdpSigned2;
    req.smdpSignature2  = in->choice.authenticateClientOk.smdpSignature2;
    req.smdpCertificate = in->choice.authenticateClientOk.smdpCertificate;

    {
        rsp_growbuf_t g = {0};
        asn_enc_rval_t er = der_encode(&asn_DEF_PrepareDownloadRequest,
                                        &req, growbuf_sink, &g);
        if (er.encoded < 0) {
            rsp_growbuf_free(&g);
        } else {
            *out = g.buf;
            *out_len = g.len;
            ret = 0;
        }
    }

    ASN_STRUCT_FREE(asn_DEF_AuthenticateClientResponseEs9, in);
    return ret;
}

int rsp_lpa_install(rsp_transport_t *t,
                    const uint8_t *upp, size_t upp_len,
                    const uint8_t *metadata, size_t metadata_len,
                    const uint8_t transaction_id[16],
                    const uint8_t server_challenge[16],
                    const uint8_t otsk_dp[32],
                    const char *server_address,
                    uint8_t **result, size_t *result_len,
                    int *step, int *no_isdr, int *installed)
{
    struct install_scratch g;
    size_t info1_len = 0, auth_req_len = 0, auth_resp_len = 0;
    size_t prep_req_len = 0, prep_resp_len = 0, bpp_len = 0;
    rsp_dp_session_t *s = NULL;
    int rc;

    memset(&g, 0, sizeof g);
    if (step) *step = 0;
    if (no_isdr) *no_isdr = 0;
    if (!t || !upp || !metadata || !transaction_id || !server_challenge ||
        !otsk_dp || !server_address ||
        !result || !result_len) {
        return -2;
    }
    *result = NULL;
    *result_len = 0;

    if (step) *step = 1;
    rc = rsp_card_get_info1(t, &g.info1, &info1_len, no_isdr);
    if (rc != 0) goto out;

    if (step) *step = 2;
    uint8_t challenge[16];
    rc = rsp_card_get_challenge(t, challenge, no_isdr);
    if (rc != 0) goto out;

    /* From here on the card holds a session, and every exit has to
       cancel it. */
    if (step) *step = 3;
    rc = rsp_dp_initiate_authentication(challenge, sizeof challenge,
                                        g.info1, info1_len, transaction_id,
                                        server_challenge,
                                        server_address, server_address,
                                        &s, &g.auth_req, &auth_req_len);
    if (rc != 0) goto out;

    if (step) *step = 4;
    {
        uint8_t *req = NULL;
        size_t req_len = 0;
        rc = rsp_lpa_repack_authenticate_server(g.auth_req, auth_req_len,
                                        &req, &req_len);
        if (rc != 0) goto cancel;
        free(g.auth_req);
        g.auth_req = req;
        auth_req_len = req_len;
    }
    rc = rsp_card_authenticate_server(t, g.auth_req, auth_req_len,
                                      &g.auth_resp, &auth_resp_len, NULL);
    if (rc != 0) goto cancel;

    if (step) *step = 5;
    rc = rsp_dp_authenticate_client(s, g.auth_resp, auth_resp_len,
                                    metadata, metadata_len,
                                    &g.prep_req, &prep_req_len);
    if (rc != 0) goto cancel;

    if (step) *step = 6;
    {
        uint8_t *req = NULL;
        size_t req_len = 0;
        rc = rsp_lpa_repack_prepare_download(g.prep_req, prep_req_len,
                                     &req, &req_len);
        if (rc != 0) goto cancel;
        free(g.prep_req);
        g.prep_req = req;
        prep_req_len = req_len;
    }
    rc = rsp_card_prepare_download(t, g.prep_req, prep_req_len,
                                   &g.prep_resp, &prep_resp_len, NULL);
    if (rc != 0) goto cancel;

    if (step) *step = 7;
    rc = rsp_dp_get_bound_profile_package(s, g.prep_resp, prep_resp_len,
                                          upp, upp_len, otsk_dp,
                                          &g.bpp, &bpp_len);
    g.bpp_len = bpp_len;
    if (rc != 0) goto cancel;

    if (step) *step = 8;
    rc = rsp_card_load_bpp(t, g.bpp, bpp_len, result, result_len, NULL);
    if (rc != 0) goto cancel;

    /* Step 9: the eUICC's own report, checked rather than believed.
       Everything above this line establishes what the card was sent; this
       establishes that what came back is the card's answer to it.
       ProfileInstallationResult carries euiccSignPIR for exactly that
       purpose (SGP.22 v2.6 section 2.5.6), and until this call existed
       nothing looked at it -- a report of success was accepted because it
       arrived.

       Its own step number, not folded into 8, because the two failures
       mean different things and lead somewhere different: a step 8 failure
       is the card refusing a block, with nothing installed; a step 9
       failure is a profile that may well be installed and a report about
       it this library cannot attribute to the card. No cancel on this
       path either -- the load already completed, and cancelling a finished
       session with loadBppExecutionError would tell the card something
       untrue about what happened. */
    if (step) *step = 9;
    {
        int ok = 0;
        rc = rsp_dp_verify_installation_result(s, *result, *result_len,
                                               &ok, NULL, NULL);
        if (rc != 0) goto out;
        if (installed) *installed = ok;
    }

    goto out;

cancel:
    /* loadBppExecutionError(5) is the CancelSessionReason section 5.7.14
       provides for exactly this. The cancellation's own outcome is not
       reported: it cannot change what already went wrong, and letting it
       overwrite rc would hide the real failure behind a secondary one. */
    (void)rsp_card_cancel_session(t, transaction_id, 5, NULL);

out:
    if (s) rsp_dp_session_free(s);
    scratch_free(&g);
    return rc;
}
