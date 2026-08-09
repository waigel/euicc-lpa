/*
 * lpa_install.c -- the eight-step exchange that installs a profile.
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

int rsp_lpa_install(rsp_transport_t *t,
                    const uint8_t *upp, size_t upp_len,
                    const uint8_t *metadata, size_t metadata_len,
                    const uint8_t transaction_id[16],
                    const uint8_t otsk_dp[32],
                    uint8_t **result, size_t *result_len,
                    int *step, int *no_isdr)
{
    struct install_scratch g;
    size_t info1_len = 0, auth_req_len = 0, auth_resp_len = 0;
    size_t prep_req_len = 0, prep_resp_len = 0, bpp_len = 0;
    rsp_dp_session_t *s = NULL;
    int rc;

    memset(&g, 0, sizeof g);
    if (step) *step = 0;
    if (no_isdr) *no_isdr = 0;
    if (!t || !upp || !metadata || !transaction_id || !otsk_dp ||
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
                                        &s, &g.auth_req, &auth_req_len);
    if (rc != 0) goto out;

    if (step) *step = 4;
    rc = rsp_card_authenticate_server(t, g.auth_req, auth_req_len,
                                      &g.auth_resp, &auth_resp_len, NULL);
    if (rc != 0) goto cancel;

    if (step) *step = 5;
    rc = rsp_dp_authenticate_client(s, g.auth_resp, auth_resp_len,
                                    metadata, metadata_len,
                                    &g.prep_req, &prep_req_len);
    if (rc != 0) goto cancel;

    if (step) *step = 6;
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
