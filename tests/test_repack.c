/* The two repackers, reached with the fields the JSON binding sends
 * rather than with the encoding euicc-rsp produces.
 *
 * SGP.22 section 6.5 delivers an ES9+ answer as separately base64'd
 * fields, so a networked LPA never holds the structure the in-process
 * one does. The *_fields entry points put the envelope back before
 * repacking, and this holds them to the only standard that matters:
 * the same ES10b request the blob path produces, byte for byte.
 *
 * That standard exists because the envelope is where a tag can be wrong
 * in a way nothing catches until a card refuses. rsp-2.5.asn is
 * AUTOMATIC TAGS, and it switches off for a SEQUENCE or CHOICE as soon
 * as one component carries a tag of its own -- so InitiateAuthentication
 * Ok's envelope is a plain '30' while AuthenticateClientResponseEs9's ok
 * arm is [0] over a SEQUENCE, 'A0'. The wrong one encodes to the same
 * length and looks right. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "lpa.h"
#include "rsp.h"

static int fails;
static void ok(const char *what, int good) {
    printf("%s   %s\n", good ? "ok  " : "FAIL", what);
    if (!good) fails++;
}

static uint8_t *slurp(const char *path, size_t *n) {
    FILE *f = fopen(path, "rb");
    uint8_t *b;
    if (!f) return NULL;
    fseek(f, 0, SEEK_END);
    *n = (size_t)ftell(f);
    fseek(f, 0, SEEK_SET);
    b = malloc(*n);
    if (!b || fread(b, 1, *n, f) != *n) { free(b); fclose(f); return NULL; }
    fclose(f);
    return b;
}

#define SESSION "vendor/euicc-rsp/testdata/session/"

int main(void) {
    /* ---- AuthenticateServer, from InitiateAuthentication's fields --- */
    {
        size_t n = 0;
        uint8_t *blob = slurp(SESSION "initiate-response.der", &n);
        ok("the recorded InitiateAuthentication answer is readable", blob != NULL);
        if (blob) {
            rsp_dp_initiate_fields_t f;
            uint8_t *from_blob = NULL, *from_fields = NULL;
            size_t bl = 0, fl = 0;
            memset(&f, 0, sizeof f);

            ok("it splits into the five fields the binding sends",
               rsp_dp_initiate_fields(blob, n, &f) == 0);
            ok("the blob path repacks",
               rsp_lpa_repack_authenticate_server(blob, n, &from_blob, &bl) == 0);

            /* transactionId crosses the binding as hexadecimal, so the
               caller holds the raw value and not a TLV -- which is why
               it is the one argument given without its tag. */
            ok("the fields path repacks",
               rsp_lpa_repack_authenticate_server_fields(
                   f.transaction_id + 2, f.transaction_id_len - 2,
                   f.server_signed1, f.server_signed1_len,
                   f.server_signature1, f.server_signature1_len,
                   f.euicc_ci_pkid, f.euicc_ci_pkid_len,
                   f.server_certificate, f.server_certificate_len,
                   &from_fields, &fl) == 0);
            ok("and both produce the same ES10b request, byte for byte",
               from_blob && from_fields && bl == fl &&
               memcmp(from_blob, from_fields, bl) == 0);

            free(from_blob);
            free(from_fields);
            free(blob);
        }
    }

    /* ---- PrepareDownload, from AuthenticateClient's fields ---------- */
    {
        size_t n = 0;
        uint8_t *blob = slurp(SESSION "authenticate-response.der", &n);
        ok("the recorded AuthenticateClient answer is readable", blob != NULL);
        if (blob) {
            rsp_dp_authenticate_fields_t g;
            uint8_t *from_blob = NULL, *from_fields = NULL;
            size_t bl = 0, fl = 0;
            memset(&g, 0, sizeof g);

            ok("it splits into its five fields",
               rsp_dp_authenticate_fields(blob, n, &g) == 0);
            ok("the blob path repacks",
               rsp_lpa_repack_prepare_download(blob, n, &from_blob, &bl) == 0);
            ok("the fields path repacks",
               rsp_lpa_repack_prepare_download_fields(
                   g.transaction_id + 2, g.transaction_id_len - 2,
                   g.profile_metadata, g.profile_metadata_len,
                   g.smdp_signed2, g.smdp_signed2_len,
                   g.smdp_signature2, g.smdp_signature2_len,
                   g.smdp_certificate, g.smdp_certificate_len,
                   &from_fields, &fl) == 0);
            ok("and both produce the same ES10b request, byte for byte",
               from_blob && from_fields && bl == fl &&
               memcmp(from_blob, from_fields, bl) == 0);

            free(from_blob);
            free(from_fields);
            free(blob);
        }
    }

    /* A null transactionId is the one argument that cannot be absent:
       every other field may legitimately be empty in some future arm,
       but without this there is nothing to tag. */
    {
        uint8_t *out = NULL;
        size_t out_len = 0;
        ok("a null transactionId is refused, without reaching the repacker",
           rsp_lpa_repack_prepare_download_fields(NULL, 0, NULL, 0, NULL, 0,
                                                  NULL, 0, NULL, 0,
                                                  &out, &out_len) == -2);
    }

    return fails ? 1 : 0;
}
