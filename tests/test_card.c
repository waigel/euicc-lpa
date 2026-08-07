/* The real card. Not part of `make check`: it needs a reader, and a test
 * that silently passes when the hardware is absent is worse than no test.
 * Run it with `make check-card`.
 *
 * Two optional arguments name files: the first, when given, gets every
 * exchange of the EUICCInfo2/EID session appended to it via
 * rsp_record_open (Task 5); the second, likewise, for the separate
 * ProfileInfoList session a later round added. Each is its own PC/SC
 * session (SELECT ISD-R happens again for the second), the same way
 * omnikey-info.log and omnikey-profiles.log are two separate recordings,
 * not one file with two sessions spliced together. Plain `make check-card`
 * passes neither, so the default run writes nothing and depends on
 * nothing recorded. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "lpa.h"

static int open_maybe_recorded(const char *path, rsp_transport_t *out) {
    rsp_transport_t raw;
    int rc = rsp_pcsc_open(NULL, &raw);
    if(rc != 0) { fprintf(stderr, "cannot open the card: %d\n", rc); return rc; }
    if(!path) { *out = raw; return 0; }
    /* rsp_record_open takes ownership of raw: it must not be closed
       separately afterward (include/rsp.h). */
    rc = rsp_record_open(&raw, path, out);
    if(rc != 0) {
        fprintf(stderr, "cannot open the recording %s: %d\n", path, rc);
        raw.close(&raw);
    }
    return rc;
}

static void print_hex(const uint8_t *b, size_t n) {
    for(size_t i = 0; i < n; i++) printf("%02X", b[i]);
}

int main(int argc, char **argv) {
    char *readers = NULL;
    long n = rsp_pcsc_readers(&readers);
    if(n <= 0) {
        fprintf(stderr, "no reader attached; this test needs one\n");
        return 2;
    }
    printf("readers:\n");
    for(const char *p = readers; *p; p += strlen(p) + 1) printf("  %s\n", p);
    free(readers);

    rsp_transport_t t;
    int rc = open_maybe_recorded(argc > 1 ? argv[1] : NULL, &t);
    if(rc != 0) return 2;

    rsp_card_info_t info;
    memset(&info, 0, sizeof info);
    rc = rsp_card_read_info(&t, &info, NULL);
    if(rc != 0) { fprintf(stderr, "cannot read the card: %d\n", rc); t.close(&t); return rc == -1 ? 1 : 2; }

    printf("ok   the card answered\n");
    printf("     EID  ");
    print_hex(info.eid, sizeof info.eid);
    printf("\n     SVN  %s\n     issuers %zu\n", info.svn, info.ci_count);

    rsp_card_info_free(&info);
    t.close(&t);

    /* A second, separate PC/SC session for the profile list -- SELECT
       ISD-R again, same as any fresh session must. */
    rc = open_maybe_recorded(argc > 2 ? argv[2] : NULL, &t);
    if(rc != 0) return 2;

    rsp_profile_info_t *profiles = NULL;
    size_t count = 0;
    long err = 0;
    int no_isdr = 0;
    rc = rsp_card_read_profiles(&t, &profiles, &count, &err, &no_isdr);
    if(rc != 0) {
        fprintf(stderr, "cannot read the profile list: %d (no_isdr=%d err=%ld)\n",
                rc, no_isdr, err);
        t.close(&t);
        return rc == -1 ? 1 : 2;
    }

    printf("ok   the profile list was read\n     %zu profile(s)\n", count);
    for(size_t i = 0; i < count; i++) {
        rsp_profile_info_t *p = &profiles[i];
        printf("     [%zu] iccid=", i);
        if(p->have_iccid) print_hex(p->iccid, sizeof p->iccid); else printf("(none)");
        printf(" state=");
        if(p->have_profile_state) printf("%ld", p->profile_state); else printf("(none)");
        printf(" class=");
        if(p->have_profile_class) printf("%ld", p->profile_class); else printf("(none)");
        printf(" name=%s\n", p->profile_name ? p->profile_name : "(none)");
    }

    rsp_card_profiles_free(profiles, count);
    t.close(&t);
    return 0;
}
