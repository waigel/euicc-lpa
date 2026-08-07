/* rsp_card_read_profiles / rsp_card_profiles_free, against three
   recordings:

   - testdata/cards/omnikey-profiles.log: this project's own test eUICC,
     captured for real over PC/SC (see testdata/cards/README.md) -- and
     it has no profiles installed at all, so this is the real card's own
     "empty list" answer, not an invented one.
   - testdata/cards/synthetic-profiles.log: hand-built via the generated
     encoder (README.md again), since the real card has nothing to pin
     actual ProfileInfo content against. Two entries: one with every
     field this function reports, one with almost none, exercising the
     fact that every one of them is genuinely OPTIONAL.
   - testdata/cards/omnikey-profiles-error.log: a hand-edited copy of the
     real capture, its one STORE DATA response changed from
     profileInfoListOk to profileInfoListError -- a case a healthy card
     will not itself produce for an unrestricted request, and exactly
     why this recording exists by hand rather than by capture. */
#include <stdio.h>
#include <string.h>
#include "lpa.h"
#include "ProfileInfoListError.h"

static int fails = 0;
static void ok(const char *what, int cond) {
    printf("%s   %s\n", cond ? "ok  " : "FAIL", what);
    if(!cond) fails = 1;
}

static void test_empty_real_card(void) {
    rsp_transport_t t;
    ok("the empty-list recording opens",
       rsp_replay_open("testdata/cards/omnikey-profiles.log", &t) == 0);

    rsp_profile_info_t *profiles = (void *)0x1; /* poisoned: must become NULL */
    size_t count = 999;
    long err = -1;
    int no_isdr = 1;
    int rc = rsp_card_read_profiles(&t, &profiles, &count, &err, &no_isdr);

    ok("a real card with nothing installed reads as success, not failure",
       rc == 0);
    ok("...with an empty list", count == 0);
    ok("...and *out left NULL, not dangling", profiles == NULL);
    ok("...err untouched (0) on success", err == 0);
    ok("...and no_isdr is 0: the ISD-R itself did answer", no_isdr == 0);

    rsp_card_profiles_free(profiles, count); /* must tolerate NULL/0 */
    t.close(&t);
}

static void test_populated_synthetic(void) {
    rsp_transport_t t;
    ok("the synthetic populated recording opens",
       rsp_replay_open("testdata/cards/synthetic-profiles.log", &t) == 0);

    rsp_profile_info_t *profiles = NULL;
    size_t count = 0;
    long err = 0;
    int no_isdr = 0;
    int rc = rsp_card_read_profiles(&t, &profiles, &count, &err, &no_isdr);
    t.close(&t);

    ok("the populated list reads as success", rc == 0);
    ok("...with exactly two entries", count == 2);
    if(count != 2) { rsp_card_profiles_free(profiles, count); return; }

    static const uint8_t iccid_a[10] = {
        0x89, 0x44, 0x05, 0x89, 0x25, 0x00, 0x12, 0x34, 0x56, 0x7F
    };
    static const uint8_t aid_a[16] = {
        0xA0, 0x00, 0x00, 0x05, 0x59, 0x10, 0x10, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01
    };
    rsp_profile_info_t *a = &profiles[0];
    ok("entry 0: iccid present", a->have_iccid);
    ok("entry 0: iccid matches", memcmp(a->iccid, iccid_a, sizeof iccid_a) == 0);
    ok("entry 0: isdpAid present", a->have_isdp_aid);
    ok("entry 0: isdpAid length is 16", a->isdp_aid_len == 16);
    ok("entry 0: isdpAid matches",
       memcmp(a->isdp_aid, aid_a, sizeof aid_a) == 0);
    ok("entry 0: profileState present", a->have_profile_state);
    ok("entry 0: profileState is enabled(1)", a->profile_state == 1);
    ok("entry 0: profileNickname", a->profile_nickname != NULL
       && strcmp(a->profile_nickname, "My SIM") == 0);
    ok("entry 0: serviceProviderName", a->service_provider_name != NULL
       && strcmp(a->service_provider_name, "Test Telco") == 0);
    ok("entry 0: profileName", a->profile_name != NULL
       && strcmp(a->profile_name, "Test Telco Postpaid") == 0);
    ok("entry 0: profileClass present", a->have_profile_class);
    ok("entry 0: profileClass is operational(2)", a->profile_class == 2);

    static const uint8_t iccid_b[10] = {
        0x89, 0x44, 0x05, 0x89, 0x25, 0x00, 0x98, 0x76, 0x54, 0x3F
    };
    rsp_profile_info_t *b = &profiles[1];
    ok("entry 1: iccid present", b->have_iccid);
    ok("entry 1: iccid matches", memcmp(b->iccid, iccid_b, sizeof iccid_b) == 0);
    ok("entry 1: profileState present", b->have_profile_state);
    ok("entry 1: profileState is disabled(0)", b->profile_state == 0);
    ok("entry 1: isdpAid absent, not a stray guess", !b->have_isdp_aid);
    ok("entry 1: profileNickname absent", b->profile_nickname == NULL);
    ok("entry 1: serviceProviderName absent", b->service_provider_name == NULL);
    ok("entry 1: profileName absent", b->profile_name == NULL);
    ok("entry 1: profileClass absent", !b->have_profile_class);

    rsp_card_profiles_free(profiles, count);
}

static void test_error_variant(void) {
    rsp_transport_t t;
    ok("the hand-edited error recording opens",
       rsp_replay_open("testdata/cards/omnikey-profiles-error.log", &t) == 0);

    rsp_profile_info_t *profiles = (void *)0x1;
    size_t count = 999;
    long err = 0;
    int no_isdr = 1;
    int rc = rsp_card_read_profiles(&t, &profiles, &count, &err, &no_isdr);
    t.close(&t);

    /* This is the one path a healthy card cannot produce for an
       unrestricted request, and exactly why it must read as a real
       refusal (-1), not "could not be asked" (-2) and not success. */
    ok("a decoded profileInfoListError is -1, a real refusal", rc == -1);
    ok("...naming which error: incorrectInputValues(1)",
       err == ProfileInfoListError_incorrectInputValues);
    ok("...*out left NULL on this path too", profiles == NULL);
    ok("...*out_count left 0", count == 0);
    ok("...no_isdr is 0: the ISD-R answered, it just refused the request",
       no_isdr == 0);
}

/* A command that does not match what the recording expects is refused by
   name, not silently answered -- this is replay's own strictness
   (src/rsp_transport.c, tests/test_recording.c), re-asserted here against
   this round's own request byte (BF 2D 00) rather than borrowed from
   another test's fixture, so a regression that only ever sent the wrong
   ES10 request for THIS command would still be caught here even if every
   other replay test kept passing. */
static void test_wrong_request_is_refused(void) {
    rsp_transport_t t;
    ok("the mutated-request recording opens",
       rsp_replay_open("testdata/cards/synthetic-profiles-bad-request.log", &t)
       == 0);

    rsp_profile_info_t *profiles = NULL;
    size_t count = 0;
    long err = 0;
    int no_isdr = 0;
    int rc = rsp_card_read_profiles(&t, &profiles, &count, &err, &no_isdr);
    t.close(&t);

    ok("a request that does not match the recording is -2, not a fake answer",
       rc == -2);
    rsp_card_profiles_free(profiles, count);
}

/* The card, not this library, chooses what profileNickname,
   serviceProviderName and profileName contain: they are UTF8String in
   rsp-2.5.asn, and SGP.22 v2.6 section 5.7.15 has the eUICC return them
   verbatim. Every other fixture here happens to hold nothing but plain
   ASCII letters and spaces, so nothing so far distinguishes a decoder
   that hands the bytes back untouched from one that mangles anything
   unusual. This one asserts the bytes survive exactly -- multi-byte
   UTF-8 included, which a per-byte transformation would corrupt.

   The escaping those same strings need on the way into JSON is a
   separate question and belongs to whoever formats them; euicc-tools'
   tests/run-tests pins that against this same recording. */
static void test_card_chosen_text_survives(void) {
    rsp_transport_t t;
    ok("the card-chosen-text recording opens",
       rsp_replay_open("testdata/cards/synthetic-profiles-hostile-text.log", &t)
       == 0);

    rsp_profile_info_t *profiles = NULL;
    size_t count = 0;
    int rc = rsp_card_read_profiles(&t, &profiles, &count, NULL, NULL);
    t.close(&t);

    ok("card-chosen text reads as success", rc == 0);
    ok("...one entry", count == 1);
    if(count != 1) { rsp_card_profiles_free(profiles, count); return; }

    /* A quote, a backslash, a tab and a C0 control, byte for byte. */
    static const char nick[] =
        "He said \"hi\" \\n is not a newline\t\x01";
    ok("profileNickname survives quote, backslash, tab and control",
       profiles[0].profile_nickname != NULL
       && strcmp(profiles[0].profile_nickname, nick) == 0);
    ok("...and is NUL-terminated at the right length",
       profiles[0].profile_nickname != NULL
       && strlen(profiles[0].profile_nickname) == sizeof nick - 1);

    ok("serviceProviderName keeps an embedded newline",
       profiles[0].service_provider_name != NULL
       && strcmp(profiles[0].service_provider_name, "Acme\nTelco") == 0);

    /* "Gruesse" with u-umlaut and eszett, then two CJK characters --
       two-byte and three-byte UTF-8 sequences, written as bytes here so
       this source file itself stays ASCII. */
    static const char name[] =
        "Gr\xC3\xBC\xC3\x9F" "e \xE6\x97\xA5\xE6\x9C\xAC";
    ok("profileName keeps multi-byte UTF-8 unmangled",
       profiles[0].profile_name != NULL
       && strcmp(profiles[0].profile_name, name) == 0);

    rsp_card_profiles_free(profiles, count);
}

int main(void) {
    test_empty_real_card();
    test_populated_synthetic();
    test_error_variant();
    test_wrong_request_is_refused();
    test_card_chosen_text_survives();
    return fails;
}
