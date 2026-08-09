/* rsp_card_get_challenge and rsp_card_delete_profile: the two ES10
   commands the write path needs before anything is installed.

   Both are driven from hand-built recordings, for reasons this
   directory's README goes into: the challenge is sixteen random bytes
   the card picks, so a real capture would pin nothing that recognisable
   fixed bytes do not pin better; and this project's test eUICC has no
   profiles on it, so a real delete could only ever answer
   iccidOrAidNotFound. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "lpa.h"

static int fails = 0;
static void ok(const char *what, int cond) {
    printf("%s   %s\n", cond ? "ok  " : "FAIL", what);
    if(!cond) fails = 1;
}

static void test_challenge(void) {
    rsp_transport_t t;
    ok("the challenge recording opens",
       rsp_replay_open("testdata/cards/synthetic-challenge.log", &t) == 0);

    /* Poisoned, so a function that returned 0 without writing anything
       would be caught by the value assertion rather than passing on
       whatever happened to be on the stack. */
    uint8_t chal[16];
    memset(chal, 0xAA, sizeof chal);
    int no_isdr = 1;
    int rc = rsp_card_get_challenge(&t, chal, &no_isdr);
    t.close(&t);

    ok("the challenge is read", rc == 0);
    ok("...and no_isdr is 0: the ISD-R answered", no_isdr == 0);

    static const uint8_t want[16] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F
    };
    /* The exact bytes, not the length. A decoder that returned sixteen
       bytes of something else -- the wrong field, or an uninitialised
       buffer -- passes a length check and fails this. */
    ok("...and it is the sixteen bytes the card sent",
       memcmp(chal, want, sizeof want) == 0);
}

static void test_delete_ok(void) {
    rsp_transport_t t;
    ok("the delete recording opens",
       rsp_replay_open("testdata/cards/synthetic-delete-ok.log", &t) == 0);

    static const uint8_t iccid[10] = {
        0x89, 0x44, 0x05, 0x89, 0x25, 0x00, 0x12, 0x34, 0x56, 0x7F
    };
    long result = 99;
    int no_isdr = 1;
    int rc = rsp_card_delete_profile(&t, iccid, &result, &no_isdr);
    t.close(&t);

    ok("a deleted profile reads as success", rc == 0);
    ok("...with *result left at 0, not the card's enum value",
       result == 0);
    ok("...and no_isdr is 0", no_isdr == 0);
}

static void test_delete_refused(void) {
    rsp_transport_t t;
    ok("the refused-delete recording opens",
       rsp_replay_open("testdata/cards/synthetic-delete-enabled.log", &t)
       == 0);

    static const uint8_t iccid[10] = {
        0x89, 0x44, 0x05, 0x89, 0x25, 0x00, 0x12, 0x34, 0x56, 0x7F
    };
    long result = 0;
    int no_isdr = 1;
    int rc = rsp_card_delete_profile(&t, iccid, &result, &no_isdr);
    t.close(&t);

    /* The distinction this whole out-parameter exists for: the card
       answered, so this is -1 and not -2, and the reason is carried
       rather than flattened. "still enabled" and "no such profile" send
       a reader to entirely different places. */
    ok("a refused delete is -1, a real answer, not -2", rc == -1);
    ok("...and names profileNotInDisabledState(2)", result == 2);
    ok("...with no_isdr 0: the ISD-R answered, it just refused",
       no_isdr == 0);
}

/* Replay is a pin on the wire, not a lenient stub: a request that does
   not match what was recorded is refused by name. Asserted here against
   this round's own two requests rather than borrowed from another test,
   so a regression that only ever sent the wrong bytes for THESE two
   commands would still be caught. */
static void test_wrong_iccid_is_refused(void) {
    rsp_transport_t t;
    ok("the delete recording opens again",
       rsp_replay_open("testdata/cards/synthetic-delete-ok.log", &t) == 0);

    static const uint8_t other[10] = {
        0x89, 0x44, 0x05, 0x89, 0x25, 0x00, 0x99, 0x99, 0x99, 0x9F
    };
    long result = 0;
    int rc = rsp_card_delete_profile(&t, other, &result, NULL);
    t.close(&t);

    ok("deleting a different ICCID does not match the recording",
       rc == -2);
}

static void test_load_bpp(void) {
    rsp_transport_t t;
    ok("the load-BPP recording opens",
       rsp_replay_open("testdata/cards/synthetic-load-bpp.log", &t) == 0);

    /* The same 30 bytes the recording documents. Built here rather than
       read from a file so the structure the segmenter walks is visible
       beside the APDUs it is expected to produce. */
    static const uint8_t bpp[] = {
        0xBF, 0x36, 0x1B,
          0xBF, 0x23, 0x03, 0x01, 0x02, 0x03,
          0xA0, 0x04, 0x87, 0x02, 0xAA, 0xBB,
          0xA1, 0x04, 0x88, 0x02, 0xCC, 0xDD,
          0xA3, 0x07, 0x86, 0x02, 0x11, 0x22, 0x86, 0x01, 0x33
    };

    uint8_t *res = NULL;
    size_t res_len = 0;
    int no_isdr = 1;
    int rc = rsp_card_load_bpp(&t, bpp, sizeof bpp, &res, &res_len,
                               &no_isdr);
    t.close(&t);

    /* Replay refuses any exchange whose command does not match, so this
       passing means every one of the seven segments went out with the
       right bytes, the right length and -- the thing that matters --
       P2 back at zero. A running counter fails at the second segment. */
    ok("the BPP is sent in section 2.5.5's seven segments", rc == 0);
    ok("...and no_isdr is 0", no_isdr == 0);

    static const uint8_t want[] = { 0xBF, 0x37, 0x03, 0x80, 0x01, 0x00 };
    ok("...and the Profile Installation Result comes back",
       res_len == sizeof want && res
       && memcmp(res, want, sizeof want) == 0);
    free(res);
}

/* A package whose own lengths do not agree with its size is refused,
   not read past. The outer header here claims 27 bytes of content but
   only 5 follow. */
static void test_truncated_bpp_is_refused(void) {
    rsp_transport_t t;
    ok("the load-BPP recording opens again",
       rsp_replay_open("testdata/cards/synthetic-load-bpp.log", &t) == 0);

    static const uint8_t bad[] = { 0xBF, 0x36, 0x1B, 0xBF, 0x23, 0x03, 0x01, 0x02 };
    uint8_t *res = (void *)0x1;
    size_t res_len = 99;
    int rc = rsp_card_load_bpp(&t, bad, sizeof bad, &res, &res_len, NULL);
    t.close(&t);

    ok("a BPP shorter than its own length field is -2", rc == -2);
    ok("...with nothing handed back", res == NULL && res_len == 0);
}

/* rsp_lpa_install: what can be asserted without a card.

   The eight-step exchange itself cannot be driven from a hand-built
   recording -- steps 4 and 6 answer with structures the eUICC signs
   with its own key, and inventing those would prove only that this
   test can forge what the library then accepts. The full flow gets its
   proof from a recording of a real installation, which is the next
   piece of work and needs the card.

   What is provable now is the part that has nothing to do with
   cryptography: that arguments are rejected before any I/O happens, and
   that *step reports where the exchange actually got to. On a failure
   that number is the difference between "the card would not talk to us"
   and "we built a package it would not take", which the return value
   alone cannot say. */
static void test_install_arguments(void) {
    uint8_t *res = (void *)0x1;
    size_t res_len = 99;
    int step = 7;
    static const uint8_t upp[1] = { 0x00 };
    static const uint8_t md[1] = { 0x00 };
    static const uint8_t tid[16] = { 0 };
    static const uint8_t otsk[32] = { 0 };

    ok("a null transport is refused",
       rsp_lpa_install(NULL, upp, 1, md, 1, tid, otsk, &res, &res_len,
                       &step, NULL) == -2);
    ok("...before any step is attempted", step == 0);
}

static void test_install_reports_the_step(void) {
    rsp_transport_t t;
    /* This recording answers a challenge request, not the euiccInfo1
       request step 1 sends, so replay refuses the very first exchange.
       That makes it a fixture for exactly one thing: does *step say 1. */
    ok("a recording that cannot answer step 1 opens",
       rsp_replay_open("testdata/cards/synthetic-challenge.log", &t) == 0);

    uint8_t *res = NULL;
    size_t res_len = 0;
    int step = 0;
    static const uint8_t upp[1] = { 0x00 };
    static const uint8_t md[1] = { 0x00 };
    static const uint8_t tid[16] = { 0 };
    static const uint8_t otsk[32] = { 0 };
    int rc = rsp_lpa_install(&t, upp, 1, md, 1, tid, otsk, &res, &res_len,
                             &step, NULL);
    t.close(&t);

    ok("an install that cannot start fails", rc != 0);
    ok("...and names step 1, not a later one", step == 1);
    ok("...with nothing handed back", res == NULL && res_len == 0);
}

int main(void) {
    test_challenge();
    test_delete_ok();
    test_delete_refused();
    test_wrong_iccid_is_refused();
    test_load_bpp();
    test_truncated_bpp_is_refused();
    test_install_arguments();
    test_install_reports_the_step();
    return fails;
}
