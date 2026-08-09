/* rsp_card_get_challenge and rsp_card_delete_profile: the two ES10
   commands the write path needs before anything is installed.

   Both are driven from hand-built recordings, for reasons this
   directory's README goes into: the challenge is sixteen random bytes
   the card picks, so a real capture would pin nothing that recognisable
   fixed bytes do not pin better; and this project's test eUICC has no
   profiles on it, so a real delete could only ever answer
   iccidOrAidNotFound. */
#include <stdio.h>
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

int main(void) {
    test_challenge();
    test_delete_ok();
    test_delete_refused();
    test_wrong_iccid_is_refused();
    return fails;
}
