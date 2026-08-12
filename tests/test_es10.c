/* The commands, end to end against a recording: select, EUICCInfo2, EID.
   The main flow below drives testdata/cards/omnikey-info.log, captured
   verbatim from Task 5's session with this project's own test eUICC over
   PC/SC (see testdata/cards/README.md) -- so this is no longer a synthetic
   payload the generated encoder produced, but the real card's own bytes,
   asserted against the real card's own answer. */
#include <stdio.h>
#include <string.h>
#include "lpa.h"

static int fails = 0;
static void ok(const char *what, int cond) {
    printf("%s   %s\n", cond ? "ok  " : "FAIL", what);
    if(!cond) fails = 1;
}

int main(void) {
    rsp_transport_t t;
    ok("the recording opens",
       rsp_replay_open("testdata/cards/omnikey-info.log", &t) == 0);

    rsp_card_info_t info;
    memset(&info, 0, sizeof info);
    ok("the card is read", rsp_card_read_info(&t, &info, NULL) == 0);
    ok("the EID arrived", info.have_eid);

    /* What the card in the OMNIKEY reader actually answered during Task 5's
       session, byte for byte, per testdata/cards/omnikey-info.log. */
    static const uint8_t expected_eid[16] = {
        0x89, 0x04, 0x90, 0x32, 0x12, 0x34, 0x51, 0x23,
        0x45, 0x12, 0x34, 0x56, 0x78, 0x90, 0x12, 0x35
    };
    ok("the EID is the real card's own",
       memcmp(info.eid, expected_eid, sizeof expected_eid) == 0);
    ok("the version is parsed", strcmp(info.svn, "2.2.0") == 0);
    ok("the issuer count matches what the real card listed",
       info.ci_count == 2);

    /* The identifier the recording carries must be recognised, and one that
       differs in a single byte must not be. */
    uint8_t known[20]; memcpy(known, info.ci_ids, info.ci_id_len);
    ok("a listed issuer is trusted",
       rsp_card_trusts(&info, known, info.ci_id_len) == 1);
    known[0] ^= 0xFF;
    ok("an unlisted issuer is not trusted",
       rsp_card_trusts(&info, known, info.ci_id_len) == 0);

    /* Fix round 1, finding 3: the id_len check must precede any memcmp,
       so a shorter, longer, or zero-length id -- and specifically a
       genuine PREFIX of a listed identifier, not just any wrong length --
       can never read as trusted. Restore known's first byte first: this
       block asks about known-as-a-listed-issuer's own bytes, truncated or
       extended, not about the flipped-byte value above. */
    known[0] ^= 0xFF;
    ok("known is a listed issuer again, for the length checks below",
       rsp_card_trusts(&info, known, info.ci_id_len) == 1);

    ok("a shorter identifier -- a genuine prefix of a listed one -- is not trusted",
       rsp_card_trusts(&info, known, info.ci_id_len - 1) == 0);

    uint8_t longer[21];
    memcpy(longer, known, info.ci_id_len);
    longer[info.ci_id_len] = 0x00; /* one byte past what any listed id has */
    ok("a longer identifier is not trusted",
       rsp_card_trusts(&info, longer, info.ci_id_len + 1) == 0);

    ok("a zero-length identifier is not trusted",
       rsp_card_trusts(&info, known, 0) == 0);

    /* An eUICC that lists no issuer at all must not crash the check, and
       must not be trusted for anything, including a zero-length id (which
       would otherwise match ci_id_len == 0 on a zeroed struct and reach
       the loop body -- except the loop body never runs when ci_count is
       0, so there is nothing for it to dereference). */
    rsp_card_info_t empty;
    memset(&empty, 0, sizeof empty);
    ok("an eUICC with an empty issuer list trusts nothing",
       rsp_card_trusts(&empty, known, info.ci_id_len) == 0);
    ok("...not even a zero-length id against an empty list",
       rsp_card_trusts(&empty, known, 0) == 0);

    /* uiccCapability, as this card actually sent it: '06 7F 36 C0' -- six
       unused bits, so eighteen declared, over the bytes 7F 36 C0.
       Asserted as individual capabilities rather than as those three
       bytes, because the bytes are only the transport: what a caller acts
       on is "does this card do X", and the numbering between octet and
       capability is exactly where that goes wrong. Bit 0 is clear in 0x7F
       while bits 1..7 are set, which makes it the one bit that catches a
       most-significant-first mix-up on its own. */
    ok("the card declared a uiccCapability", info.have_uicc_capability);
    ok("...of eighteen bits", info.uicc_capability_bits == 18);

    ok("contactless: not claimed", rsp_card_supports(&info, 0) == 0);
    ok("usim: claimed",            rsp_card_supports(&info, 1) == 1);
    ok("javacard: claimed",        rsp_card_supports(&info, 14) == 1);
    ok("multos: not claimed",      rsp_card_supports(&info, 15) == 0);
    ok("multipleIsim: claimed, and the last bit the card declared",
       rsp_card_supports(&info, 17) == 1);

    /* The three things TS.48 v7.0's Generic Test Profile demands that
       this card does not declare -- why it is refused unmodified. They
       sit past the eighteen bits above, so this is also the case that
       has to read as a plain "no" rather than "the card did not say". */
    ok("getIdentity: past what the card declared, so not claimed",
       rsp_card_supports(&info, 22) == 0);
    ok("profile-a-x25519: not claimed", rsp_card_supports(&info, 23) == 0);
    ok("profile-b-p256: not claimed",   rsp_card_supports(&info, 24) == 0);

    ok("a card that sent no uiccCapability answers -1, not 0",
       rsp_card_supports(&empty, 1) == -1);
    ok("...and so does a null card", rsp_card_supports(NULL, 1) == -1);

    rsp_card_info_free(&info);
    t.close(&t);

    /* Fix round 2, real hardware: this project's own test eUICC answers
       SELECT of the ISD-R with '61 21', ISO/IEC 7816-4 response chaining,
       not a bare '9000' -- and the first version of rsp_card_select_isdr
       treated anything but an exact '9000' as a refusal, so it never got
       past the very first exchange against real hardware. omnikey-info.log
       above carries exactly that '61xx' shape, straight from the card
       itself now (Task 5), so "the card is read" already exercises the
       chaining. This second, still-synthetic recording pins the other
       shape ISO/IEC 7816-4 also permits -- a SELECT answering 9000
       directly, with no FCI at all -- a shape this particular card does
       not itself produce, so it stays covered only here. */
    rsp_transport_t t2;
    ok("the direct-SELECT recording opens",
       rsp_replay_open("testdata/cards/synthetic-info-direct-select.log", &t2) == 0);
    rsp_card_info_t info2;
    memset(&info2, 0, sizeof info2);
    ok("the card is read when SELECT answers 9000 directly",
       rsp_card_read_info(&t2, &info2, NULL) == 0);
    rsp_card_info_free(&info2);
    t2.close(&t2);

    /* card.c's own message for "no ISD-R" depends on rsp_card_read_info
       telling the two -1 causes apart: a SELECT of the ISD-R that comes
       back refused (this may not be an eUICC at all, or its ISD-R is
       locked) versus a later ES10 request the ISD-R accepted and then
       refused (the card answered a specific question with no). '6A82' --
       "file or application not found" -- is what a real card without our
       AID provisioned answers a SELECT with; it is the shape, not a
       specific card's own recorded answer, so this fixture is written by
       hand rather than pulled from real hardware. */
    {
        const char *path = "/tmp/rsp-test-no-isdr.log";
        FILE *f = fopen(path, "w");
        if (f) {
            fputs("# SELECT of the ISD-R, refused: no application by that "
                  "AID -- \"6A82\" is ISO/IEC 7816-4's \"file or application "
                  "not found\". Same fixed AID rsp_card_select_isdr always\n"
                  "# asks for (see isdr_aid in src/rsp_es10.c); a card with\n"
                  "# no ISD-R answers this exact command, not a different one.\n"
                  "> 00A4040010A0000005591010FFFFFFFF890000010000\n"
                  "< 6A82\n", f);
            fclose(f);
        }
        rsp_transport_t t3;
        ok("the no-ISD-R recording opens", rsp_replay_open(path, &t3) == 0);
        rsp_card_info_t info3;
        memset(&info3, 0, sizeof info3);
        int no_isdr = 0;
        int rc3 = rsp_card_read_info(&t3, &info3, &no_isdr);
        ok("SELECT refused by the card is reported as -1",
           rc3 == -1);
        ok("no_isdr is set: the ISD-R itself never answered",
           no_isdr == 1);
        t3.close(&t3);

        /* The distinction only means something if a LATER refusal, past a
           successful SELECT, leaves no_isdr at 0 -- otherwise it would
           just be "was there ever any -1", already covered by rc3 alone.
           Truncate omnikey-info.log's own recording right after its
           SELECT/GET RESPONSE pair (still a real SELECT), then answer the
           GetEUICCInfo2 STORE DATA that follows with a refusal instead of
           its recorded 9000. */
        const char *path2 = "/tmp/rsp-test-later-refusal.log";
        FILE *f2 = fopen(path2, "w");
        if (f2) {
            fputs("# A real SELECT (see testdata/cards/omnikey-info.log),\n"
                  "# followed by a GetEUICCInfo2 the ISD-R refuses instead\n"
                  "# of answering -- unrelated to whether an ISD-R exists.\n"
                  "> 00A4040010A0000005591010FFFFFFFF890000010000\n"
                  "< 6121\n"
                  "> 00C0000021\n"
                  "< 6F1F8410A0000005591010FFFFFFFF8900000100A5049F6501FFE005820302020"
                  "09000\n"
                  "> 80E2910003BF220000\n"
                  "< 6A88\n", f2);
            fclose(f2);
        }
        rsp_transport_t t4;
        ok("the later-refusal recording opens", rsp_replay_open(path2, &t4) == 0);
        rsp_card_info_t info4;
        memset(&info4, 0, sizeof info4);
        no_isdr = 1; /* poison, to prove rsp_card_read_info clears it */
        int rc4 = rsp_card_read_info(&t4, &info4, &no_isdr);
        ok("a refusal past a successful SELECT is still -1",
           rc4 == -1);
        ok("...but no_isdr is 0: the ISD-R itself did answer",
           no_isdr == 0);
        t4.close(&t4);
    }

    /* ---- ListNotification -------------------------------------------
       Replayed from a real card. The queue is where a profile management
       operation leaves its trace, and the eUICC keeps it until an LPA
       delivers and says so -- so this fixture also documents what an
       undelivered queue looks like: three of its five entries name
       "smdp-address-placeholder.invalid", from before euicc-rsp took a
       real address, and RFC 2606 guarantees that address never resolves.
       They cannot be delivered, only removed. */
    {
        rsp_transport_t t;
        rsp_notification_info_t *n = NULL;
        size_t count = 0;
        long err = 1;
        int no_isdr = 1;

        ok("the notification recording opens",
           rsp_replay_open("testdata/cards/omnikey-notifications.log", &t) == 0);
        int rc = rsp_card_list_notifications(&t, &n, &count, &err, &no_isdr);
        t.close(&t);

        ok("the card answers ListNotification", rc == 0);
        ok("...with five pending notifications", count == 5);
        ok("...and neither an error nor a missing ISD-R",
           err == 0 && no_isdr == 0);

        if (rc == 0 && count == 5) {
            ok("the sequence numbers come out in order",
               n[0].seq_number == 24 && n[4].seq_number == 28);
            ok("every one of them is an install",
               n[0].operation == 0 && n[1].operation == 0 &&
               n[2].operation == 0 && n[3].operation == 0 &&
               n[4].operation == 0);
            ok("the undeliverable ones still name the placeholder they were "
               "signed with",
               strcmp(n[0].notification_address,
                      "smdp-address-placeholder.invalid") == 0);
            ok("and the later ones name the server that actually answered",
               strcmp(n[4].notification_address, "127.0.0.1") == 0);
            ok("the OPTIONAL iccid is present and ten bytes",
               n[0].have_iccid && n[0].iccid[0] == 0x98 && n[0].iccid[9] == 0x14);
        }
        rsp_card_notifications_free(n, count);
    }

    return fails ? 1 : 0;
}
