/* A recording is a text file so it can be read in a review, diffed, and
   hand-edited into the failure cases a healthy card will not produce. */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "lpa.h"

static int fails = 0;
static void ok(const char *what, int cond) {
    printf("%s   %s\n", cond ? "ok  " : "FAIL", what);
    if(!cond) fails = 1;
}

static void write_file(const char *path, const char *body) {
    FILE *f = fopen(path, "w");
    if(f) { fputs(body, f); fclose(f); }
}

int main(void) {
    const char *path = "/tmp/rsp-test-recording.log";
    /* A third exchange, beyond the two the brief's prose walks through, so
       that "an unexpected command is refused" below has a real recorded
       exchange still pending when it fires. Without it, both recorded
       exchanges are already consumed by the two calls that precede it, and
       that assertion would be indistinguishable from "the recording ran
       out" -- true regardless of whether transceive checks the command at
       all. See task-1-report.md for the full account of this deviation. */
    write_file(path,
        "# a recording, for the test\n"
        "> 00A4040002A000\n"
        "< 9000\n"
        "> BF2200\n"
        "< BF2201 9000\n"
        "> 00C0000002\n"
        "< 9000\n");

    rsp_transport_t t;
    ok("a recording opens", rsp_replay_open(path, &t) == 0);

    uint8_t resp[64];
    const uint8_t sel[] = { 0x00,0xA4,0x04,0x00,0x02,0xA0,0x00 };
    long n = t.transceive(&t, sel, sizeof sel, resp, sizeof resp);
    ok("the first exchange returns its recorded answer",
       n == 2 && resp[0] == 0x90 && resp[1] == 0x00);

    /* Whitespace inside a hex line is insignificant: the writer groups the
       status bytes for readability and the reader must not care. */
    const uint8_t info[] = { 0xBF,0x22,0x00 };
    n = t.transceive(&t, info, sizeof info, resp, sizeof resp);
    ok("whitespace in the recorded hex is ignored",
       n == 5 && resp[0] == 0xBF && resp[3] == 0x90 && resp[4] == 0x00);

    /* The strict sequence is the point: a recording is a pin on the bytes,
       not a lenient stub. Sending something else must stop the run. The
       third exchange above is still unconsumed at this point (pos 2 of 3),
       so this is refused for being the wrong command, not because the
       recording ran out. */
    ok("an unexpected command is refused",
       t.transceive(&t, sel, sizeof sel, resp, sizeof resp) < 0);
    t.close(&t);

    /* Running past the end is a failure, not a silent empty answer. All
       three recorded exchanges are consumed first, so this is genuinely
       past the end, not a wrong-command refusal wearing the same sign. */
    const uint8_t getresp[] = { 0x00,0xC0,0x00,0x00,0x02 };
    ok("a short recording opens", rsp_replay_open(path, &t) == 0);
    t.transceive(&t, sel, sizeof sel, resp, sizeof resp);
    t.transceive(&t, info, sizeof info, resp, sizeof resp);
    t.transceive(&t, getresp, sizeof getresp, resp, sizeof resp);
    ok("running past the end is refused",
       t.transceive(&t, getresp, sizeof getresp, resp, sizeof resp) < 0);
    t.close(&t);

    ok("a missing file is could-not-answer",
       rsp_replay_open("/tmp/rsp-no-such-recording", &t) == -2);

    /* Recording a replayed session must reproduce the same file, so the
       writer and the reader are proven inverse to each other. */
    rsp_transport_t inner, rec;
    ok("the inner transport opens", rsp_replay_open(path, &inner) == 0);
    ok("the recorder opens",
       rsp_record_open(&inner, "/tmp/rsp-test-rerecorded.log", &rec) == 0);
    rec.transceive(&rec, sel, sizeof sel, resp, sizeof resp);
    rec.transceive(&rec, info, sizeof info, resp, sizeof resp);
    rec.close(&rec);

    rsp_transport_t again;
    ok("the re-recorded file replays", rsp_replay_open("/tmp/rsp-test-rerecorded.log", &again) == 0);
    n = again.transceive(&again, sel, sizeof sel, resp, sizeof resp);
    ok("and answers the same", n == 2 && resp[0] == 0x90);
    again.close(&again);

    /* Finding F: every file rsp_record_open writes opens with a "#" header
       saying what it holds -- read as an ordinary comment by
       rsp_replay_open, per the format's own rule, which is exactly why
       the round trip above already worked without any parser change. */
    {
        FILE *hf = fopen("/tmp/rsp-test-rerecorded.log", "r");
        char hbuf[4096];
        size_t hgot = hf ? fread(hbuf, 1, sizeof hbuf - 1, hf) : 0;
        if (hf) fclose(hf);
        hbuf[hgot] = '\0';
        ok("a re-recorded file opens with a '#' header",
           hbuf[0] == '#' && strstr(hbuf, "protected material") != NULL);
    }

    /* Fix round 1, finding 1: recording a FAILED exchange must reproduce
       the same failure on replay, not a blank "< " line that reads back
       as a fake zero-length success. The inner transport below has only
       one recorded exchange, so its second call genuinely fails -- an
       exhausted recording is "we could not ask", -2, per finding E's
       later pass that made replay's exhaustion/mismatch/buffer-too-small
       cases agree with PC/SC's own -2 for the same class of failure
       (include/rsp.h's failure convention) -- the same shape a real card
       refusing something during a live session (Task 5) will take. */
    {
        const char *shortpath = "/tmp/rsp-test-one-exchange.log";
        const char *failpath = "/tmp/rsp-test-failure.log";
        write_file(shortpath, "> AABBCC\n< 9000\n");

        rsp_transport_t innerFail, recFail;
        ok("a one-exchange recording opens",
           rsp_replay_open(shortpath, &innerFail) == 0);
        ok("the failure-capturing recorder opens",
           rsp_record_open(&innerFail, failpath, &recFail) == 0);

        const uint8_t cmdA[] = { 0xAA, 0xBB, 0xCC };
        const uint8_t cmdB[] = { 0xDD, 0xEE, 0xFF };
        long r1 = recFail.transceive(&recFail, cmdA, sizeof cmdA, resp, sizeof resp);
        ok("the first exchange still succeeds through the recorder",
           r1 == 2 && resp[0] == 0x90 && resp[1] == 0x00);

        long r2 = recFail.transceive(&recFail, cmdB, sizeof cmdB, resp, sizeof resp);
        ok("the inner transport's second call genuinely fails",
           r2 == -2);
        recFail.close(&recFail);

        /* The literal bug the review reproduced: a blank "< " line that
           replays as a fake zero-length success. Confirm the file holds
           the failure marker instead of that blank line.

           4096, not 256: rsp_record_open now opens every file with a "#"
           header (finding F) ahead of the actual exchange lines, and a
           buffer too small to hold header-plus-exchanges would silently
           truncate before ever reaching the marker this assertion is
           looking for -- passing for the wrong reason, or failing for one
           unrelated to what it claims to check. */
        FILE *ff = fopen(failpath, "r");
        char buf[4096];
        size_t got = ff ? fread(buf, 1, sizeof buf - 1, ff) : 0;
        if (ff) fclose(ff);
        buf[got] = '\0';
        ok("the recording holds a failure marker, not a blank response line",
           strstr(buf, "!-2") != NULL && strstr(buf, "< \n") == NULL);

        rsp_transport_t replayedFail;
        ok("the recording of a failed exchange replays",
           rsp_replay_open(failpath, &replayedFail) == 0);
        long p1 = replayedFail.transceive(&replayedFail, cmdA, sizeof cmdA, resp, sizeof resp);
        ok("the first, successful exchange still replays as success",
           p1 == 2 && resp[0] == 0x90 && resp[1] == 0x00);

        memset(resp, 0xAA, sizeof resp); /* poison, to prove it stays untouched */
        long p2 = replayedFail.transceive(&replayedFail, cmdB, sizeof cmdB, resp, sizeof resp);
        ok("the failed exchange replays as the same failure, not a fake success",
           p2 == -2);
        ok("a replayed failure does not touch the caller's response buffer",
           resp[0] == 0xAA);
        replayedFail.close(&replayedFail);
    }

    /* Fix round 1, finding 2: every malformed-file path rsp_replay_open
       defends against gets its own recorded assertion. Each must be -2 --
       "cannot be parsed" -- since a hand-edited recording is the normal
       case for this format, per the brief, not an exotic one. */
    {
        rsp_transport_t bad;

        write_file("/tmp/rsp-bad-odd.log", "> ABC\n< 9000\n");
        ok("an odd number of hex digits is -2",
           rsp_replay_open("/tmp/rsp-bad-odd.log", &bad) == -2);

        write_file("/tmp/rsp-bad-nonhex.log", "> AABBZZ\n< 9000\n");
        ok("a non-hex character is -2",
           rsp_replay_open("/tmp/rsp-bad-nonhex.log", &bad) == -2);

        write_file("/tmp/rsp-bad-orphan.log", "< 9000\n");
        ok("a response with no preceding command is -2",
           rsp_replay_open("/tmp/rsp-bad-orphan.log", &bad) == -2);

        write_file("/tmp/rsp-bad-double.log", "> AABBCC\n> DDEEFF\n< 9000\n");
        ok("two commands in a row with no response between them is -2",
           rsp_replay_open("/tmp/rsp-bad-double.log", &bad) == -2);

        write_file("/tmp/rsp-bad-trailing.log", "> AABBCC\n");
        ok("a trailing command with no response is -2",
           rsp_replay_open("/tmp/rsp-bad-trailing.log", &bad) == -2);

        write_file("/tmp/rsp-bad-empty.log", "");
        ok("an empty file is -2",
           rsp_replay_open("/tmp/rsp-bad-empty.log", &bad) == -2);

        write_file("/tmp/rsp-bad-comments-only.log", "# nothing but comments\n\n");
        ok("a file with only comments and blank lines is also -2",
           rsp_replay_open("/tmp/rsp-bad-comments-only.log", &bad) == -2);
    }

    return fails ? 1 : 0;
}
