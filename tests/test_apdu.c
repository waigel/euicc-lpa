/* Chaining is where card drivers fail, so it is tested in both directions
   before anything talks to hardware. These recordings are synthetic: they
   prove the logic, not the fidelity. Task 5 adds a real capture.

   The command line in every recording below is the real STORE DATA APDU
   for req = { 0xBF, 0x22, 0x00 } (3 bytes, one block, so P1 is always
   "last block"): CLA '80' (SGP.22 v2.6 section 5.7.2 Table 47's range is
   '80'-'83' or 'C0'-'CF'; this library always uses channel 0, no secure
   messaging -- GPCS section 11.1.4.1), INS 'E2' (STORE DATA), P1 '91'
   (Table 48: b8=1 "last block", plus the fixed bits for "no general
   encryption info", "BER-TLV", "ISO case 4"), P2 '00' (the first and only
   block), Lc '03', the 3 data bytes, Le '00'. See src/rsp_es10.c's
   top-of-file comment for the full citation trail. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "lpa.h"

static int fails = 0;
static void ok(const char *what, int cond) {
    printf("%s   %s\n", cond ? "ok  " : "FAIL", what);
    if(!cond) fails = 1;
}

static void write_file(const char *path, const char *body) {
    FILE *f = fopen(path, "w"); if(f) { fputs(body, f); fclose(f); }
}

/* Appends one recording line (prefix, then hex(b[0..n)), then a newline)
   to f. Used below where the line is built from real bytes rather than
   typed out, because a 255- or 256-byte hex string is easy to get wrong
   by eye. */
static void write_apdu(FILE *f, const char *prefix, const uint8_t *b, size_t n) {
    if (!f) return;
    fputs(prefix, f);
    for (size_t i = 0; i < n; i++) fprintf(f, "%02X", b[i]);
    fputc('\n', f);
}

/* One STORE DATA command APDU -- CLA 0x80, INS 0xE2 (SGP.22 v2.6 section
   5.7.2, Table 47), the caller's P1/P2, Lc, the data, Le 0x00. cmd must
   have room for 6 + n bytes. Returns the command's length. */
static size_t store_data_cmd(uint8_t *cmd, uint8_t p1, uint8_t p2,
                             const uint8_t *data, size_t n) {
    cmd[0] = 0x80; cmd[1] = 0xE2; cmd[2] = p1; cmd[3] = p2;
    cmd[4] = (uint8_t)n;
    if (n) memcpy(cmd + 5, data, n);
    cmd[5 + n] = 0x00;
    return 6 + n;
}

int main(void) {
    /* A short request and a short answer: no chaining either way. */
    const char *simple = "/tmp/rsp-apdu-simple.log";
    write_file(simple,
        "> 80E2910003BF220000\n"
        "< BF220102 9000\n");

    rsp_transport_t t;
    ok("the simple recording opens", rsp_replay_open(simple, &t) == 0);

    const uint8_t req[] = { 0xBF, 0x22, 0x00 };
    uint8_t *out = NULL; size_t out_len = 0; unsigned sw = 0;
    ok("a short exchange succeeds",
       rsp_es10_send(&t, req, sizeof req, &out, &out_len, &sw) == 0);
    ok("the status bytes are stripped from the answer", out_len == 4);
    ok("the answer is the response DER",
       out && out[0] == 0xBF && out[1] == 0x22);
    free(out); out = NULL;
    t.close(&t);

    /* A long answer: the card reports 61xx and the rest arrives through
       GET RESPONSE. The driver must join the parts and strip both
       statuses. The TLV declares a 6-byte value (BF 22 06 ...) but only 3
       of those 6 bytes are in this response; 61 03 says 3 more are
       waiting. GET RESPONSE (CLA '00', INS 'C0', ISO/IEC 7816-4, per
       SGP.22 v2.6 section 5.7.2 / GPCS section 11.1.5.2) asks for exactly
       those 3 (Le '03') and gets them, followed by 9000. The joined
       answer is the tag+length (2) plus all 6 value bytes: 9 bytes. */
    const char *chained = "/tmp/rsp-apdu-chained.log";
    write_file(chained,
        "> 80E2910003BF220000\n"
        "< BF22 06 010203 6103\n"
        "> 00C0000003\n"
        "< 040506 9000\n");
    ok("the chained recording opens", rsp_replay_open(chained, &t) == 0);
    ok("a chained answer succeeds",
       rsp_es10_send(&t, req, sizeof req, &out, &out_len, &sw) == 0);
    ok("the parts are joined in order",
       out_len == 9 && out[5] == 0x03 && out[6] == 0x04 && out[8] == 0x06);
    free(out); out = NULL;
    t.close(&t);

    /* A status the driver cannot use is a real negative answer, and the
       caller must be able to see which one it was. */
    const char *refused = "/tmp/rsp-apdu-refused.log";
    write_file(refused,
        "> 80E2910003BF220000\n"
        "< 6A82\n");
    ok("the refusal recording opens", rsp_replay_open(refused, &t) == 0);
    ok("a refusal is a real negative answer",
       rsp_es10_send(&t, req, sizeof req, &out, &out_len, &sw) == -1);
    ok("and the status word is reported", sw == 0x6A82);
    ok("and nothing is handed back", out == NULL);
    t.close(&t);

    /* A truncated chain: the card promises more and the exchange ends.
       This must fail, not return the part that did arrive. */
    const char *truncated = "/tmp/rsp-apdu-truncated.log";
    write_file(truncated,
        "> 80E2910003BF220000\n"
        "< BF22 06 010203 6103\n");
    ok("the truncated recording opens", rsp_replay_open(truncated, &t) == 0);
    ok("a truncated chain fails rather than returning a fragment",
       rsp_es10_send(&t, req, sizeof req, &out, &out_len, &sw) < 0);
    ok("and still hands nothing back", out == NULL);
    t.close(&t);

    /* Outward chaining, exercised for real: everything above sends a
       request that fits in one block, so the block-splitting path
       (src/rsp_es10.c's outer loop) never runs under those recordings.
       rsp_replay_open's exact-match requirement (src/rsp_transport.c) is
       itself the assertion that the driver produced the right P1, P2 and
       split: if any of them were wrong, the recorded exchange below
       would simply refuse to replay, and the ok() around it would go
       red -- there is no way for these to pass without the outward
       chaining being right. */
    {
        static uint8_t big[256];
        for (size_t i = 0; i < sizeof big; i++) big[i] = (uint8_t)i;

        /* One byte under the block size: still a single block, P1 last
           (0x91), P2 0. */
        {
            uint8_t cmd[6 + 254];
            size_t cmd_len = store_data_cmd(cmd, 0x91, 0x00, big, 254);
            const char *path = "/tmp/rsp-apdu-under.log";
            FILE *f = fopen(path, "w");
            write_apdu(f, "> ", cmd, cmd_len);
            write_apdu(f, "< ", (const uint8_t[]){ 0x90, 0x00 }, 2);
            if (f) fclose(f);

            ok("the 254-byte (one under the block size) recording opens",
               rsp_replay_open(path, &t) == 0);
            ok("a 254-byte request is one block, P1 last, P2 0",
               rsp_es10_send(&t, big, 254, &out, &out_len, &sw) == 0);
            free(out); out = NULL;
            t.close(&t);
        }

        /* Exactly at the block size: still one block. */
        {
            uint8_t cmd[6 + 255];
            size_t cmd_len = store_data_cmd(cmd, 0x91, 0x00, big, 255);
            const char *path = "/tmp/rsp-apdu-at.log";
            FILE *f = fopen(path, "w");
            write_apdu(f, "> ", cmd, cmd_len);
            write_apdu(f, "< ", (const uint8_t[]){ 0x90, 0x00 }, 2);
            if (f) fclose(f);

            ok("the 255-byte (exactly the block size) recording opens",
               rsp_replay_open(path, &t) == 0);
            ok("a 255-byte request is still one block, P1 last, P2 0",
               rsp_es10_send(&t, big, 255, &out, &out_len, &sw) == 0);
            free(out); out = NULL;
            t.close(&t);
        }

        /* One byte over the block size: two blocks. The first carries
           P1 "more blocks" (0x11) and P2 0 with the 255 bytes that fit;
           the second carries P1 "last block" (0x91) and P2 1 with the
           one byte left over -- the split SGP.22 v2.6 section 2.5.5
           describes ("blocks of 255 bytes for the first blocks and a
           last block that MAY be shorter"). */
        {
            uint8_t cmd1[6 + 255];
            size_t cmd1_len = store_data_cmd(cmd1, 0x11, 0x00, big, 255);
            uint8_t cmd2[6 + 1];
            size_t cmd2_len = store_data_cmd(cmd2, 0x91, 0x01, big + 255, 1);
            const char *path = "/tmp/rsp-apdu-over.log";
            FILE *f = fopen(path, "w");
            write_apdu(f, "> ", cmd1, cmd1_len);
            write_apdu(f, "< ", (const uint8_t[]){ 0x90, 0x00 }, 2);
            write_apdu(f, "> ", cmd2, cmd2_len);
            write_apdu(f, "< ", (const uint8_t[]){ 0xAA, 0xBB, 0x90, 0x00 }, 4);
            if (f) fclose(f);

            ok("the 256-byte (one over the block size) recording opens",
               rsp_replay_open(path, &t) == 0);
            ok("a 256-byte request splits into two blocks -- first P1 "
               "0x11/P2 0 with 255 bytes, second P1 0x91/P2 1 with the "
               "last byte -- and succeeds",
               rsp_es10_send(&t, big, 256, &out, &out_len, &sw) == 0);
            ok("the answer is what the last block's exchange recorded",
               out_len == 2 && out[0] == 0xAA && out[1] == 0xBB);
            free(out); out = NULL;
            t.close(&t);
        }
    }

    /* An intermediate block's response must never carry a data field
       (SGP.22 v2.6 section 5.7.6, "Response Data"), even alongside a
       bare 9000 -- a card that does this is breaking the protocol, and
       include/lpa.h ties -1's *sw strictly to a genuine refusal status,
       so reporting -1 with *sw == 0x9000 would say "refused, status:
       success", a contradiction the caller cannot act on. The right
       answer is -2, same as any other exchange that could not happen,
       with *sw left untouched. */
    {
        static uint8_t big2[256];
        for (size_t i = 0; i < sizeof big2; i++) big2[i] = (uint8_t)i;

        uint8_t cmd1[6 + 255];
        size_t cmd1_len = store_data_cmd(cmd1, 0x11, 0x00, big2, 255);
        uint8_t cmd2[6 + 1];
        size_t cmd2_len = store_data_cmd(cmd2, 0x91, 0x01, big2 + 255, 1);
        const char *path = "/tmp/rsp-apdu-intermediate-data.log";
        FILE *f = fopen(path, "w");
        write_apdu(f, "> ", cmd1, cmd1_len);
        write_apdu(f, "< ", (const uint8_t[]){ 0x01, 0x02, 0x90, 0x00 }, 4);
        write_apdu(f, "> ", cmd2, cmd2_len);
        write_apdu(f, "< ", (const uint8_t[]){ 0x90, 0x00 }, 2);
        if (f) fclose(f);

        ok("the intermediate-block-with-data recording opens",
           rsp_replay_open(path, &t) == 0);
        ok("an intermediate block answering 9000 with a data field is -2 "
           "(a protocol violation), not -1 with *sw == 0x9000",
           rsp_es10_send(&t, big2, 256, &out, &out_len, &sw) == -2);
        ok("and nothing is handed back", out == NULL);
        ok("and *sw is the entry-reset 0, not the paradoxical 9000",
           sw == 0);
        t.close(&t);
    }

    /* A card that never terminates the chain must not hang the driver.
       This recording answers every GET RESPONSE with another 61xx and no
       data -- 300 times over, comfortably more than the bound
       src/rsp_es10.c enforces -- so if that bound did not exist, replay
       would happily keep answering past it; the failure below can only
       come from the bound itself, not from the recording running out. */
    {
        const char *path = "/tmp/rsp-apdu-unbounded.log";
        FILE *f = fopen(path, "w");
        if (f) {
            fputs("> 80E2910003BF220000\n< 6101\n", f);
            for (int i = 0; i < 300; i++) {
                fputs("> 00C0000001\n< 6101\n", f);
            }
            fclose(f);
        }

        ok("the never-ending recording opens", rsp_replay_open(path, &t) == 0);
        ok("a chain that never terminates fails instead of hanging",
           rsp_es10_send(&t, req, sizeof req, &out, &out_len, &sw) == -2);
        ok("and nothing is handed back", out == NULL);
        t.close(&t);
    }

    return fails ? 1 : 0;
}
