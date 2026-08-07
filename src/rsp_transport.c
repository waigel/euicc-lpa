/*
 * rsp_transport.c -- the transport interface (rsp_transport_t) and its two
 * built-in implementations: a replay transport that answers from a text
 * recording, and a recorder that wraps any other transport and writes one
 * down as it runs.
 *
 * The command layer above this (later tasks) sends and receives APDUs
 * through rsp_transport_t alone; it never knows whether the far end is a
 * physical reader or a file. That split is what lets the same command path
 * run in CI with no hardware attached.
 *
 * The recording format is deliberately plain text, not a binary capture:
 * a line beginning "> " is a command APDU in hex, a line beginning "< " is
 * the response including its two trailing status bytes, "#" and blank
 * lines are comments, and whitespace inside a hex line is insignificant.
 * That is what lets a recording be read in a code review, diffed
 * meaningfully, and hand-edited into the failure cases a healthy card will
 * not itself produce (a wrong status word, a truncated response, a
 * reordered exchange).
 *
 * A "< " line has one more shape besides hex: "< !-1" or "< !-2" records
 * that the exchange itself failed -- transceive returned that negative
 * value instead of a response, per include/rsp.h's failure convention --
 * rather than that the card answered with zero bytes. rsp_record_open
 * writes this marker whenever the transport it wraps returns negative,
 * and rsp_replay_open turns it straight back into the same negative
 * return, so a failure recorded during a live session (Task 5) replays
 * as the same failure, not as a fake zero-length success.
 *
 * The whole file is parsed at rsp_replay_open into a fixed array of
 * exchanges; nothing under transceive() allocates. A transport that could
 * fail to answer for a reason unrelated to the card (an allocation failing
 * mid-replay) would defeat the point of replaying at all.
 *
 * rsp_record_open writes a "#" header, below, as the first thing in every
 * file it creates -- ordinary comment lines by this same format's own
 * rule, so rsp_replay_open already skips them without any change; see the
 * header text itself for why it exists. A hand-written fixture (every one
 * under testdata/) has no such header and does not need one.
 *
 * Nothing in a recording is treated as secret in this round -- see
 * testdata/cards/README.md -- so mismatches are reported on stderr with
 * both the expected and the received bytes, and no buffer here is wiped.
 */
#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "lpa.h"

/* ---- shared hex helpers ------------------------------------------------ */

static int hex_digit(char c)
{
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

/* Decodes the hex digits in s[0..slen) (whitespace between them is
 * skipped, per the format's own rule) into a freshly malloc'ed buffer.
 * Returns 0, or -1 if that range holds anything other than whitespace and
 * hex digits, an odd number of digits, or the allocation fails. A
 * zero-digit line decodes to a valid, zero-length buffer (out set to a
 * one-byte allocation, *out_len 0) rather than NULL, so the caller can
 * always free() it uniformly.
 *
 * Takes an explicit length rather than reading to s's NUL: getline's own
 * length (what every call site here passes) is the true extent of the
 * line, and a line that happens to contain an embedded NUL byte before
 * that point must be rejected as unparseable, not silently truncated
 * there with everything past it dropped. */
static int parse_hexline(const char *s, size_t slen, uint8_t **out, size_t *out_len)
{
    size_t ndigits = 0;
    for (size_t i = 0; i < slen; i++) {
        if (isspace((unsigned char)s[i])) continue;
        if (hex_digit(s[i]) < 0) return -1;
        ndigits++;
    }
    if (ndigits % 2 != 0) return -1;

    size_t n = ndigits / 2;
    uint8_t *buf = malloc(n ? n : 1);
    if (!buf) return -1;

    size_t bi = 0;
    int hi = -1;
    for (size_t i = 0; i < slen; i++) {
        if (isspace((unsigned char)s[i])) continue;
        int v = hex_digit(s[i]);
        if (hi < 0) {
            hi = v;
        } else {
            buf[bi++] = (uint8_t)((hi << 4) | v);
            hi = -1;
        }
    }
    *out = buf;
    *out_len = n;
    return 0;
}

static void print_hex(FILE *f, const uint8_t *b, size_t n)
{
    for (size_t i = 0; i < n; i++) {
        fprintf(f, "%02X", b[i]);
    }
}

/* s/slen is a "< " line's content, already past the "< " prefix. Returns
 * 0 and sets *code if it is exactly the failure marker "!-1" or "!-2" (the
 * only two negative values include/rsp.h's convention allows). Returns -1
 * if it does not even start with '!' -- not a marker at all, so the
 * caller should try parsing it as hex instead. Returns -2 if it starts
 * with '!' but is not one of the two recognized markers, which the
 * caller should treat as unparseable rather than silently falling back to
 * hex (a stray '!' is never valid hex either, so there is no ambiguity to
 * preserve). */
static int parse_fail_marker(const char *s, size_t slen, long *code)
{
    if (slen == 0 || s[0] != '!') return -1;
    if (slen == 3 && s[1] == '-' && s[2] == '1') { *code = -1; return 0; }
    if (slen == 3 && s[1] == '-' && s[2] == '2') { *code = -2; return 0; }
    return -2;
}

/* ---- replay ------------------------------------------------------------- */

typedef struct {
    uint8_t *cmd;
    size_t   cmd_len;
    /* fail_code is 0 for an exchange that succeeded, in which case resp/
     * resp_len hold the recorded answer (resp non-NULL even when
     * resp_len is 0, so free() is always valid). Otherwise fail_code is
     * the negative value transceive returned instead of a response
     * (-1 or -2, include/rsp.h's convention), resp is NULL and resp_len
     * is 0: the "< !-1" / "< !-2" marker line, see the file header. */
    long     fail_code;
    uint8_t *resp;
    size_t   resp_len;
} rsp_exchange_t;

typedef struct {
    rsp_exchange_t *ex;
    size_t n;
    size_t pos;   /* index of the next exchange transceive() must match */
} rsp_replay_state_t;

static void free_exchanges(rsp_exchange_t *ex, size_t n)
{
    for (size_t i = 0; i < n; i++) {
        free(ex[i].cmd);
        free(ex[i].resp);
    }
    free(ex);
}

/* All three failures below are "we could not ask", not "the card said no",
 * so each returns -2 -- the same convention src/rsp_pcsc.c already applies
 * to a real transport's own could-not-happen cases (an unreachable reader,
 * a response too big for the caller's buffer). A recording running out, a
 * command not matching what was expected, and a response that would
 * overflow resp_cap are all cases where no card was ever actually asked
 * anything; -1 stays reserved for e->fail_code below, which passes through
 * whatever the ORIGINAL live exchange decided (see rsp_record_open) rather
 * than deciding anything itself. */
static long replay_transceive(rsp_transport_t *t, const uint8_t *cmd,
                              size_t cmd_len, uint8_t *resp, size_t resp_cap)
{
    rsp_replay_state_t *st = t->ctx;

    if (st->pos >= st->n) {
        fprintf(stderr,
            "rsp_replay: no recorded exchange left to answer command %zu "
            "(the recording has %zu)\n", st->pos, st->n);
        return -2;
    }

    rsp_exchange_t *e = &st->ex[st->pos];
    if (e->cmd_len != cmd_len || memcmp(e->cmd, cmd, cmd_len) != 0) {
        fprintf(stderr, "rsp_replay: exchange %zu: command does not match "
                         "the recording\n", st->pos);
        fprintf(stderr, "  expected: ");
        print_hex(stderr, e->cmd, e->cmd_len);
        fprintf(stderr, "\n  received: ");
        print_hex(stderr, cmd, cmd_len);
        fprintf(stderr, "\n");
        return -2;
    }

    if (e->fail_code != 0) {
        fprintf(stderr, "rsp_replay: exchange %zu: recorded as a failed "
                         "exchange (%ld)\n", st->pos, e->fail_code);
        st->pos++;
        return e->fail_code;
    }

    if (e->resp_len > resp_cap) {
        /* A caller-supplied buffer too small for the answer is exactly
         * src/rsp_pcsc.c's SCARD_E_INSUFFICIENT_BUFFER case, and that file
         * spells out why it is -2 rather than -1: resp_cap is this
         * function's own argument, not something the card was asked and
         * said "no" to. */
        fprintf(stderr, "rsp_replay: exchange %zu: recorded response is "
                         "%zu bytes, resp_cap is only %zu\n",
                st->pos, e->resp_len, resp_cap);
        return -2;
    }

    memcpy(resp, e->resp, e->resp_len);
    st->pos++;
    return (long)e->resp_len;
}

static void replay_close(rsp_transport_t *t)
{
    rsp_replay_state_t *st = t->ctx;
    if (!st) return;
    free_exchanges(st->ex, st->n);
    free(st);
    t->ctx = NULL;
}

int rsp_replay_open(const char *path, rsp_transport_t *out)
{
    if (!path || !out) return -2;

    FILE *f = fopen(path, "r");
    if (!f) return -2;

    rsp_exchange_t *ex = NULL;
    size_t n = 0, cap = 0;

    uint8_t *pending_cmd = NULL;
    size_t pending_cmd_len = 0;
    int have_cmd = 0;

    char *line = NULL;
    size_t linecap = 0;
    ssize_t got;
    int malformed = 0;

    while (!malformed && (got = getline(&line, &linecap, f)) != -1) {
        size_t len = (size_t)got;
        while (len > 0 && (line[len - 1] == '\n' || line[len - 1] == '\r')) {
            line[--len] = '\0';
        }

        if (len == 0 || line[0] == '#') {
            continue; /* blank or comment */
        }

        if (len >= 2 && line[0] == '>' && line[1] == ' ') {
            if (have_cmd) {
                fprintf(stderr, "rsp_replay_open: %s: two commands in a row "
                                 "with no response between them\n", path);
                malformed = 1;
                break;
            }
            if (parse_hexline(line + 2, len - 2, &pending_cmd, &pending_cmd_len) != 0) {
                fprintf(stderr, "rsp_replay_open: %s: unparseable command "
                                 "line: %s\n", path, line);
                malformed = 1;
                break;
            }
            have_cmd = 1;
        } else if (len >= 2 && line[0] == '<' && line[1] == ' ') {
            if (!have_cmd) {
                fprintf(stderr, "rsp_replay_open: %s: a response with no "
                                 "command before it\n", path);
                malformed = 1;
                break;
            }
            long fail_code = 0;
            uint8_t *resp = NULL;
            size_t resp_len = 0;
            int mret = parse_fail_marker(line + 2, len - 2, &fail_code);
            if (mret == -2) {
                fprintf(stderr, "rsp_replay_open: %s: unrecognized failure "
                                 "marker (only !-1 and !-2 exist): %s\n",
                        path, line);
                free(pending_cmd);
                malformed = 1;
                break;
            } else if (mret == -1) {
                /* not a marker; an ordinary hex response */
                if (parse_hexline(line + 2, len - 2, &resp, &resp_len) != 0) {
                    fprintf(stderr, "rsp_replay_open: %s: unparseable "
                                     "response line: %s\n", path, line);
                    free(pending_cmd);
                    malformed = 1;
                    break;
                }
            }
            if (n == cap) {
                size_t newcap = cap ? cap * 2 : 8;
                rsp_exchange_t *p = realloc(ex, newcap * sizeof *ex);
                if (!p) {
                    free(pending_cmd);
                    free(resp);
                    malformed = 1;
                    break;
                }
                ex = p;
                cap = newcap;
            }
            ex[n].cmd = pending_cmd;
            ex[n].cmd_len = pending_cmd_len;
            ex[n].fail_code = fail_code;
            ex[n].resp = resp;
            ex[n].resp_len = resp_len;
            n++;
            pending_cmd = NULL;
            have_cmd = 0;
        } else {
            fprintf(stderr, "rsp_replay_open: %s: a line is neither a "
                             "comment nor \"> \"/\"< \": %s\n", path, line);
            malformed = 1;
        }
    }
    free(line);
    fclose(f);

    if (!malformed && have_cmd) {
        fprintf(stderr, "rsp_replay_open: %s: a trailing command has no "
                         "response\n", path);
        free(pending_cmd);
        malformed = 1;
    }

    /* An empty file (or one holding only comments/blank lines) has
     * nothing wrong with it syntactically, but it is not a recording of
     * anything either -- there is no exchange for a first transceive()
     * call to answer. Read "cannot be parsed" to include "parsed to
     * nothing usable" rather than opening a transport that immediately,
     * and silently, refuses its very first call. */
    if (!malformed && n == 0) {
        fprintf(stderr, "rsp_replay_open: %s: no exchanges recorded\n", path);
        malformed = 1;
    }

    if (malformed) {
        free_exchanges(ex, n);
        return -2;
    }

    rsp_replay_state_t *st = malloc(sizeof *st);
    if (!st) {
        free_exchanges(ex, n);
        return -2;
    }
    st->ex = ex;
    st->n = n;
    st->pos = 0;

    out->transceive = replay_transceive;
    out->close = replay_close;
    out->ctx = st;
    return 0;
}

/* ---- record -------------------------------------------------------------
 *
 * Wraps any transport: forward the call, then append what happened to the
 * file in the same format rsp_replay_open reads, so recording a replayed
 * session and replaying the result again reproduces the original. */

typedef struct {
    rsp_transport_t inner;
    FILE *f;
} rsp_record_state_t;

static long record_transceive(rsp_transport_t *t, const uint8_t *cmd,
                              size_t cmd_len, uint8_t *resp, size_t resp_cap)
{
    rsp_record_state_t *st = t->ctx;
    /* rsp_record_open copies *inner by value (its own doc comment,
     * include/rsp.h), so a caller that passed a half-built rsp_transport_t
     * -- transceive left NULL -- reaches this call with no chance for
     * rsp_record_open itself to have caught it. src/rsp_pcsc.c's own
     * transceive checks its arguments the same defensive way; there is
     * nothing card-specific about it. */
    if (!st || !st->inner.transceive) return -2;

    long n = st->inner.transceive(&st->inner, cmd, cmd_len, resp, resp_cap);

    fprintf(st->f, "> ");
    print_hex(st->f, cmd, cmd_len);
    fprintf(st->f, "\n< ");
    if (n < 0) {
        /* The exchange itself failed -- write the marker rsp_replay_open
         * turns back into this same negative return, not a blank line
         * that would replay as a fake zero-length success. See the file
         * header and include/rsp.h's comment on rsp_record_open. */
        fprintf(st->f, "!%ld", n);
    } else if (n > 0) {
        print_hex(st->f, resp, (size_t)n);
    }
    fprintf(st->f, "\n");
    fflush(st->f);

    return n;
}

static void record_close(rsp_transport_t *t)
{
    rsp_record_state_t *st = t->ctx;
    if (!st) return;
    if (st->f) {
        fclose(st->f);
    }
    if (st->inner.close) {
        st->inner.close(&st->inner);
    }
    free(st);
    t->ctx = NULL;
}

/* Written as the first thing into every file rsp_record_open creates, as
 * ordinary "#" comment lines -- rsp_replay_open already skips those (see
 * this file's top comment), so no parser change was needed to make it
 * skippable; a recording with this header opens exactly like one without
 * it, and a recording made by hand (every fixture under testdata/) simply
 * never has it, which is fine, since nothing here requires it.
 *
 * It exists because a machine-produced recording is the one a person with
 * a problem actually sends: this round's are all read-only ES10 queries
 * and hold only public data (EID, version numbers, certificate issuer key
 * identifiers), but a recording of a WRITE session -- installing,
 * enabling, deleting a profile -- would carry protected material instead,
 * and nobody should paste one into an issue without a line in the file
 * itself saying so. */
static const char RECORDING_HEADER[] =
    "# A euicc-rsp session, recorded by rsp_record_open: one line per\n"
    "# direction, hex APDUs (see this project's src/rsp_transport.c for the\n"
    "# exact format). This is a log, not something to run.\n"
    "#\n"
    "# Whether this file is safe to share depends on what was asked of the\n"
    "# card during the session it captures, and this header cannot know\n"
    "# that in general -- a read-only query (EID, versions, key\n"
    "# identifiers) is public; a write session (installing, enabling,\n"
    "# deleting a profile) can carry protected material. Check what is\n"
    "# actually below before pasting this into an issue.\n";

int rsp_record_open(rsp_transport_t *inner, const char *path,
                    rsp_transport_t *out)
{
    if (!inner || !path || !out) return -2;

    FILE *f = fopen(path, "w");
    if (!f) return -2;

    if (fputs(RECORDING_HEADER, f) < 0) {
        fclose(f);
        return -2;
    }

    rsp_record_state_t *st = malloc(sizeof *st);
    if (!st) {
        fclose(f);
        return -2;
    }
    st->inner = *inner;
    st->f = f;

    out->transceive = record_transceive;
    out->close = record_close;
    out->ctx = st;
    return 0;
}
