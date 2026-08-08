/*
 * rsp_pcsc.c -- the transport that carries bytes to actual hardware, PC/SC.
 *
 * PC/SC (PC/Smart Card, the interface both macOS and Linux expose under the
 * same function names, winscard.h) is the one place in this library that
 * touches a card reader instead of a recording. It implements the same
 * rsp_transport_t the replay transport (src/rsp_transport.c) does, and
 * nothing above this file -- rsp_es10_send, rsp_card_read_info, the command
 * layer later tasks build -- can tell the two apart.
 *
 * macOS ships PC/SC as a framework: <PCSC/winscard.h> and <PCSC/wintypes.h>,
 * linked with -framework PCSC. Linux has no PC/SC of its own; pcsc-lite is
 * the interface's reference implementation there, and its single header is
 * plain <winscard.h> (it already pulls in pcsclite.h, which is where
 * wintypes.h's macOS split lives on that side). The two are not textually
 * identical, but they define the same names -- SCARDCONTEXT, SCardConnect,
 * SCARD_PCI_T0, and so on -- so everything past this #if is written once.
 *
 * PC/SC's own functions return a signed LONG; every nonzero value is a
 * failure and SCARD_S_SUCCESS (0) is the only success. This file only ever
 * surfaces two of the numbers lpa.h defines: 0 for done, and -2 for "the
 * exchange could not happen" -- transceive's own -1 ("the card answered
 * something unusable") is reserved for an answer that arrived and made no
 * sense, which is not something PC/SC's return code, only the response
 * bytes, could ever tell us. Every failure here also prints a sentence:
 * pcsc_stringify_error's own text for the ones this file has no more to
 * say about, and a hand-written one for the three failures a person
 * actually hits -- no reader attached, a reader with an empty tray, and
 * another process already holding the card (SCARD_E_SHARING_VIOLATION),
 * which on macOS is almost always the system's own card services, not
 * this program's fault at all.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#if defined(__APPLE__)
#include <PCSC/winscard.h>
#include <PCSC/wintypes.h>
#else
#include <winscard.h>
#endif

#include "lpa.h"

typedef struct {
    SCARDCONTEXT ctx;
    SCARDHANDLE  card;
    DWORD        protocol;   /* SCARD_PROTOCOL_T0 or _T1, whichever SCardConnect settled on */
} rsp_pcsc_state_t;

/* SCardListReaders' own multi-string: names separated by one NUL, the
 * whole list terminated by a second (an empty final name). Walked the
 * same way in rsp_pcsc_readers, rsp_pcsc_open below and tests/test_card.c.
 *
 * Called with ctx already established. *out is malloc'ed and always set
 * on success -- to a one-byte "\0" when no reader is attached, not left
 * NULL, so the caller can always free() it uniformly. Returns the count
 * of names, or -2 with a message on stderr. */
static long pcsc_list(SCARDCONTEXT ctx, char **out)
{
    *out = NULL;

    DWORD needed = 0;
    LONG rv = SCardListReaders(ctx, NULL, NULL, &needed);
    if (rv == (LONG)SCARD_E_NO_READERS_AVAILABLE || (rv == SCARD_S_SUCCESS && needed == 0)) {
        char *empty = malloc(1);
        if (!empty) return -2;
        empty[0] = '\0';
        *out = empty;
        return 0;
    }
    if (rv != SCARD_S_SUCCESS) {
        fprintf(stderr, "rsp_pcsc: cannot list readers: %s\n", pcsc_stringify_error(rv));
        return -2;
    }

    char *buf = malloc(needed);
    if (!buf) return -2;

    DWORD got = needed;
    rv = SCardListReaders(ctx, NULL, buf, &got);
    if (rv != SCARD_S_SUCCESS) {
        fprintf(stderr, "rsp_pcsc: cannot list readers: %s\n", pcsc_stringify_error(rv));
        free(buf);
        return -2;
    }

    long count = 0;
    for (const char *p = buf; *p; p += strlen(p) + 1) count++;
    *out = buf;
    return count;
}

long rsp_pcsc_readers(char **out)
{
    if (!out) return -2;
    *out = NULL;

    SCARDCONTEXT ctx;
    LONG rv = SCardEstablishContext(SCARD_SCOPE_SYSTEM, NULL, NULL, &ctx);
    if (rv != SCARD_S_SUCCESS) {
        fprintf(stderr, "rsp_pcsc: cannot reach the system's smart card "
                         "service: %s\n", pcsc_stringify_error(rv));
        return -2;
    }

    long n = pcsc_list(ctx, out);
    SCardReleaseContext(ctx);
    return n;
}

static long pcsc_transceive(rsp_transport_t *t, const uint8_t *cmd,
                            size_t cmd_len, uint8_t *resp, size_t resp_cap)
{
    rsp_pcsc_state_t *st = t->ctx;
    if (!st || !cmd || !resp) return -2;
    /* DWORD is 32 bits; no caller of this library ever builds a command
     * or a response buffer anywhere near that size, but a silent
     * truncation of cmd_len on the way into SCardTransmit would be worse
     * than refusing outright. */
    if (cmd_len > 0xFFFFFFFFu || resp_cap > 0xFFFFFFFFu) return -2;

    LPCSCARD_IO_REQUEST pci = (st->protocol == SCARD_PROTOCOL_T1) ? SCARD_PCI_T1 : SCARD_PCI_T0;

    DWORD recv_len = (DWORD)resp_cap;
    LONG rv = SCardTransmit(st->card, pci, cmd, (DWORD)cmd_len, NULL, resp, &recv_len);
    if (rv != SCARD_S_SUCCESS) {
        if (rv == (LONG)SCARD_W_REMOVED_CARD) {
            fprintf(stderr, "rsp_pcsc: the card was removed mid-exchange\n");
        } else if (rv == (LONG)SCARD_E_NO_SMARTCARD) {
            fprintf(stderr, "rsp_pcsc: the reader is there, but the card in "
                             "it is gone\n");
        } else if (rv == (LONG)SCARD_E_SHARING_VIOLATION) {
            fprintf(stderr, "rsp_pcsc: another process holds the card; on "
                             "macOS this is usually the system's own card "
                             "services\n");
        } else if (rv == (LONG)SCARD_E_INSUFFICIENT_BUFFER) {
            /* Still -2, not -1: resp_cap is this function's own argument,
             * not something the card said "no" to, so this is closer to
             * "the exchange could not happen as asked" than to "the card
             * answered and made no sense." */
            fprintf(stderr, "rsp_pcsc: the card's answer did not fit the "
                             "buffer given to it\n");
        } else {
            fprintf(stderr, "rsp_pcsc: the exchange failed: %s\n", pcsc_stringify_error(rv));
        }
        return -2;
    }

    /* An APDU response always carries its two status bytes; anything
     * shorter is not a response this transport can hand back as one --
     * lpa.h's -1, an answer that arrived but made no sense, not this
     * function's -2. */
    if (recv_len < 2) return -1;
    return (long)recv_len;
}

/* Walks an ATR's interface bytes (ISO/IEC 7816-3) far enough to say which
 * transmission protocols the card itself offers, without ever connecting
 * to it -- SCardGetStatusChange (rsp_pcsc_open, below) hands back the ATR
 * for free, cached by the reader, before any SCardConnect is attempted.
 *
 * atr[0] is TS. atr[1] is T0: its high nibble Y1 says which of
 * TA1/TB1/TC1/TD1 follow; TD1, if present, both says which of
 * TA2/TB2/TC2/TD2 follow AND carries a protocol number in its own low
 * nibble, and so on for TD2, TD3... -- each TDi both continues the walk
 * and announces one more offered protocol, except for one reserved value:
 * a low nibble of 15 is not a protocol at all, it is ISO 7816-3's marker
 * that the NEXT group is "global interface bytes" (clock-stop, class
 * indicator) rather than protocol parameters. A walk that read T=15 as an
 * offered protocol would go on to ask SCardConnect for a protocol number
 * that means something else entirely on the wire. If TD1 is absent, the
 * card offers T=0 alone -- ISO 7816-3's own default, never spelled out in
 * the bytes at all.
 *
 * Returns a bitmask, bit 0 for "offers T=0" and bit 1 for "offers T=1"
 * (a card can set both). Returns 0 if the ATR is too short to say
 * anything, or runs out of bytes partway through the walk with nothing
 * decided yet -- the caller reads a 0 as "unknown," not as "the card
 * offers nothing," and falls back accordingly. */
static unsigned atr_protocol_mask(const unsigned char *atr, unsigned len)
{
    if (len < 2) return 0;

    unsigned mask = 0;
    unsigned pos = 2;              /* atr[0] TS, atr[1] T0 already read */
    unsigned y = (unsigned)(atr[1] >> 4);
    int have_td = 0;

    for (;;) {
        if (y & 0x1) {              /* TAi present */
            if (pos >= len) return mask;
            pos++;
        }
        if (y & 0x2) {              /* TBi present */
            if (pos >= len) return mask;
            pos++;
        }
        if (y & 0x4) {              /* TCi present */
            if (pos >= len) return mask;
            pos++;
        }
        if (!(y & 0x8)) {           /* no TDi: the walk ends here */
            break;
        }
        if (pos >= len) return mask;
        unsigned char td = atr[pos++];
        unsigned t = (unsigned)(td & 0x0F);
        have_td = 1;
        if (t <= 1) {
            mask |= (1u << t);
        }
        /* t == 15: the global-interface-bytes marker, not a protocol --
         * deliberately not added to mask. Any other value is a protocol
         * this walk does not know how to request either, so it is also
         * left out of mask; the caller's fallback path covers both. */
        y = (unsigned)(td >> 4);
    }

    if (!have_td) {
        mask |= 1u;                 /* no TD1 at all: T=0, implicitly */
    }
    return mask;
}

static void pcsc_close(rsp_transport_t *t)
{
    rsp_pcsc_state_t *st = t->ctx;
    if (!st) return;
    SCardDisconnect(st->card, SCARD_LEAVE_CARD);
    SCardReleaseContext(st->ctx);
    free(st);
    t->ctx = NULL;
}

int rsp_pcsc_open(const char *reader, rsp_transport_t *out)
{
    if (!out) return -2;

    SCARDCONTEXT ctx;
    LONG rv = SCardEstablishContext(SCARD_SCOPE_SYSTEM, NULL, NULL, &ctx);
    if (rv != SCARD_S_SUCCESS) {
        /* Whatever is down -- pcscd, the macOS daemon, the whole stack --
         * this is the one SCardEstablishContext a caller-supplied reader
         * name actually reaches (rsp_pcsc_readers' own call, above, never
         * sees a reader argument at all). "The service is unreachable" is
         * still the honest diagnosis: naming the reader on top of it, when
         * one was asked for, does not paper over that, it just means a
         * caller who named a reader hears the name back too, instead of a
         * message that looks -- to a test, or to a person -- like it
         * forgot what was asked. */
        if (reader) {
            fprintf(stderr, "rsp_pcsc: cannot reach the system's smart card "
                             "service (asked for reader \"%s\"): %s\n",
                             reader, pcsc_stringify_error(rv));
        } else {
            fprintf(stderr, "rsp_pcsc: cannot reach the system's smart card "
                             "service: %s\n", pcsc_stringify_error(rv));
        }
        return -2;
    }

    char *list = NULL;
    const char *use = reader;
    if (!use) {
        long n = pcsc_list(ctx, &list);
        if (n < 0) {
            SCardReleaseContext(ctx);
            return -2;
        }
        if (n == 0) {
            /* reader is NULL on every path that reaches here (use == reader,
             * and this whole block is guarded by !use), so this always takes
             * the "no name at all" wording below -- but it is written to
             * check reader rather than assume that, so this branch and the
             * SCARD_E_UNKNOWN_READER/SCARD_E_NO_READERS_AVAILABLE one in the
             * SCardConnect failure path below say the same thing the same
             * way, rather than one of the two silently drifting if either is
             * ever reached from a changed caller. */
            if (reader) {
                fprintf(stderr, "rsp_pcsc: no reader named \"%s\" is attached\n", reader);
            } else {
                fprintf(stderr, "rsp_pcsc: no reader is attached\n");
            }
            free(list);
            SCardReleaseContext(ctx);
            return -2;
        }
        if (n > 1) {
            fprintf(stderr, "rsp_pcsc: more than one reader is attached; "
                             "name the one to use\n");
            free(list);
            SCardReleaseContext(ctx);
            return -2;
        }
        use = list;   /* the sole name, NUL-terminated */
    }

    /* SCARD_PROTOCOL_T0|SCARD_PROTOCOL_T1 is the right request to make --
     * it asks PC/SC to negotiate whichever protocol the card actually
     * supports, and it is what every portable PC/SC client sends. But at
     * least one real combination (an OMNIKEY AG Smart Card Reader USB on
     * macOS, confirmed against real hardware, not a guess) answers that
     * combined request with SCARD_W_UNRESPONSIVE_CARD even though the
     * exact same card connects fine when asked for T0 alone -- the stack
     * mishandles the combined request, not the request itself, and there
     * is nothing on this side of the interface that makes that go away.
     * Measured cold (the card left idle ~90s, nothing else asked of it
     * since): the combined request takes just over 18 seconds to fail
     * that way before anything gets a chance to retry.
     *
     * SCardGetStatusChange does not have this cost -- it never talks to
     * the card at all, only to the reader's own cached notion of what is
     * inserted, and it hands back the ATR as part of that. So: read the
     * ATR first, with a zero timeout (asks for the current state, does
     * not wait for a change), and use atr_protocol_mask to work out which
     * single protocol the card itself is offering. When that comes back
     * as exactly one protocol, ask for that one directly, first --
     * skipping the doomed combined attempt entirely rather than paying
     * for it and then falling back. When the ATR could not be read, could
     * not be parsed, or genuinely offers both protocols, there is no
     * reason yet to expect the combined request to fail, so it is still
     * asked for first, unchanged from before.
     *
     * Either way, the original try-each-protocol sequence stays as the
     * net: if the ATR's own answer turns out to be wrong for some reason
     * this walk did not anticipate, or the ATR was unreadable to begin
     * with, every protocol still gets tried in turn before this function
     * gives up. A silent fallback that happens to work is only marginally
     * better than a loud failure that does not -- either way the next
     * person has no way to tell what actually happened -- so every
     * attempt after the first, and the protocol that ultimately got
     * negotiated, is reported on stderr. If every attempt fails, the
     * error reported and returned is the first attempt's: whichever
     * request was tried first is the one whose failure is actually
     * diagnostic, where "protocol mismatch" from a later retry is not
     * telling you anything you did not already ask for. */
    unsigned atr_mask = 0;
    {
        SCARD_READERSTATE rs;
        memset(&rs, 0, sizeof rs);
        rs.szReader = use;
        rs.dwCurrentState = SCARD_STATE_UNAWARE;
        if (SCardGetStatusChange(ctx, 0, &rs, 1) == SCARD_S_SUCCESS) {
            atr_mask = atr_protocol_mask(rs.rgbAtr, rs.cbAtr);
        }
    }

    static const DWORD fallback_protocols[] = {
        SCARD_PROTOCOL_T0 | SCARD_PROTOCOL_T1,
        SCARD_PROTOCOL_T0,
        SCARD_PROTOCOL_T1,
    };
    static const char *const fallback_names[] = { "T0|T1", "T0", "T1" };

    DWORD protocols[4];
    const char *protocol_names[4];
    size_t n_protocols = 0;

    if (atr_mask == 1u || atr_mask == 2u) {
        protocols[n_protocols] = (atr_mask == 1u) ? SCARD_PROTOCOL_T0 : SCARD_PROTOCOL_T1;
        protocol_names[n_protocols] = (atr_mask == 1u) ? "T0" : "T1";
        n_protocols++;
    }
    for (size_t i = 0; i < sizeof fallback_protocols / sizeof fallback_protocols[0]; i++) {
        if (n_protocols > 0 && fallback_protocols[i] == protocols[0]) {
            continue;   /* already the ATR's own first choice, above */
        }
        protocols[n_protocols] = fallback_protocols[i];
        protocol_names[n_protocols] = fallback_names[i];
        n_protocols++;
    }

    SCARDHANDLE card;
    DWORD active_protocol = 0;
    LONG first_rv = SCARD_S_SUCCESS;
    size_t connected_at = (size_t)-1;
    for (size_t i = 0; i < n_protocols; i++) {
        rv = SCardConnect(ctx, use, SCARD_SHARE_SHARED, protocols[i],
                          &card, &active_protocol);
        if (i == 0) first_rv = rv;
        if (rv == SCARD_S_SUCCESS) {
            connected_at = i;
            break;
        }
    }

    if (connected_at == (size_t)-1) {
        rv = first_rv;   /* the first attempt's failure is the diagnostic one */
        if (rv == (LONG)SCARD_E_NO_SMARTCARD) {
            fprintf(stderr, "rsp_pcsc: the reader is there, but no card is "
                             "in it\n");
        } else if (rv == (LONG)SCARD_E_SHARING_VIOLATION) {
            fprintf(stderr, "rsp_pcsc: another process holds the card; on "
                             "macOS this is usually the system's own card "
                             "services -- close whatever else has it open "
                             "and try again\n");
        } else if (rv == (LONG)SCARD_E_UNKNOWN_READER || rv == (LONG)SCARD_E_NO_READERS_AVAILABLE) {
            /* A caller-named reader skips pcsc_list entirely above (use ==
             * reader, unexamined) and goes straight to SCardConnect with
             * that exact name -- so when it cannot be provided, PC/SC's
             * answer depends on whether its reader table is empty at that
             * moment (SCARD_E_NO_READERS_AVAILABLE) or holds readers, just
             * not this one (SCARD_E_UNKNOWN_READER). Both mean the same
             * thing to whoever typed the name: it is not attached, whether
             * because nothing is or because something else is. Collapsing
             * them into one message, naming the reader, is what keeps this
             * answer true on a desk with hardware and in CI with none --
             * a message that only fires on one of the two PC/SC codes reads
             * differently depending on which environment happens to run it,
             * which is exactly the defect this fixes. */
            if (reader) {
                fprintf(stderr, "rsp_pcsc: no reader named \"%s\" is attached\n", reader);
            } else {
                fprintf(stderr, "rsp_pcsc: no reader is attached\n");
            }
        } else {
            fprintf(stderr, "rsp_pcsc: cannot connect to the card: %s\n", pcsc_stringify_error(rv));
        }
        free(list);
        SCardReleaseContext(ctx);
        return -2;
    }

    if (connected_at > 0) {
        /* Only worth a line when the fallback actually fired: this is
         * exactly the moment the negotiated protocol is diagnostic, not
         * routine chatter on every ordinary open (rsp_replay_open and
         * rsp_record_open say nothing on success either). */
        fprintf(stderr, "rsp_pcsc: asking for %s failed (%s); fell back "
                         "to asking for %s alone -- connected, negotiated "
                         "protocol %s\n",
                protocol_names[0], pcsc_stringify_error(first_rv),
                protocol_names[connected_at],
                active_protocol == SCARD_PROTOCOL_T1 ? "T=1" : "T=0");
    }
    free(list);

    rsp_pcsc_state_t *st = malloc(sizeof *st);
    if (!st) {
        SCardDisconnect(card, SCARD_LEAVE_CARD);
        SCardReleaseContext(ctx);
        return -2;
    }
    st->ctx = ctx;
    st->card = card;
    st->protocol = active_protocol;

    out->transceive = pcsc_transceive;
    out->close = pcsc_close;
    out->ctx = st;
    return 0;
}
