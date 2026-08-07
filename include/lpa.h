/*
 * lpa.h -- the LPA role of SGP.22, as a library.
 *
 * The LPA sits between an eUICC and an RSP server. This library holds the
 * card side of that: a transport that carries APDUs over a real reader,
 * over a text recording, or over a wrapper that writes one; the ES10
 * command layer on top of it; and the read-only commands a card answers
 * without a secure channel.
 *
 * It stands on euicc-rsp (vendor/euicc-rsp) for crypto, PKI and the
 * generated ASN.1 codec, which is produced from the whole RSP module and
 * belongs to neither role in particular.
 */
#ifndef LPA_H
#define LPA_H

#include <stddef.h>
#include <stdint.h>

/* The library version, for a bug report. */
const char *lpa_version(void);

#endif /* LPA_H */
