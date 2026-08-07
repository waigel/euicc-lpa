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

/* A transport carries APDUs and knows nothing else. */
typedef struct rsp_transport rsp_transport_t;
struct rsp_transport {
    /* Send one command APDU, receive one response APDU including its two
       status bytes. Returns the response length, -1 if the card answered
       something unusable (fewer than two bytes -- no room for a status
       word), -2 if the exchange could not happen at all: no reader or no
       recorded exchange to answer with, a command that does not match
       what a recording expects, or resp_cap too small for what came back
       -- the last one is -2 rather than -1 in every transport here
       (src/rsp_pcsc.c, src/rsp_transport.c's replay and record), because
       resp_cap is the caller's own argument, not something the card was
       asked and said no to. */
    long (*transceive)(rsp_transport_t *t, const uint8_t *cmd, size_t cmd_len,
                       uint8_t *resp, size_t resp_cap);
    void (*close)(rsp_transport_t *t);
    void *ctx;
};

/* A transport that answers from a recording. Returns 0, or -2 if the file
   cannot be read or parsed. */
int rsp_replay_open(const char *path, rsp_transport_t *out);

/* Wrap any transport so every exchange is appended to `path`. The wrapper
   takes ownership of `inner` and must itself be closed. Returns 0 or -2.

   The file opens with a "#" header explaining what it is and, since this
   function has no way to know whether the session it is about to capture
   is read-only or not, warning that a write session's recording can carry
   protected material -- see src/rsp_transport.c's own comment on
   RECORDING_HEADER for the exact text. rsp_replay_open skips it like any
   other comment.

   "Takes ownership" is literal, not a suggestion: rsp_record_open copies
   *inner's fields into the wrapper's own storage, and out->close calls
   the inner transport's close for you. Do not call inner->close yourself
   afterward -- the caller's original `inner` struct and the wrapper's
   copy of it both still point at the same underlying resource (the same
   ctx), so closing both is a double close/double free of whatever inner
   owns, not two independent releases. Close the wrapper (`out`) once,
   and treat the `inner` you passed in as consumed. */
int rsp_record_open(rsp_transport_t *inner, const char *path,
                    rsp_transport_t *out);

/* The transport that carries bytes to actual hardware, over PC/SC. See
   src/rsp_pcsc.c for the citation trail and the three failures a person
   actually hits when using it. */

/* Connect to a reader. `reader` names one, or is NULL to take the only one
   attached. Returns 0; -2 with a message on stderr when there is no reader,
   no card, or the card is held by another process. */
int rsp_pcsc_open(const char *reader, rsp_transport_t *out);

/* The attached readers, NUL-separated and terminated by an empty string.
   The caller frees. Returns the count, or -2. */
long rsp_pcsc_readers(char **out);

/* Send one ES10 request to the ISD-R and collect the whole answer, driving
   command chaining outward and 61xx/GET RESPONSE inward (SGP.22 v2.6
   section 5.7.2 -- see src/rsp_es10.c for the full citation trail). `req`
   is the DER of the request; `*out` is malloc'ed and belongs to the
   caller and holds the response without its status bytes. Returns 0;
   -1 when the card answered with a status other than 9000 or 61xx, with
   *sw set to that status, or when the transport itself already reported
   the answer as unusable (*sw left at 0: there is no status word for a
   transport-level -1 to carry); -2 when the exchange could not happen,
   or the chain would not terminate within this file's own bounds. */
int rsp_es10_send(rsp_transport_t *t, const uint8_t *req, size_t req_len,
                  uint8_t **out, size_t *out_len, unsigned *sw);

/* What a card says about itself, decoded from GetEUICCInfo2 (EUICCInfo2,
   SGP.22 v2.6 section 5.7.13) and GetEID (GetEuiccDataResponse, section
   5.7.11). Strings are NUL-terminated; ci_ids holds ci_count identifiers
   of ci_id_len bytes each, concatenated -- the Certificate Issuer
   SubjectKeyIdentifiers the card lists in euiccCiPKIdListForVerification,
   the ones rsp_card_trusts answers questions about. */
typedef struct {
    uint8_t eid[16];
    int     have_eid;
    char    svn[16];            /* "2.2.0" */
    uint8_t *ci_ids;            /* for verification */
    size_t   ci_count;
    size_t   ci_id_len;
} rsp_card_info_t;

/* Select the ISD-R, then read EUICCInfo2 and the EID. Returns 0, -1 if the
   card refused, -2 if it could not be asked.

   `no_isdr`, if not NULL, is set to 1 when a -1 happened at the very first
   step -- selecting the ISD-R itself came back refused (a real answer,
   commonly '6A82' or another SELECT-specific status, not a chain this
   function did not know how to follow) -- and left at 0 for every other
   outcome, including success and -2. That distinction is for a caller
   like euicc-tools' `card info`: an ISD-R that never answers at all reads
   very differently from a later ES10 request the ISD-R accepted and then
   refused -- the first says the card in the reader may not be an eUICC at
   all, or its ISD-R is locked; the second says it is one, and it said no
   to something specific asked of it. */
int rsp_card_read_info(rsp_transport_t *t, rsp_card_info_t *out, int *no_isdr);

/* Release an rsp_card_info_t obtained from rsp_card_read_info. Safe to call
   on a zeroed struct. Nothing here is secret (see testdata/cards/README.md,
   "What is safe to commit"), so there is no wipe. */
void rsp_card_info_free(rsp_card_info_t *i);

/* Does this card accept the issuer whose SubjectKeyIdentifier is `id`?
   Returns 1 for yes, 0 for no.

   This is the one function in this header where 0 is not "the question
   was asked and the answer is no" in the -1/-2 sense the rest of this
   file documents above -- there is no -1/-2 split here at all, only 1 and
   0. A null `i` or `id`, or an `id_len` that does not match this card's
   own identifier length, answers 0 too, indistinguishable from a real
   "this card does not trust that issuer." That is deliberate: a caller
   with no info to ask the question of has no card to be wrong about
   either, so collapsing "could not ask" into "no" costs nothing a caller
   could otherwise usefully act on differently -- but it does mean a 0
   here is not on its own proof that a real card was consulted and
   disagreed, the way an -1 elsewhere in this file is. */
int rsp_card_trusts(const rsp_card_info_t *i, const uint8_t *id, size_t id_len);

/* One profile as GetProfilesInfo lists it (ProfileInfo, SGP.22 v2.6
   section 5.7.15). Every member of the ASN.1 type is OPTIONAL, and a
   card is free to omit any of them for any profile -- so, the same way
   rsp_card_info_t's have_eid says whether the EID actually arrived, each
   field below that a card can plausibly omit has its own have_* flag
   set only when the card actually sent it; the field itself is left at
   0/NULL otherwise, never used to mean "absent" on its own. iconType and
   icon (up to 1024 bytes of image data, SGP.22's own SIZE bound) are not
   decoded here at all -- nothing in this struct represents them, and
   they are freed unread the same way rsp_card_select_isdr already
   discards a SELECT's FCI in src/rsp_es10.c -- a profile listing is not
   the place to hand back a kilobyte of icon per entry. Strings are
   malloc'ed, NUL-terminated, and owned by the struct. */
typedef struct {
    uint8_t iccid[10];
    int     have_iccid;

    uint8_t isdp_aid[16];
    size_t  isdp_aid_len;      /* 1..16 when have_isdp_aid; 0 otherwise */
    int     have_isdp_aid;

    long    profile_state;     /* ProfileState_disabled(0) / _enabled(1) */
    int     have_profile_state;

    char   *profile_nickname;        /* NULL if the card sent none */
    char   *service_provider_name;
    char   *profile_name;

    long    profile_class;     /* ProfileClass_test(0)/_provisioning(1)/_operational(2) */
    int     have_profile_class;
} rsp_profile_info_t;

/* Select the ISD-R, then ask for every installed profile
   (ProfileInfoListRequest with every member absent, SGP.22 v2.6 section
   5.7.15 -- an empty body asks for all of them, not none: 'BF2D 00' is
   that clause's own worked example of "retrieve the ProfileInfo for all
   installed Profiles"). *out is
   malloc'ed on success, an array of *out_count rsp_profile_info_t,
   released with rsp_card_profiles_free; a card with nothing installed
   answers 0 with *out_count == 0 and *out == NULL, a complete answer,
   not this function's failure to find anything.

   Returns 0, or:

   -1 when an answer came back and it is a refusal: the card sent
   ProfileInfoListError rather than the list. *err, if not NULL, is set
   to which one (ProfileInfoListError_incorrectInputValues == 1 or
   ProfileInfoListError_undefinedError == 127, dist/ProfileInfoListError.h)
   -- a caller that only needs the exit code can pass NULL and ignore the
   distinction, the same as rsp_card_read_info's no_isdr parameter. *err
   is left at 0 for every other outcome, including success; check it only
   after this function itself returns -1.

   -2 when the exchange could not happen, or the response arrived but
   could not be decoded as ProfileInfoListResponse, or as some ProfileInfo
   entry this struct cannot represent (an iccid whose length is not
   exactly 10, an isdpAid longer than isdp_aid can hold or of length 0,
   or an allocation failure) -- the same "cannot make sense of it" -2
   rsp_card_read_info already gives a non-uniform ci_ids list.

   no_isdr follows rsp_card_read_info's own convention exactly: set to 1
   when the very first step -- selecting the ISD-R -- is itself what
   refused (a -1 there, before ProfileInfoListRequest was ever sent), 0
   for every other outcome including success. Left untouched if NULL. */
int rsp_card_read_profiles(rsp_transport_t *t, rsp_profile_info_t **out,
                            size_t *out_count, long *err, int *no_isdr);

/* Release an array obtained from rsp_card_read_profiles: each entry's
   owned strings, then the array itself. Safe to call with profiles ==
   NULL (whether or not count is 0) and safe on a zeroed array. */
void rsp_card_profiles_free(rsp_profile_info_t *profiles, size_t count);

#endif /* LPA_H */
