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

    /* uiccCapability, EUICCInfo2's UICCCapability BIT STRING: what this
       card claims it can do, one bit per capability, the module's bit 0
       being the most significant bit of the first byte.
       uicc_capability_bits is how many bits the card actually declared. A
       card may send fewer than the module defines, and everything past
       the end is simply not claimed -- which is how an eUICC built to an
       older profile version says it has none of the capabilities the
       module has grown since. Read these through rsp_card_supports
       rather than directly. */
    uint8_t uicc_capability[8];
    size_t  uicc_capability_bits;
    int     have_uicc_capability;
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

/* Does this card claim capability `bit` of UICCCapability (rsp-2.5.asn's
   own bit numbering: contactlessSupport(0), usimSupport(1), ...,
   getIdentity(22), profile-a-x25519(23), profile-b-p256(24),
   suciCalculatorApi(25))?

   1 yes, 0 no, -1 the card said nothing this question could be put to --
   a null `i`, or an EUICCInfo2 that carried no uiccCapability at all.
   Unlike rsp_card_trusts above, "no" and "could not tell" are kept apart
   here, because they lead somewhere different: a capability a card
   declares it lacks is a reason to refuse a profile that requires it,
   while a card that declared nothing is a card this check cannot speak
   for, and refusing on that basis would turn silence into a verdict.

   A bit past the end of what the card declared is a 0, not a -1: a
   shorter BIT STRING is a complete answer that happens not to claim the
   capability, not a missing one. */
int rsp_card_supports(const rsp_card_info_t *i, unsigned bit);

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

/* Ask the eUICC for a challenge (ES10b GetEUICCChallenge, SGP.22 v2.6
   section 5.7.7). The card generates sixteen random bytes and signs them
   later, which is how it satisfies itself that the server answered this
   challenge rather than a recorded one.

   This is the one ES10 command in this header whose answer is meant to
   differ on every call. A recording replays whatever was captured, which
   is right for a replay -- the point is that a session's bytes are the
   ones actually exchanged -- but it means an assertion that two calls
   differ cannot be driven from one.

   Returns 0 with out filled. -1 when the card answered and refused, with
   *no_isdr set to 1 if the ISD-R selection itself was refused. -2 when
   the exchange could not happen or the answer could not be decoded. */
int rsp_card_get_challenge(rsp_transport_t *t, uint8_t out[16], int *no_isdr);

/* Delete a profile by ICCID (ES10c DeleteProfile, SGP.22 v2.6 section
   5.7.18). This is what makes an install repeatable: without it every
   attempt during development burns a slot.

   The card refuses an enabled profile -- 5.7.18 has the eUICC check the
   state and the Profile Policy Rules first and answer with an error
   rather than deleting. A freshly installed profile is disabled, so this
   reaches the case that matters; a profile that somehow becomes enabled
   cannot be removed with this alone.

   Returns 0 when the card answered ok(0). -1 when it answered and
   refused, with *result set to which refusal: iccidOrAidNotFound(1),
   profileNotInDisabledState(2), disallowedByPolicy(3) or
   undefinedError(127) (dist/DeleteProfileResponse.h). *result is left at
   0 on every other outcome, success included; read it only after -1.
   -2 when the exchange could not happen or the answer could not be
   decoded. no_isdr follows rsp_card_read_info's convention. */
int rsp_card_delete_profile(rsp_transport_t *t, const uint8_t iccid[10],
                            long *result, int *no_isdr);

/* The three exchanges whose request this library does not build.
   AuthenticateServer (SGP.22 v2.6 section 5.7.13) and PrepareDownload
   (section 5.7.5) carry a structure the SM-DP+ produced and signed; the
   LPA carries it to the card and the answer back, and must not alter a
   byte, because the card verifies exactly what was signed. GetEUICCInfo
   (section 5.7.8) has a fixed empty request but its answer goes into
   what the SM-DP+ signs, so it too is handed back encoded rather than
   decoded -- a decode-and-re-encode round trip is precisely the thing
   that changes a byte and breaks a signature for no visible reason.

   *out is malloc'ed and belongs to the caller on success. Returns 0, -1
   when the card answered and refused, -2 when the exchange could not
   happen. no_isdr follows rsp_card_read_info's convention. */
int rsp_card_authenticate_server(rsp_transport_t *t,
                                 const uint8_t *req, size_t req_len,
                                 uint8_t **out, size_t *out_len,
                                 int *no_isdr);
int rsp_card_prepare_download(rsp_transport_t *t,
                              const uint8_t *req, size_t req_len,
                              uint8_t **out, size_t *out_len,
                              int *no_isdr);
int rsp_card_get_info1(rsp_transport_t *t, uint8_t **out, size_t *out_len,
                       int *no_isdr);

/* End an RSP session on the card (ES10b CancelSession, SGP.22 v2.6
   section 5.7.14). This is the way out of a failed install: section
   5.5.1 has the eUICC reject InitialiseSecureChannel while a session is
   already ongoing, so without this one botched attempt blocks every
   later one. reason is a CancelSessionReason -- loadBppExecutionError(5)
   for a load that broke off, endUserRejection(0), postponed(1),
   timeout(2), pprNotAllowed(3), metadataMismatch(4), undefinedReason(127).

   The eUICC checks that transaction_id is the session it is holding and
   answers invalidTransactionId otherwise. So this cannot clear a session
   stranded by a crash: a fresh run does not know the id, and the card
   has to be re-seated instead.

   Returns 0, -1 when the card answered and refused, -2 otherwise. */
int rsp_card_cancel_session(rsp_transport_t *t,
                            const uint8_t transaction_id[16], long reason,
                            int *no_isdr);

/* Transfer a Bound Profile Package to the eUICC (ES10b
   LoadBoundProfilePackage, SGP.22 v2.6 section 5.7.6) with the
   segmentation section 2.5.5 requires.

   This is not "send the BPP in 255-byte chunks". Section 2.5.5 splits it
   along its own TLV structure -- the outer header with the
   InitialiseSecureChannel request, each sequence wrapper, each '88' and
   each '86' -- and, the rule easiest to miss, "at the beginning of each
   segment the block number of the STORE DATA commands SHALL be reset".
   A package sent with one running block counter is refused by the card
   without saying why.

   *out is malloc'ed and belongs to the caller: it is the Profile
   Installation Result the eUICC returned (section 2.5.6).

   Returns 0 when the card took the package and answered. **0 does not
   mean the install succeeded** -- the result itself says that, and the
   caller has to decode it. -1 when the card refused a block outright
   with a status word. -2 when the exchange could not happen, or the
   package's own lengths do not agree with its size. no_isdr follows
   rsp_card_read_info's convention.

   A load that breaks off leaves an RSP session open on the card, and
   section 5.5.1 has the eUICC reject the next InitialiseSecureChannel
   while one is ongoing. Call rsp_card_cancel_session with
   loadBppExecutionError(5) after a failure, or the next attempt cannot
   start. */
int rsp_card_load_bpp(rsp_transport_t *t, const uint8_t *bpp, size_t bpp_len,
                      uint8_t **out, size_t *out_len, int *no_isdr);

/* Install a profile: the whole eight-step exchange, card and SM-DP+
   alternating, in the order SGP.22 sections 3.1.2 and 3.1.3 fix. See
   src/lpa_install.c's own comment for the steps and why the order is
   forced rather than chosen.

   upp is an Unprotected Profile Package -- a profile in DER, what
   `euicc build` writes. metadata is an encoded StoreMetadataRequest
   (section 5.5.3): this library has no profile-order database to learn a
   profile's ICCID, name and provider from, so the caller supplies them.

   transaction_id and otsk_dp are inputs rather than values this function
   generates. Production passes fresh ones; a test passes fixed ones,
   which is what makes a recorded session replay byte for byte. There is
   no default, so there is no test path that can be shipped by accident.

   *result is malloc'ed and belongs to the caller: the eUICC's own
   ProfileInstallationResult (section 2.5.6).

   Returns 0 when the exchange completed and the card answered. **This
   does not mean the profile installed** -- the result says that, and the
   caller must decode it. -1 when the card or the server answered and
   refused. -2 when the exchange could not happen.

   *step, if not NULL, receives which of the eight steps was last
   attempted (1..8, or 0 if an argument was rejected before any). On a
   failure this is the difference between "the card would not talk to us"
   and "we built a package it would not take", which the return value
   alone cannot say.

   On any failure from step 3 onward this cancels the card's RSP session
   before returning, because section 5.5.1 has the eUICC reject the next
   InitialiseSecureChannel while one is ongoing. What it cannot clear is
   a session stranded by a crash: CancelSession needs the matching
   transactionId, which a fresh run does not know, and then the card has
   to be re-seated. */
int rsp_lpa_install(rsp_transport_t *t,
                    const uint8_t *upp, size_t upp_len,
                    const uint8_t *metadata, size_t metadata_len,
                    const uint8_t transaction_id[16],
                    const uint8_t otsk_dp[32],
                    uint8_t **result, size_t *result_len,
                    int *step, int *no_isdr);

#endif /* LPA_H */
