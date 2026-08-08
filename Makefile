# euicc-lpa -- the LPA role of SGP.22 as a library.
#
#     make          the library
#     make check    the tests that need no reader
#     make check-card   the tests that need a real card in a reader
#     make record-card  capture a real session into a new testdata/cards fixture
#     make clean    everything the build produced
#
# This library stands on euicc-rsp for two things: its crypto and PKI
# (librsp.a), and its generated codec (dist/), which is produced from the
# whole of rsp-2.5.asn and serves both roles. euicc-lpa deliberately does
# NOT generate a second copy of that codec -- see the spec's "The generated
# codec is not duplicated" for why a third set of duplicate strong symbols
# would be worse than the two euicc-tools already reconciles.

.DELETE_ON_ERROR:

CC      ?= cc
CFLAGS  ?= -O2 -g
STD     := -std=c99
WARN    := -Wall -Wextra -Wno-unused-parameter \
           -Werror=implicit-function-declaration -Werror=int-conversion

VERSION := 0.1
RSP     := vendor/euicc-rsp
MBED    := $(RSP)/vendor/mbedtls
RSPDIST := $(RSP)/dist

# src/rsp_es10.c wipes a growbuf with mbedtls_platform_zeroize (see
# src/rsp_internal.h), so any test binary that links src/rsp_es10.o now
# needs these two archives too, the same pair euicc-rsp's own Makefile
# links tests against. Named directly on each link line below, not listed
# as a make prerequisite: $(RSP)/librsp.a already forces `make -C $(RSP)`,
# which builds these as a side effect (build/mbed.stamp, in euicc-rsp's
# Makefile) before this recipe runs, the same way $(RSPDIST)/*.o below is
# named in the recipe text rather than declared a prerequisite.
MBED_LIBS := $(MBED)/library/libmbedx509.a $(MBED)/library/libmbedcrypto.a

# -I$(RSP)/src is for rsp_internal.h, which holds only static inline
# helpers (rsp_growbuf_t, rsp_der_length_octets) that both sides of the
# repository split need. Copying it here would be a second implementation
# of one rule, which this project has already had to unpick once.
INC     := -Iinclude -Isrc -I$(RSP)/include -I$(RSP)/src -I$(MBED)/include
DEF     := -DLPA_VERSION='"$(VERSION)"'
EXTRA   := -D_DEFAULT_SOURCE
ifeq ($(shell uname -s),Darwin)
EXTRA   += -D_DARWIN_C_SOURCE
endif

ifeq ($(shell uname -s),Darwin)
PCSC_LIBS := -framework PCSC
else
PCSC_CFLAGS := $(shell pkg-config --cflags libpcsclite 2>/dev/null)
PCSC_LIBS   := $(shell pkg-config --libs libpcsclite 2>/dev/null || echo -lpcsclite)
endif

ALL_CFLAGS = $(STD) $(WARN) $(CFLAGS) $(EXTRA) $(INC) $(DEF) $(PCSC_CFLAGS)

SRCS := $(wildcard src/*.c)
OBJS := $(SRCS:.c=.o)
LIB  := liblpa.a

# Both headers against every object: every translation unit here reaches
# one or both, so listing them is an over-approximation, not a guess.
# Without it, touching include/lpa.h changes nothing make can see.
#
# Makefile itself is a prerequisite too: DEF and the rest of ALL_CFLAGS are
# compiled in, not read at run time, so an edit to a flag here is exactly
# as invisible to make as an edit to a header would be without the line
# above -- without this, "make" reuses an object built under the old
# flags and calls it current.
#
# This rule is also the first target GNU Make finds in this file, which
# would make it the default goal -- bare "make" would build only the
# first of $(OBJS) and stop, not the library "all" documents at the top.
# euicc-rsp's own Makefile hit the same shape once (see its comment on
# .DEFAULT_GOAL) and fixed it the same way: state the intended default
# goal explicitly, so file order stops deciding it by accident.
.DEFAULT_GOAL := all

$(OBJS): include/lpa.h $(RSP)/include/rsp.h Makefile

.PHONY: all
all: $(LIB)

# euicc-rsp's own Makefile decides whether anything is stale; ar only
# touches librsp.a's mtime when a member actually changed, so a build with
# nothing to do stays cheap.
.PHONY: rsp-force
rsp-force:

$(RSP)/librsp.a: rsp-force
	@test -e $(MBED)/.git || { \
	    echo "euicc-rsp's submodules are missing:" >&2; \
	    echo "  git -C $(RSP) submodule update --init --recursive" >&2; \
	    exit 1; }
	$(MAKE) -C $(RSP) $(if $(ASN1C),ASN1C="$(ASN1C)") $(if $(SKELDIR),SKELDIR="$(SKELDIR)")

# $(RSP)/librsp.a here, not just as a tests/run-% prerequisite: euicc-rsp's
# own Makefile generates dist/ (rsp_es10.c's EUICCInfo2.h and the rest) as
# a side effect of building librsp.a, and every object here compiles
# against that generated codec via -idirafter $(RSPDIST) below. Without
# this, "make" (or "make all") alone in a fresh checkout failed compiling
# src/rsp_es10.c on a missing generated header, because nothing had asked
# euicc-rsp to generate it yet -- only "make check" (whose tests/run-%
# rule already lists $(RSP)/librsp.a) happened to paper over the gap, by
# building the codec before linking a test, too late to help $(LIB) itself.
%.o: %.c $(RSP)/librsp.a
	$(CC) $(ALL_CFLAGS) -idirafter $(RSPDIST) -c $< -o $@

$(LIB): $(OBJS)
	ar rcs $@ $(OBJS)

# run-card needs a reader and is excluded from "make check" here, the same
# way euicc-rsp excludes its own.
TEST_SRCS  := $(wildcard tests/test_*.c)
TEST_BINS  := $(patsubst tests/test_%.c,tests/run-%,$(TEST_SRCS))
CHECK_BINS := $(filter-out tests/run-card,$(TEST_BINS))

# Makefile is a prerequisite on purpose: this recipe's own link line lives
# here, not in test_link.c, so make has no other way to notice that the
# line changed. GNU Make tracks prerequisite mtimes, not recipe text --
# without this, removing (or adding back) a library from the link line
# above leaves the already-built tests/run-% binary looking up to date,
# and "make check" silently re-runs the old binary instead of relinking.
# That is a mutation of the test proving nothing, not a passing test: see
# euicc-tools' Makefile, which takes the same precaution on "euicc" for
# the same reason (VERSION compiled in via -D).
tests/run-%: tests/test_%.c $(LIB) $(RSP)/librsp.a Makefile
	$(CC) $(ALL_CFLAGS) -idirafter $(RSPDIST) $< $(LIB) \
	    $(RSP)/librsp.a $(RSPDIST)/*.o $(MBED_LIBS) \
	    -o $@ $(PCSC_LIBS) -lm
	@# On Darwin, a -g link auto-generates a companion run-%.dSYM directory.
	@# tests/run-tests globs "run-*", so that bundle would be picked up and
	@# "run" as if it were a test binary. Drop it: it is a build byproduct,
	@# not a test. (Same fix as euicc-rsp's own Makefile.)
	@rm -rf $@.dSYM

.PHONY: check
check: $(CHECK_BINS)
	./tests/run-tests

.PHONY: check-card
check-card: tests/run-card
	./tests/run-card

# Captures a session against the real reader TWICE and only writes OUT if
# both agree, byte for byte. testdata/cards/README.md's own review found a
# live capture desync once in fourteen attempts on this project's shared
# rig -- SCardConnect in shared mode does not force a cold reset, so
# leftover state from whatever last touched the card can bleed into a
# capture. That is invisible by looking at the file afterward: a desynced
# recording still parses, still replays, and reads exactly like a good
# one, right up until it is trusted as ground truth for what the card
# actually said. Two independent captures agreeing is the cheapest check
# available that does not require a person to already know what the right
# answer looks like. Moved here from euicc-rsp with the rest of the card
# side: it captures through tests/run-card, which is built here now.
#
# OUT defaults to a scratch path under /tmp rather than committing anything
# by default -- this is a capture tool, not a promise that its result
# belongs in testdata/cards/. Point OUT at a real destination to keep one:
#   make record-card OUT=testdata/cards/card.log
OUT ?= /tmp/rsp-record-card.log

.PHONY: record-card
record-card: tests/run-card
	@out="$(OUT)"; \
	 tmp1=$$(mktemp) && tmp2=$$(mktemp) || exit 1; \
	 trap 'rm -f "$$tmp1" "$$tmp2"' EXIT; \
	 echo "record-card: capture 1/2..."; \
	 ./tests/run-card "$$tmp1" || { echo "record-card: first capture failed" >&2; exit 1; }; \
	 echo "record-card: capture 2/2..."; \
	 ./tests/run-card "$$tmp2" || { echo "record-card: second capture failed" >&2; exit 1; }; \
	 if ! cmp -s "$$tmp1" "$$tmp2"; then \
	     echo "record-card: the two captures do not agree -- not writing $$out" >&2; \
	     echo "record-card: (a shared reader can desync between passes;" >&2; \
	     echo "record-card:  see testdata/cards/README.md); try again" >&2; \
	     diff -u "$$tmp1" "$$tmp2" >&2 || true; \
	     exit 1; \
	 fi; \
	 mkdir -p "$$(dirname "$$out")"; \
	 cp "$$tmp1" "$$out"; \
	 echo "record-card: wrote $$out, confirmed by two agreeing captures"

.PHONY: clean
clean:
	rm -f $(OBJS) $(LIB) $(TEST_BINS)
