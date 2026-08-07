# euicc-lpa -- the LPA role of SGP.22 as a library.
#
#     make          the library
#     make check    the tests that need no reader
#     make check-card   the tests that need a real card in a reader
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
$(OBJS): include/lpa.h $(RSP)/include/rsp.h

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

%.o: %.c
	$(CC) $(ALL_CFLAGS) -idirafter $(RSPDIST) -c $< -o $@

$(LIB): $(OBJS)
	ar rcs $@ $(OBJS)

# run-card needs a reader and is excluded from "make check" here, the same
# way euicc-rsp excludes its own.
TEST_SRCS  := $(wildcard tests/test_*.c)
TEST_BINS  := $(patsubst tests/test_%.c,tests/run-%,$(TEST_SRCS))
CHECK_BINS := $(filter-out tests/run-card,$(TEST_BINS))

tests/run-%: tests/test_%.c $(LIB) $(RSP)/librsp.a
	$(CC) $(ALL_CFLAGS) -idirafter $(RSPDIST) $< $(LIB) \
	    $(RSP)/librsp.a $(RSPDIST)/*.o \
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

.PHONY: clean
clean:
	rm -f $(OBJS) $(LIB) $(TEST_BINS)
