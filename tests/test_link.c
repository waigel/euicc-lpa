/* Does this library link, and does it reach both things it stands on? A
   build that compiles but resolves no euicc-rsp symbol, or that cannot
   see the generated codec, passes every other test in this suite -- because
   every other test would fail to build rather than fail to pass, and a
   missing binary is not a failing one. This is the floor. */
#include <stdio.h>
#include <string.h>

#include "lpa.h"
#include "rsp.h"
#include "EUICCInfo2.h"

/* The same macro the Makefile hands to src/lpa_version.c's build, folded
   into ALL_CFLAGS so every object here sees it. Comparing lpa_version()
   against it, rather than against a second hand-typed copy, is what makes
   this assertion able to fail when the two drift. */
#ifndef LPA_VERSION
#error "LPA_VERSION must be defined by the build"
#endif

static int fails = 0;
static void ok(const char *what, int cond) {
    printf("%s   %s\n", cond ? "ok  " : "FAIL", what);
    if(!cond) fails = 1;
}

int main(void) {
    ok("lpa_version() is not null", lpa_version() != NULL);
    ok("lpa_version() matches what the build compiled in",
       lpa_version() != NULL && strcmp(lpa_version(), LPA_VERSION) == 0);

    /* euicc-rsp resolves: a symbol from librsp.a, not from a header. */
    ok("euicc-rsp is linked in, not just included",
       rsp_version() != NULL && rsp_version()[0] != '\0');

    /* The generated codec resolves: a descriptor object, which lives in
       dist/EUICCInfo2.o and cannot be satisfied by a declaration alone. */
    ok("the generated codec is linked in",
       asn_DEF_EUICCInfo2.name != NULL
       && strcmp(asn_DEF_EUICCInfo2.name, "EUICCInfo2") == 0);

    return fails;
}
