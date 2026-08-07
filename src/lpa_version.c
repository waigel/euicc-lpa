/* The version, compiled in from the Makefile so there is exactly one copy
   of the string. tests/test_link.c pins this against the same macro. */
#include "lpa.h"

const char *lpa_version(void) { return LPA_VERSION; }
