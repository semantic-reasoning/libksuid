/* SPDX-License-Identifier: LGPL-3.0-or-later
 *
 * Companion to test_smoke.c that links against the libksuid SHARED
 * library rather than the static archive. This is the Windows DLL
 * consumer scenario in miniature: KSUID_PUBLIC expands to
 * __declspec(dllimport) here (because KSUID_BUILDING is undefined for
 * this TU), and KSUID_NIL / KSUID_MAX are therefore *not* constant
 * expressions in this translation unit. If the build of this file
 * succeeds, the public KSUID_*_INIT macros really do work as static-
 * storage initialisers under the same constraints downstream
 * consumers will face. The test then memcmp's against the symbols
 * to prove the bytes match.
 *
 * This file exists because tests/test_smoke.c links the static
 * archive (KSUID_BUILDING is in scope, no dllimport, the symbol is a
 * normal const) and so does NOT exercise the very codepath issue #1
 * was filed about. */

#include <libksuid/ksuid.h>
#include "test_util.h"

/* File-scope static storage from the macro form. On Windows DLL
 * consumers the equivalent `static const ksuid_t g = KSUID_NIL;`
 * fails with C2099 "initializer is not a constant" -- that is the
 * regression we are guarding against. */
static const ksuid_t kSharedNilInit = KSUID_NIL_INIT;
static const ksuid_t kSharedMaxInit = KSUID_MAX_INIT;

static void
test_macros_at_static_storage_match_shared_symbols (void)
{
  /* If KSUID_NIL / KSUID_MAX really are dllimport on this build (the
   * Windows lane) the runtime symbol resolution lands here at
   * comparison time, after the file-scope statics above were already
   * frozen at load time from the macro values. */
  ASSERT_EQ_BYTES (kSharedNilInit.b, KSUID_NIL.b, KSUID_BYTES);
  ASSERT_EQ_BYTES (kSharedMaxInit.b, KSUID_MAX.b, KSUID_BYTES);
  ASSERT_TRUE (ksuid_is_nil (&kSharedNilInit));
}

int
main (void)
{
  RUN_TEST (test_macros_at_static_storage_match_shared_symbols);
  TEST_MAIN_END ();
}
