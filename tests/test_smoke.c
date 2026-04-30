/* SPDX-License-Identifier: LGPL-3.0-or-later */
#include <libksuid/ksuid.h>
#include "test_util.h"

/* File-scope statics initialised from the public macros. The point of
 * this test pattern is that exactly this codepath -- aggregate
 * initialisation at static storage from a public sentinel -- is what
 * fails to compile on Windows DLL with the symbol form (issue #1). If
 * this TU compiles, KSUID_*_INIT works as a constant expression on
 * the target. The runtime memcmp below proves the bytes are right. */
static const ksuid_t kStaticNilInit = KSUID_NIL_INIT;
static const ksuid_t kStaticMaxInit = KSUID_MAX_INIT;

static void
test_constants_have_expected_layout (void)
{
  ASSERT_EQ_INT (KSUID_BYTES, 20);
  ASSERT_EQ_INT (KSUID_STRING_LEN, 27);
  ASSERT_EQ_INT (KSUID_PAYLOAD_LEN, 16);
  ASSERT_EQ_INT (KSUID_EPOCH_SECONDS, 1400000000LL);
  ASSERT_EQ_INT (sizeof (ksuid_t), KSUID_BYTES);
}

static void
test_nil_is_all_zero (void)
{
  static const uint8_t zero[KSUID_BYTES] = { 0 };
  ASSERT_EQ_BYTES (KSUID_NIL.b, zero, KSUID_BYTES);
  ASSERT_TRUE (ksuid_is_nil (&KSUID_NIL));
}

static void
test_max_is_all_ff (void)
{
  uint8_t ff[KSUID_BYTES];
  memset (ff, 0xff, sizeof ff);
  ASSERT_EQ_BYTES (KSUID_MAX.b, ff, KSUID_BYTES);
  ASSERT_FALSE (ksuid_is_nil (&KSUID_MAX));
}

static void
test_compare_orders_lex (void)
{
  ASSERT_TRUE (ksuid_compare (&KSUID_NIL, &KSUID_MAX) < 0);
  ASSERT_TRUE (ksuid_compare (&KSUID_MAX, &KSUID_NIL) > 0);
  ASSERT_EQ_INT (ksuid_compare (&KSUID_NIL, &KSUID_NIL), 0);
  ASSERT_EQ_INT (ksuid_compare (&KSUID_MAX, &KSUID_MAX), 0);
}

static void
test_compare_first_byte_dominates (void)
{
  ksuid_t a = KSUID_NIL, b = KSUID_NIL;
  a.b[0] = 0x01;
  b.b[19] = 0xff;
  ASSERT_TRUE (ksuid_compare (&a, &b) > 0);
  ASSERT_TRUE (ksuid_compare (&b, &a) < 0);
}

static void
test_init_macros_match_symbols (void)
{
  /* File-scope statics: the codepath that fails on Windows DLL today.
   * Byte-for-byte parity with the runtime symbols proves the macros
   * encode the right constants. */
  ASSERT_EQ_BYTES (kStaticNilInit.b, KSUID_NIL.b, KSUID_BYTES);
  ASSERT_EQ_BYTES (kStaticMaxInit.b, KSUID_MAX.b, KSUID_BYTES);
  ASSERT_TRUE (ksuid_is_nil (&kStaticNilInit));

  /* Block-scope static storage: distinct codepath from file scope on
   * some compilers, worth pinning separately. */
  static const ksuid_t local_nil = KSUID_NIL_INIT;
  static const ksuid_t local_max = KSUID_MAX_INIT;
  ASSERT_TRUE (ksuid_is_nil (&local_nil));
  ASSERT_EQ_BYTES (local_max.b, KSUID_MAX.b, KSUID_BYTES);
}

static void
test_version_macros_are_consistent (void)
{
  /* DELIBERATE SYNC POINT: these literal values must equal the
   * `version :` field in the top-level meson.build. The test exists
   * to prove that meson.project_version() flows through the
   * configure_file substitution into ksuid_version.h.in -- a
   * `>= 0` check would silently accept an empty @VERSION_MAJOR@
   * substitution that the C preprocessor turns into 0. A real
   * regression in the substitution chain therefore fails here.
   *
   * When you bump meson.build's project version you MUST update
   * these four asserts in the same commit. */
  ASSERT_EQ_INT (KSUID_VERSION_MAJOR, 0);
  ASSERT_EQ_INT (KSUID_VERSION_MINOR, 1);
  ASSERT_EQ_INT (KSUID_VERSION_PATCH, 0);
  ASSERT_EQ_STR (KSUID_VERSION_STRING, "0.1.0");

  /* The composite KSUID_VERSION must equal the documented
   * (MAJOR << 16) | (MINOR << 8) | PATCH layout for `#if
   * KSUID_VERSION >= ...` arithmetic to behave the way callers
   * expect. */
  int composed = (KSUID_VERSION_MAJOR << 16)
      | (KSUID_VERSION_MINOR << 8)
      | (KSUID_VERSION_PATCH);
  ASSERT_EQ_INT (KSUID_VERSION, composed);
}

int
main (void)
{
  RUN_TEST (test_constants_have_expected_layout);
  RUN_TEST (test_nil_is_all_zero);
  RUN_TEST (test_max_is_all_ff);
  RUN_TEST (test_compare_orders_lex);
  RUN_TEST (test_compare_first_byte_dominates);
  RUN_TEST (test_init_macros_match_symbols);
  RUN_TEST (test_version_macros_are_consistent);
  TEST_MAIN_END ();
}
