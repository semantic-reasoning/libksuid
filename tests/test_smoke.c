/* SPDX-License-Identifier: LGPL-3.0-or-later */
#include <libksuid/ksuid.h>
#include "test_util.h"

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

int
main (void)
{
  RUN_TEST (test_constants_have_expected_layout);
  RUN_TEST (test_nil_is_all_zero);
  RUN_TEST (test_max_is_all_ff);
  RUN_TEST (test_compare_orders_lex);
  RUN_TEST (test_compare_first_byte_dominates);
  TEST_MAIN_END ();
}
