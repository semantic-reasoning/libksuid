/* SPDX-License-Identifier: LGPL-3.0-or-later */
#include <libksuid/ksuid.h>
#include "test_util.h"

static void
test_next_of_nil_is_one (void)
{
  ksuid_t n = ksuid_next (&KSUID_NIL);
  uint8_t expected[KSUID_BYTES] = { 0 };
  expected[KSUID_BYTES - 1] = 1;
  ASSERT_EQ_BYTES (n.b, expected, KSUID_BYTES);
}

static void
test_prev_of_nil_is_max (void)
{
  /* Mirrors upstream TestPrevNext (ksuid_test.go:282-298): prev of the
   * Nil KSUID wraps both payload and timestamp around to all-0xff. */
  ksuid_t p = ksuid_prev (&KSUID_NIL);
  ASSERT_EQ_INT (ksuid_compare (&p, &KSUID_MAX), 0);
}

static void
test_next_of_max_is_nil (void)
{
  ksuid_t n = ksuid_next (&KSUID_MAX);
  ASSERT_TRUE (ksuid_is_nil (&n));
}

static void
test_prev_of_max_decrements_low_byte (void)
{
  ksuid_t p = ksuid_prev (&KSUID_MAX);
  uint8_t expected[KSUID_BYTES];
  memset (expected, 0xff, KSUID_BYTES);
  expected[KSUID_BYTES - 1] = 0xfe;
  ASSERT_EQ_BYTES (p.b, expected, KSUID_BYTES);
}

static void
test_payload_increment_no_timestamp_bump (void)
{
  /* All payload bytes are 0xff except the last; incr should set the
   * last byte to 0xff +1 = 0x00 with carry into byte 18, leaving the
   * timestamp untouched. */
  ksuid_t in = { 0 };
  in.b[0] = 0x12;
  in.b[1] = 0x34;
  in.b[2] = 0x56;
  in.b[3] = 0x78;
  for (size_t i = KSUID_TIMESTAMP_LEN; i < KSUID_BYTES - 1; ++i)
    in.b[i] = 0xff;
  in.b[KSUID_BYTES - 1] = 0xfe;

  ksuid_t n = ksuid_next (&in);
  /* Timestamp prefix unchanged. */
  ASSERT_EQ_INT (ksuid_timestamp (&n), 0x12345678u);
  /* Payload now all 0xff. */
  uint8_t allff[KSUID_PAYLOAD_LEN];
  memset (allff, 0xff, KSUID_PAYLOAD_LEN);
  ASSERT_EQ_BYTES (ksuid_payload (&n), allff, KSUID_PAYLOAD_LEN);
}

static void
test_payload_overflow_bumps_timestamp (void)
{
  ksuid_t in = { 0 };
  in.b[0] = 0x00;
  in.b[1] = 0x00;
  in.b[2] = 0x00;
  in.b[3] = 0x42;
  for (size_t i = KSUID_TIMESTAMP_LEN; i < KSUID_BYTES; ++i)
    in.b[i] = 0xff;

  ksuid_t n = ksuid_next (&in);
  ASSERT_EQ_INT (ksuid_timestamp (&n), 0x43u);
  /* Payload after wrap is all-zero. */
  uint8_t zero[KSUID_PAYLOAD_LEN] = { 0 };
  ASSERT_EQ_BYTES (ksuid_payload (&n), zero, KSUID_PAYLOAD_LEN);
}

static void
test_next_then_prev_is_identity (void)
{
  /* For any KSUID that is not at a boundary, next then prev is identity.
   * This also exercises the cmp ordering invariant. */
  ksuid_t in;
  uint64_t s = 0x517cc1b727220a95ULL;
  for (size_t i = 0; i < KSUID_BYTES; ++i) {
    s = s * 6364136223846793005ULL + 1442695040888963407ULL;
    in.b[i] = (uint8_t) (s >> 56);
  }
  ksuid_t after = ksuid_next (&in);
  ksuid_t back = ksuid_prev (&after);
  ASSERT_EQ_BYTES (back.b, in.b, KSUID_BYTES);
  /* And next is strictly greater. */
  ASSERT_TRUE (ksuid_compare (&in, &after) < 0);
}

int
main (void)
{
  RUN_TEST (test_next_of_nil_is_one);
  RUN_TEST (test_prev_of_nil_is_max);
  RUN_TEST (test_next_of_max_is_nil);
  RUN_TEST (test_prev_of_max_decrements_low_byte);
  RUN_TEST (test_payload_increment_no_timestamp_bump);
  RUN_TEST (test_payload_overflow_bumps_timestamp);
  RUN_TEST (test_next_then_prev_is_identity);
  TEST_MAIN_END ();
}
