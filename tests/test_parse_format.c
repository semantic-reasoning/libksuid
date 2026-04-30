/* SPDX-License-Identifier: LGPL-3.0-or-later */
#include <libksuid/ksuid.h>
#include "test_util.h"

static const uint8_t kSampleBytes[KSUID_BYTES] = {
  0x06, 0x69, 0xF7, 0xEF,
  0xB5, 0xA1, 0xCD, 0x34, 0xB5, 0xF9, 0x9D, 0x11,
  0x54, 0xFB, 0x68, 0x53, 0x34, 0x5C, 0x97, 0x35,
};

static const char *const kSampleStr = "0ujtsYcgvSTl8PAuAdqWYSMnLOv";
static const char *const kNilStr = "000000000000000000000000000";
static const char *const kMaxStr = "aWgEPTl1tmebfsQzFP4bxwgy80V";

static void
test_parse_golden (void)
{
  ksuid_t id;
  ASSERT_EQ_INT (ksuid_parse (&id, kSampleStr, KSUID_STRING_LEN), KSUID_OK);
  ASSERT_EQ_BYTES (id.b, kSampleBytes, KSUID_BYTES);

  ASSERT_EQ_INT (ksuid_parse (&id, kNilStr, KSUID_STRING_LEN), KSUID_OK);
  ASSERT_TRUE (ksuid_is_nil (&id));

  ASSERT_EQ_INT (ksuid_parse (&id, kMaxStr, KSUID_STRING_LEN), KSUID_OK);
  ASSERT_EQ_INT (ksuid_compare (&id, &KSUID_MAX), 0);
}

static void
test_parse_size_errors (void)
{
  ksuid_t id = KSUID_MAX;
  ASSERT_EQ_INT (ksuid_parse (&id, kSampleStr, 0), KSUID_ERR_STR_SIZE);
  ASSERT_EQ_INT (ksuid_parse (&id, kSampleStr, 26), KSUID_ERR_STR_SIZE);
  ASSERT_EQ_INT (ksuid_parse (&id, kSampleStr, 28), KSUID_ERR_STR_SIZE);
  /* On size error |out| must not have been mutated. */
  ASSERT_EQ_INT (ksuid_compare (&id, &KSUID_MAX), 0);
}

static void
test_parse_value_errors (void)
{
  ksuid_t id;
  /* Mirrors upstream TestIssue25 (ksuid_test.go:100-111). */
  ASSERT_EQ_INT (ksuid_parse (&id, "aaaaaaaaaaaaaaaaaaaaaaaaaaa",
          KSUID_STRING_LEN), KSUID_ERR_STR_VALUE);
  ASSERT_EQ_INT (ksuid_parse (&id, "aWgEPTl1tmebfsQzFP4bxwgy80!",
          KSUID_STRING_LEN), KSUID_ERR_STR_VALUE);
  /* One past Max -- value overflow rather than alphabet violation. */
  ASSERT_EQ_INT (ksuid_parse (&id, "aWgEPTl1tmebfsQzFP4bxwgy80W",
          KSUID_STRING_LEN), KSUID_ERR_STR_VALUE);
}

static void
test_parse_value_error_does_not_mutate_out (void)
{
  /* The decoder partially writes its destination before detecting
   * overflow. ksuid_parse must therefore use a temporary internally
   * and leave the caller's |*out| untouched on every failure path. */
  ksuid_t pre = KSUID_MAX;
  ksuid_t id = pre;
  ASSERT_EQ_INT (ksuid_parse (&id, "aWgEPTl1tmebfsQzFP4bxwgy80W",
          KSUID_STRING_LEN), KSUID_ERR_STR_VALUE);
  ASSERT_EQ_BYTES (id.b, pre.b, KSUID_BYTES);

  ASSERT_EQ_INT (ksuid_parse (&id, "!!!!!!!!!!!!!!!!!!!!!!!!!!!",
          KSUID_STRING_LEN), KSUID_ERR_STR_VALUE);
  ASSERT_EQ_BYTES (id.b, pre.b, KSUID_BYTES);
}

static void
test_parse_or_nil (void)
{
  ksuid_t bad = ksuid_parse_or_nil (kSampleStr, 26);
  ASSERT_TRUE (ksuid_is_nil (&bad));
  ksuid_t ok = ksuid_parse_or_nil (kSampleStr, KSUID_STRING_LEN);
  ASSERT_EQ_BYTES (ok.b, kSampleBytes, KSUID_BYTES);
}

static void
test_format_golden (void)
{
  char out[KSUID_STRING_LEN];

  ksuid_format (&KSUID_NIL, out);
  ASSERT_EQ_STRN (out, kNilStr, KSUID_STRING_LEN);

  ksuid_format (&KSUID_MAX, out);
  ASSERT_EQ_STRN (out, kMaxStr, KSUID_STRING_LEN);

  ksuid_t sample;
  ksuid_from_bytes (&sample, kSampleBytes, KSUID_BYTES);
  ksuid_format (&sample, out);
  ASSERT_EQ_STRN (out, kSampleStr, KSUID_STRING_LEN);
}

static void
test_round_trip (void)
{
  /* Exercise format . parse for a deterministic byte pattern that
   * walks through a wide range of timestamp and payload values. */
  for (size_t trial = 0; trial < 128; ++trial) {
    ksuid_t in;
    uint64_t s = 0xcbf29ce484222325ULL ^ (trial * 0x100000001b3ULL);
    for (size_t i = 0; i < KSUID_BYTES; ++i) {
      s = s * 6364136223846793005ULL + 1442695040888963407ULL;
      in.b[i] = (uint8_t) (s >> 56);
    }
    char str[KSUID_STRING_LEN];
    ksuid_format (&in, str);
    ksuid_t round;
    ASSERT_EQ_INT (ksuid_parse (&round, str, KSUID_STRING_LEN), KSUID_OK);
    ASSERT_EQ_BYTES (round.b, in.b, KSUID_BYTES);
  }
}

int
main (void)
{
  RUN_TEST (test_parse_golden);
  RUN_TEST (test_parse_size_errors);
  RUN_TEST (test_parse_value_errors);
  RUN_TEST (test_parse_value_error_does_not_mutate_out);
  RUN_TEST (test_parse_or_nil);
  RUN_TEST (test_format_golden);
  RUN_TEST (test_round_trip);
  TEST_MAIN_END ();
}
