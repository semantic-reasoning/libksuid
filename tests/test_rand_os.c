/* SPDX-License-Identifier: LGPL-3.0-or-later */
#include <libksuid/rand.h>
#include "test_util.h"

static void
test_returns_nonzero_bytes (void)
{
  uint8_t buf[64];
  memset (buf, 0, sizeof buf);
  ASSERT_EQ_INT (ksuid_os_random_bytes (buf, sizeof buf), 0);
  /* Probability of a real CSPRNG returning all zeros is 2^-512, so
   * this test is effectively deterministic. */
  uint8_t zero[64];
  memset (zero, 0, sizeof zero);
  ASSERT_TRUE (memcmp (buf, zero, sizeof buf) != 0);
}

static void
test_two_calls_differ (void)
{
  uint8_t a[32], b[32];
  ASSERT_EQ_INT (ksuid_os_random_bytes (a, sizeof a), 0);
  ASSERT_EQ_INT (ksuid_os_random_bytes (b, sizeof b), 0);
  /* Probability of collision is 2^-256. */
  ASSERT_TRUE (memcmp (a, b, sizeof a) != 0);
}

static void
test_zero_length_is_noop (void)
{
  uint8_t buf[1] = { 0xab };
  ASSERT_EQ_INT (ksuid_os_random_bytes (buf, 0), 0);
  ASSERT_EQ_INT (buf[0], 0xab);
}

static void
test_large_buffer (void)
{
  /* Many entropy back-ends cap a single call (e.g. getentropy at 256).
   * Verify the loop fills past the cap. */
  uint8_t buf[1024];
  ASSERT_EQ_INT (ksuid_os_random_bytes (buf, sizeof buf), 0);
  /* Heuristic: at least 200 of 1024 bytes must be nonzero. */
  size_t nonzero = 0;
  for (size_t i = 0; i < sizeof buf; ++i)
    if (buf[i] != 0)
      ++nonzero;
  ASSERT_TRUE (nonzero > 200);
}

int
main (void)
{
  RUN_TEST (test_returns_nonzero_bytes);
  RUN_TEST (test_two_calls_differ);
  RUN_TEST (test_zero_length_is_noop);
  RUN_TEST (test_large_buffer);
  TEST_MAIN_END ();
}
