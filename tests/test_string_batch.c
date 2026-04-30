/* SPDX-License-Identifier: LGPL-3.0-or-later
 *
 * Tests for the public ksuid_string_batch bulk encoder. This commit
 * lands the API + the scalar reference; the AVX2 8-wide kernel
 * lands in a follow-up commit. The differential parity test against
 * the AVX2 kernel arrives in commit 4. For now we pin the contract:
 *   - n == 0 is a no-op
 *   - n KSUIDs land at the documented output offsets
 *   - every produced 27-byte slice equals ksuid_format of the same ID
 */
#include <libksuid/ksuid.h>
#include "test_util.h"

#include <stdlib.h>

static void
fill_pseudo_random (ksuid_t *id, uint64_t seed)
{
  uint64_t s = seed;
  for (size_t i = 0; i < KSUID_BYTES; ++i) {
    s = s * 6364136223846793005ULL + 1442695040888963407ULL;
    id->b[i] = (uint8_t) (s >> 56);
  }
}

static void
test_batch_zero_count_is_noop (void)
{
  /* The batch entry point must not write to |out| when n == 0
   * (Critic R12). Pin via a sentinel pattern. */
  char out[1] = { (char) 0xa5 };
  ksuid_string_batch (NULL, out, 0);
  ASSERT_EQ_INT ((unsigned char) out[0], 0xa5);
}

static void
test_batch_matches_format_for_n (size_t n)
{
  ksuid_t *ids = malloc (n * sizeof *ids);
  ASSERT_TRUE (ids != NULL);
  for (size_t i = 0; i < n; ++i)
    fill_pseudo_random (&ids[i],
        0x9e3779b97f4a7c15ULL ^ (i * 0x100000001b3ULL));

  char *batch_out = malloc (n * KSUID_STRING_LEN);
  ASSERT_TRUE (batch_out != NULL);
  ksuid_string_batch (ids, batch_out, n);

  for (size_t i = 0; i < n; ++i) {
    char ref[KSUID_STRING_LEN];
    ksuid_format (&ids[i], ref);
    ASSERT_EQ_BYTES (batch_out + i * KSUID_STRING_LEN, ref, KSUID_STRING_LEN);
  }
  free (ids);
  free (batch_out);
}

static void
test_batch_one (void)
{
  test_batch_matches_format_for_n (1);
}

static void
test_batch_seven (void)
{
  test_batch_matches_format_for_n (7);
}

static void
test_batch_eight_exact (void)
{
  test_batch_matches_format_for_n (8);
}

static void
test_batch_nine_one_past (void)
{
  test_batch_matches_format_for_n (9);
}

static void
test_batch_64 (void)
{
  test_batch_matches_format_for_n (64);
}

static void
test_batch_257_misaligned (void)
{
  test_batch_matches_format_for_n (257);
}

static void
test_batch_pinned_corners (void)
{
  ksuid_t ids[3];
  ids[0] = KSUID_NIL;
  ids[1] = KSUID_MAX;
  for (size_t i = 0; i < KSUID_BYTES; ++i)
    ids[2].b[i] = (uint8_t) (i * 7 + 11);

  char out[3 * KSUID_STRING_LEN];
  ksuid_string_batch (ids, out, 3);

  /* Compare each against the canonical ksuid_format output. */
  for (size_t i = 0; i < 3; ++i) {
    char ref[KSUID_STRING_LEN];
    ksuid_format (&ids[i], ref);
    ASSERT_EQ_BYTES (out + i * KSUID_STRING_LEN, ref, KSUID_STRING_LEN);
  }
}

int
main (void)
{
  RUN_TEST (test_batch_zero_count_is_noop);
  RUN_TEST (test_batch_one);
  RUN_TEST (test_batch_seven);
  RUN_TEST (test_batch_eight_exact);
  RUN_TEST (test_batch_nine_one_past);
  RUN_TEST (test_batch_64);
  RUN_TEST (test_batch_257_misaligned);
  RUN_TEST (test_batch_pinned_corners);
  TEST_MAIN_END ();
}
