/* SPDX-License-Identifier: LGPL-3.0-or-later
 *
 * Differential parity test that pins the SSE2 / NEON 20-byte compare
 * kernel against the scalar reference. The scalar function is always
 * compiled (libksuid/compare_scalar.c is in core_sources unconditionally)
 * so this test exercises the scalar path on every host even when the
 * production library would dispatch to a SIMD kernel. On hosts where
 * neither SSE2 nor NEON is selected, KSUID_COMPARE20 maps to the
 * scalar kernel and the test degenerates into a self-consistency
 * check, which still pins regressions.
 *
 * Coverage:
 *   - identical pairs (must return 0)
 *   - single-byte flip at every byte position 0..19, both directions
 *   - the pinned NIL/MAX boundary (must be -1 / +1)
 *   - 4096 LCG-random pairs
 *   - "almost equal" pairs that share a long prefix and differ only
 *     at byte 19, the case random testing rarely produces
 */
#include <libksuid/compare_simd.h>
#include "test_util.h"

#include <string.h>

static void
check_match (const uint8_t *a, const uint8_t *b)
{
  int s = ksuid_compare20_scalar (a, b);
  int v = KSUID_COMPARE20 (a, b);
  ASSERT_EQ_INT (s, v);
  /* Plus the {-1, 0, +1} contract -- the SIMD kernel must not
   * return e.g. -42 even if its sign happens to match. */
  ASSERT_TRUE (v == -1 || v == 0 || v == 1);
}

static void
test_compare_identical_pairs (void)
{
  uint8_t buf[20] = { 0 };
  check_match (buf, buf);
  for (int i = 0; i < 20; ++i)
    buf[i] = (uint8_t) (i * 13 + 7);
  check_match (buf, buf);
  /* Distinct buffers, identical bytes. */
  uint8_t copy[20];
  memcpy (copy, buf, 20);
  check_match (buf, copy);
}

static void
test_compare_single_byte_flip_at_every_position (void)
{
  /* For each of the 20 byte positions, build two 20-byte buffers
   * that share a (k)-byte prefix and differ at byte k. Drive both
   * orderings (a < b and a > b) and pin the SIMD kernel against
   * the scalar reference. This is the case 4096 random pairs
   * almost never produce. */
  for (int k = 0; k < 20; ++k) {
    uint8_t a[20], b[20];
    memset (a, 0x55, 20);
    memset (b, 0x55, 20);
    a[k] = 0x10;
    b[k] = 0x20;
    check_match (a, b);         /* expect a < b */
    check_match (b, a);         /* expect b > a */
  }
}

static void
test_compare_pinned_nil_max (void)
{
  uint8_t nil[20] = { 0 };
  uint8_t max[20];
  memset (max, 0xff, 20);
  /* Specifically pin the {-1, +1} integer values, not just sign. */
  ASSERT_EQ_INT (KSUID_COMPARE20 (nil, max), -1);
  ASSERT_EQ_INT (KSUID_COMPARE20 (max, nil), +1);
  ASSERT_EQ_INT (KSUID_COMPARE20 (nil, nil), 0);
  ASSERT_EQ_INT (KSUID_COMPARE20 (max, max), 0);
}

static void
test_compare_pseudo_random_pairs (void)
{
  uint8_t a[20], b[20];
  uint64_t s = 0x9e3779b97f4a7c15ULL;
  for (size_t trial = 0; trial < 4096; ++trial) {
    for (int i = 0; i < 20; ++i) {
      s = s * 6364136223846793005ULL + 1442695040888963407ULL;
      a[i] = (uint8_t) (s >> 56);
      s = s * 6364136223846793005ULL + 1442695040888963407ULL;
      b[i] = (uint8_t) (s >> 56);
    }
    check_match (a, b);
  }
}

static void
test_compare_long_common_prefix (void)
{
  /* Same scenarios as the single-byte-flip test but with a more
   * realistic mid-prefix layout: bytes 0..k-1 match, byte k differs,
   * bytes k+1..19 also differ. Catches a SIMD kernel that wrongly
   * keys on the LAST difference instead of the FIRST. */
  uint8_t a[20], b[20];
  uint64_t s = 0xcbf29ce484222325ULL;
  for (int k = 0; k < 20; ++k) {
    for (int i = 0; i < 20; ++i) {
      s = s * 6364136223846793005ULL + 1442695040888963407ULL;
      uint8_t v = (uint8_t) (s >> 56);
      a[i] = v;
      b[i] = v;
    }
    /* Force a specific direction at position k, then re-randomise
     * the trailing bytes to differ in both directions. */
    a[k] = 0x40;
    b[k] = 0x80;
    for (int i = k + 1; i < 20; ++i) {
      s = s * 6364136223846793005ULL + 1442695040888963407ULL;
      a[i] = (uint8_t) (s >> 56);
      s = s * 6364136223846793005ULL + 1442695040888963407ULL;
      b[i] = (uint8_t) (s >> 56);
    }
    check_match (a, b);
    check_match (b, a);
  }
}

int
main (void)
{
  RUN_TEST (test_compare_identical_pairs);
  RUN_TEST (test_compare_single_byte_flip_at_every_position);
  RUN_TEST (test_compare_pinned_nil_max);
  RUN_TEST (test_compare_pseudo_random_pairs);
  RUN_TEST (test_compare_long_common_prefix);
  TEST_MAIN_END ();
}
