/* SPDX-License-Identifier: LGPL-3.0-or-later
 *
 * Verifies that the auto-generated KSUID_DIV62_M magic constant in
 * libksuid/divisor_magic.h, plugged into a Granlund-Moeller scalar
 * reciprocal, agrees with straight integer division by 62 for every
 * tested input. Builds the floor/correction algorithm from scratch
 * here -- the AVX2 kernel will reuse the same algebra over 8 lanes.
 *
 * Coverage:
 *   - pinned corner cases (0, 1, 61, 62, 63, UINT64_MAX, ...)
 *   - 2^20 random u64 inputs (matches the M2 acceptance criterion
 *     in issue #13: "differential parity test seed must be
 *     reproducible") via a seeded LCG.
 *
 * Failure here means either the deriver script is wrong or the
 * checked-in header was hand-edited. Both modes are blockers for
 * shipping the AVX2 kernel.
 */
#include <libksuid/divisor_magic.h>
#include "test_util.h"

/* Reference mulhi64 via __uint128_t. Available on GCC/Clang on
 * every libksuid CI lane that exercises this test (the AVX2-target
 * x86_64 lane is the only one that ships the AVX2 kernel; MSVC is
 * not in this test's build matrix). */
_Static_assert (sizeof (unsigned __int128) == 16, "test requires __uint128_t");

/* Compile-time pin of the deriver's contract. If the header was
 * hand-edited or regenerated for a different divisor, this fails
 * the build before any test runs. */
_Static_assert (KSUID_DIV62_M_BITS == 64,
    "KSUID_DIV62_M expected to be 64-bit");
_Static_assert (KSUID_DIV62_M * (uint64_t) 62
    + KSUID_DIV62_M_2N_MINUS_M_TIMES_D == 0,
    "KSUID_DIV62_M does not satisfy 2^64 - M * 62 = "
    "KSUID_DIV62_M_2N_MINUS_M_TIMES_D");
_Static_assert (KSUID_DIV62_M_2N_MINUS_M_TIMES_D < 62,
    "deficit must be in [0, d - 1]; "
    "anything else means M is not floor(2^64 / 62)");

static uint64_t
mulhi64_ref (uint64_t a, uint64_t b)
{
  return (uint64_t) (((unsigned __int128) a * b) >> 64);
}

static uint64_t
div62_via_magic (uint64_t value)
{
  uint64_t q = mulhi64_ref (value, KSUID_DIV62_M);
  uint64_t r = value - q * 62;
  /* mulhi may underestimate by exactly 1; never overestimates
   * because M is the FLOOR. The correction is unconditional in
   * the sense that r is always in [0, 123]; the branch picks the
   * exact quotient + remainder. We only need q here -- mod62 has
   * its own helper -- so the post-correction r is unused, but
   * we must run the branch to update q. */
  if (r >= 62)
    q += 1;
  return q;
}

static uint64_t
mod62_via_magic (uint64_t value)
{
  uint64_t q = mulhi64_ref (value, KSUID_DIV62_M);
  uint64_t r = value - q * 62;
  if (r >= 62)
    r -= 62;
  return r;
}

static void
check_one (uint64_t value)
{
  uint64_t q_ref = value / 62;
  uint64_t r_ref = value % 62;
  uint64_t q_mag = div62_via_magic (value);
  uint64_t r_mag = mod62_via_magic (value);
  if (q_mag != q_ref || r_mag != r_ref) {
    fprintf (stderr,
        "  divmod62 mismatch at value=0x%016llx:\n"
        "    reference: q=%llu, r=%llu\n"
        "    magic:     q=%llu, r=%llu\n",
        (unsigned long long) value,
        (unsigned long long) q_ref, (unsigned long long) r_ref,
        (unsigned long long) q_mag, (unsigned long long) r_mag);
    ksuid_test_failures_++;
  }
}

static void
test_pinned_corners (void)
{
  /* Boundaries: 0, around d, around 2^32, around 2^38 (the AVX2
   * kernel's value bound), around 2^63, max u64. */
  static const uint64_t corners[] = {
    0, 1, 60, 61, 62, 63, 123, 124, 125,
    (uint64_t) UINT32_MAX - 1, (uint64_t) UINT32_MAX,
    (uint64_t) UINT32_MAX + 1, (uint64_t) UINT32_MAX + 62,
    (uint64_t) 1 << 32, ((uint64_t) 1 << 32) + 1,
    /* The exact AVX2 in-loop bound: value < 62 * 2^32 + 2^32 */
    ((uint64_t) 62 << 32) - 1, ((uint64_t) 62 << 32),
    ((uint64_t) 63 << 32) - 1,
    /* Larger values still must work for full-u64 confidence. */
    (uint64_t) 1 << 50, (uint64_t) 1 << 60, (uint64_t) 1 << 63,
    UINT64_MAX - 62, UINT64_MAX - 61, UINT64_MAX - 1, UINT64_MAX,
  };
  for (size_t i = 0; i < sizeof corners / sizeof corners[0]; ++i)
    check_one (corners[i]);
}

static void
test_one_million_lcg_random (void)
{
  /* Seeded LCG -- a failing input found in CI must reproduce
   * locally with the same seed. Period 2^64. 2^20 = 1048576
   * samples is the M2 acceptance threshold from issue #13. */
  uint64_t s = 0x9e3779b97f4a7c15ULL;
  for (size_t trial = 0; trial < (1u << 20); ++trial) {
    s = s * 6364136223846793005ULL + 1442695040888963407ULL;
    check_one (s);
  }
}

static void
test_dense_low_range (void)
{
  /* Exhaustive sweep of every value in [0, 4 * 62) so every
   * remainder value 0..61 is exercised at every quotient
   * 0, 1, 2, 3. Catches off-by-one errors that random testing
   * misses for low quotients. */
  for (uint64_t v = 0; v < (uint64_t) 4 * 62; ++v)
    check_one (v);
}

int
main (void)
{
  RUN_TEST (test_pinned_corners);
  RUN_TEST (test_dense_low_range);
  RUN_TEST (test_one_million_lcg_random);
  TEST_MAIN_END ();
}
