/* SPDX-License-Identifier: LGPL-3.0-or-later
 *
 * Tests for the public ksuid_string_batch bulk encoder.
 *
 * Two layers of coverage:
 *   1. Public-API parity: every 27-byte slice produced by
 *      ksuid_string_batch (which dispatches to the best kernel for
 *      the host -- AVX2 on AVX2 x86_64, scalar elsewhere) equals
 *      ksuid_format of the same ID. Pins n=0 no-op, exact-multiple-
 *      of-8, off-by-one-into-tail (n=9), prime-misaligned (n=257),
 *      and the corner KSUIDs (NIL, MAX).
 *   2. Direct AVX2-vs-scalar differential parity (compiled in only
 *      when KSUID_HAVE_AVX2_BATCH is defined; gated at runtime on
 *      __builtin_cpu_supports("avx2") so the same binary is safe
 *      on non-AVX2 hosts in the same x86_64 build). Bypasses the
 *      runtime dispatcher and calls the scalar + AVX2 kernels
 *      directly, comparing byte-for-byte. This is what catches
 *      cross-lane bugs (Critic R3 in issue #13: 8 distinct KSUIDs
 *      whose lanes get swapped by an off-by-one in the SoA pack
 *      would still pass per-ID format-parity tests if the wrong
 *      output happens to match a different input).
 */
#include <libksuid/ksuid.h>
#include "test_util.h"

#include <stdlib.h>

#if defined(KSUID_HAVE_AVX2_BATCH) && (defined(__GNUC__) || defined(__clang__))
#  define KSUID_TEST_AVX2_PARITY 1
/* Internal kernel prototypes. Tests link against the static archive
 * so default-hidden visibility does not exclude these symbols. */
extern void ksuid_string_batch_scalar (const ksuid_t * ids, char *out_27n,
    size_t n);
extern void ksuid_string_batch_avx2 (const ksuid_t * ids, char *out_27n,
    size_t n);
#else
#  define KSUID_TEST_AVX2_PARITY 0
#endif

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

#if KSUID_TEST_AVX2_PARITY
static int
host_supports_avx2 (void)
{
  __builtin_cpu_init ();
  return __builtin_cpu_supports ("avx2");
}

static void
avx2_parity_for_n (size_t n)
{
  if (!host_supports_avx2 ())
    return;
  ksuid_t *ids = malloc (n * sizeof *ids);
  ASSERT_TRUE (ids != NULL);
  for (size_t i = 0; i < n; ++i)
    fill_pseudo_random (&ids[i],
        0xa3b1c2d4e5f60718ULL ^ (i * 0x9e3779b97f4a7c15ULL));

  char *out_s = malloc (n * KSUID_STRING_LEN);
  char *out_a = malloc (n * KSUID_STRING_LEN);
  if (out_s == NULL || out_a == NULL) {
    FAIL_ ("out_s/out_a malloc");
    free (ids);
    free (out_s);
    free (out_a);
    return;
  }
  ksuid_string_batch_scalar (ids, out_s, n);
  ksuid_string_batch_avx2 (ids, out_a, n);

  /* Per-lane byte compare so the failure message identifies WHICH
   * KSUID position diverged (a single ASSERT_EQ_BYTES across the
   * full buffer would only print the first byte offset). */
  for (size_t i = 0; i < n; ++i)
    ASSERT_EQ_BYTES (out_s + i * KSUID_STRING_LEN,
        out_a + i * KSUID_STRING_LEN, KSUID_STRING_LEN);

  free (ids);
  free (out_s);
  free (out_a);
}

static void
test_avx2_parity_n_in_block_boundaries (void)
{
  /* Boundaries around the 8-wide block size: tail-only, exact
   * block, off-by-one into tail, two blocks plus tail, etc. */
  static const size_t ns[] = { 1, 7, 8, 9, 15, 16, 17, 23, 24, 25, 1000 };
  for (size_t i = 0; i < sizeof ns / sizeof ns[0]; ++i)
    avx2_parity_for_n (ns[i]);
}

static void
test_avx2_parity_lane_swap_detection (void)
{
  /* 8 distinct KSUIDs in the same vector. If the AVX2 lane-pack
   * code mis-mapped lane k to lane k', the out-of-position
   * comparison against the scalar reference fails. */
  if (!host_supports_avx2 ())
    return;
  ksuid_t ids[8];
  for (size_t lane = 0; lane < 8; ++lane)
    fill_pseudo_random (&ids[lane],
        0xdeadbeefcafef00dULL + (uint64_t) (lane * 0x100000001b3ULL));

  char out_s[8 * KSUID_STRING_LEN];
  char out_a[8 * KSUID_STRING_LEN];
  ksuid_string_batch_scalar (ids, out_s, 8);
  ksuid_string_batch_avx2 (ids, out_a, 8);
  for (size_t lane = 0; lane < 8; ++lane)
    ASSERT_EQ_BYTES (out_s + lane * KSUID_STRING_LEN,
        out_a + lane * KSUID_STRING_LEN, KSUID_STRING_LEN);
}

static void
test_avx2_parity_corner_values (void)
{
  if (!host_supports_avx2 ())
    return;
  /* 16 KSUIDs of pure-NIL / pure-MAX / all-0xff payload variants
   * spread across two SIMD blocks, exercising the long-division
   * "all-zero limbs" and "max-value limbs" extremes for every
   * lane position in the SoA layout. */
  ksuid_t ids[16];
  for (size_t i = 0; i < 16; ++i) {
    if ((i & 3) == 0)
      ids[i] = KSUID_NIL;
    else if ((i & 3) == 1)
      ids[i] = KSUID_MAX;
    else if ((i & 3) == 2) {
      /* All-bytes-0x80, exercises the high bit being set in
       * every limb which would expose any signed/unsigned
       * confusion in mulhi64. */
      for (size_t j = 0; j < KSUID_BYTES; ++j)
        ids[i].b[j] = 0x80;
    } else {
      /* Limbs alternating 0xffffffff / 0x00000000 -- exercises
       * the rem-injection path with non-trivial high bits. */
      for (size_t j = 0; j < KSUID_BYTES; ++j)
        ids[i].b[j] = ((j / 4) % 2) ? 0xff : 0x00;
    }
  }
  char out_s[16 * KSUID_STRING_LEN];
  char out_a[16 * KSUID_STRING_LEN];
  ksuid_string_batch_scalar (ids, out_s, 16);
  ksuid_string_batch_avx2 (ids, out_a, 16);
  for (size_t i = 0; i < 16; ++i)
    ASSERT_EQ_BYTES (out_s + i * KSUID_STRING_LEN,
        out_a + i * KSUID_STRING_LEN, KSUID_STRING_LEN);
}

static void
test_avx2_parity_one_million_lcg (void)
{
  /* Match the M2 acceptance threshold from issue #13: >= 2^20
   * pseudo-random KSUIDs differential-checked end-to-end. The seed
   * is the same constant as test_divisor_magic.c so a CI failure
   * reproduces locally bit-for-bit. */
  if (!host_supports_avx2 ())
    return;
  size_t n = 1u << 20;
  ksuid_t *ids = malloc (n * sizeof *ids);
  ASSERT_TRUE (ids != NULL);
  uint64_t s = 0x9e3779b97f4a7c15ULL;
  for (size_t i = 0; i < n; ++i) {
    for (size_t j = 0; j < KSUID_BYTES; ++j) {
      s = s * 6364136223846793005ULL + 1442695040888963407ULL;
      ids[i].b[j] = (uint8_t) (s >> 56);
    }
  }

  char *out_s = malloc (n * KSUID_STRING_LEN);
  char *out_a = malloc (n * KSUID_STRING_LEN);
  if (out_s == NULL || out_a == NULL) {
    FAIL_ ("out_s/out_a malloc");
    free (ids);
    free (out_s);
    free (out_a);
    return;
  }
  ksuid_string_batch_scalar (ids, out_s, n);
  ksuid_string_batch_avx2 (ids, out_a, n);

  /* memcmp-style fast check; only fall through to per-position
   * report on mismatch to keep the success path cheap. */
  if (memcmp (out_s, out_a, n * KSUID_STRING_LEN) != 0) {
    for (size_t i = 0; i < n; ++i) {
      if (memcmp (out_s + i * KSUID_STRING_LEN,
              out_a + i * KSUID_STRING_LEN, KSUID_STRING_LEN) != 0) {
        fprintf (stderr, "  AVX2 parity diverged at lane %zu of %zu\n", i, n);
        ksuid_test_failures_++;
        break;
      }
    }
  }
  free (ids);
  free (out_s);
  free (out_a);
}
#endif /* KSUID_TEST_AVX2_PARITY */

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
#if KSUID_TEST_AVX2_PARITY
  RUN_TEST (test_avx2_parity_n_in_block_boundaries);
  RUN_TEST (test_avx2_parity_lane_swap_detection);
  RUN_TEST (test_avx2_parity_corner_values);
  RUN_TEST (test_avx2_parity_one_million_lcg);
#endif
  TEST_MAIN_END ();
}
