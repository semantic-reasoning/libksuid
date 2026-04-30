/* SPDX-License-Identifier: LGPL-3.0-or-later
 *
 * Differential test that pins the SIMD/NEON base62 translate kernel
 * to exact parity with the scalar reference implementation. For every
 * 16-byte input we feed both paths and require:
 *   - byte-for-byte identical output
 *   - identical {0, -1} validity verdict
 *
 * The scalar function is always exported (as the ABI fallback); the
 * dispatch macro picks the SIMD path on the supported architectures.
 * On hosts where neither SSE2 nor NEON is detected the macro maps
 * back to the scalar function and this test degenerates to a self-
 * consistency check, which is still useful (it asserts the kernel
 * doesn't regress).
 */
#include <libksuid/base62_simd.h>
#include "test_util.h"

#include <stdint.h>

static void
check_one (const uint8_t in[16])
{
  uint8_t out_scalar[16];
  uint8_t out_simd[16];
  int rc_scalar = ksuid_base62_translate16_scalar (out_scalar, in);
  int rc_simd = KSUID_TRANSLATE16 (out_simd, in);
  ASSERT_EQ_INT (rc_scalar, rc_simd);
  ASSERT_EQ_BYTES (out_scalar, out_simd, 16);
}

static void
test_all_valid_alphabet (void)
{
  /* The 62 valid characters in their natural sorted order. */
  static const char alpha[]
      = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
  /* Slide a 16-byte window across the 62-char alphabet so every
   * valid character is exercised at every lane position. */
  for (size_t i = 0; i + 16 <= sizeof alpha - 1; ++i)
    check_one ((const uint8_t *) alpha + i);
}

static void
test_each_invalid_byte_in_each_lane (void)
{
  /* Build a baseline of all-'0' (valid) and inject a known-invalid
   * byte at every lane position; the kernel must agree byte-for-byte
   * with the scalar reference. */
  static const uint8_t bad_chars[] = {
    0x00, 0x1f, '!', '/', ':', '@', 'Z' + 1, '`', 'z' + 1, 0x7f, 0x80, 0xff
  };
  for (size_t b = 0; b < sizeof bad_chars; ++b) {
    for (size_t lane = 0; lane < 16; ++lane) {
      uint8_t in[16];
      memset (in, '0', sizeof in);
      in[lane] = bad_chars[b];
      check_one (in);
    }
  }
}

static void
test_pseudo_random_inputs (void)
{
  /* Mix of valid and invalid characters drawn from an LCG. Each
   * trial puts the kernel through both branches and exercises lane-
   * crossing transitions between subranges of the alphabet. */
  uint8_t in[16];
  uint64_t s = 0xb7a4e72fcfd9c8a3ULL;
  for (size_t trial = 0; trial < 1024; ++trial) {
    for (size_t i = 0; i < 16; ++i) {
      s = s * 6364136223846793005ULL + 1442695040888963407ULL;
      in[i] = (uint8_t) (s >> 56);
    }
    check_one (in);
  }
}

static void
test_all_zero_input (void)
{
  /* All NULs are out-of-alphabet; both kernels must report -1 and
   * write 0xff into every output lane. */
  uint8_t in[16] = { 0 };
  uint8_t out_scalar[16];
  uint8_t out_simd[16];
  int rc_scalar = ksuid_base62_translate16_scalar (out_scalar, in);
  int rc_simd = KSUID_TRANSLATE16 (out_simd, in);
  ASSERT_EQ_INT (rc_scalar, -1);
  ASSERT_EQ_INT (rc_simd, -1);
  ASSERT_EQ_BYTES (out_scalar, out_simd, 16);
  for (size_t i = 0; i < 16; ++i)
    ASSERT_EQ_INT (out_simd[i], 0xff);
}

int
main (void)
{
  RUN_TEST (test_all_valid_alphabet);
  RUN_TEST (test_each_invalid_byte_in_each_lane);
  RUN_TEST (test_pseudo_random_inputs);
  RUN_TEST (test_all_zero_input);
  TEST_MAIN_END ();
}
