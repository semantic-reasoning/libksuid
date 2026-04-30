/* SPDX-License-Identifier: LGPL-3.0-or-later
 *
 * ARM NEON base62 16-byte translate-and-validate kernel. Logically
 * identical to the SSE2 version (same three range tests, same
 * sentinel-fill on miss); intrinsic spellings differ.
 *
 * NEON is mandatory in the ARMv8 / aarch64 ABI, so this TU may use
 * <arm_neon.h> intrinsics directly without a runtime CPU feature
 * check on aarch64. On 32-bit ARM the meson build only compiles
 * this file when -mfpu=neon is requested, in which case the same
 * mandatory-NEON assumption applies to the resulting binary.
 */
#if defined(__aarch64__) || defined(__arm64__) || \
    (defined(__ARM_NEON) && defined(__arm__))
#include <arm_neon.h>
#include <stdint.h>

#include <libksuid/base62_simd.h>

int
ksuid_base62_translate16_neon (uint8_t out[16], const uint8_t in[16])
{
  uint8x16_t v = vld1q_u8 (in);

  uint8x16_t d = vsubq_u8 (v, vdupq_n_u8 ('0'));
  uint8x16_t d_mask = vcleq_u8 (d, vdupq_n_u8 (9));
  uint8x16_t d_val = vandq_u8 (d_mask, d);

  uint8x16_t u = vsubq_u8 (v, vdupq_n_u8 ('A'));
  uint8x16_t u_mask = vcleq_u8 (u, vdupq_n_u8 (25));
  uint8x16_t u_val = vandq_u8 (u_mask, vaddq_u8 (u, vdupq_n_u8 (10)));

  uint8x16_t l = vsubq_u8 (v, vdupq_n_u8 ('a'));
  uint8x16_t l_mask = vcleq_u8 (l, vdupq_n_u8 (25));
  uint8x16_t l_val = vandq_u8 (l_mask, vaddq_u8 (l, vdupq_n_u8 (36)));

  uint8x16_t any_mask = vorrq_u8 (vorrq_u8 (d_mask, u_mask), l_mask);
  uint8x16_t values = vorrq_u8 (vorrq_u8 (d_val, u_val), l_val);

  /* vbicq computes a & ~b; we want 0xff where any_mask is 0, so
   * vbicq(0xff, any_mask). */
  uint8x16_t invalid_fill = vbicq_u8 (vdupq_n_u8 (0xff), any_mask);
  uint8x16_t result = vorrq_u8 (values, invalid_fill);
  vst1q_u8 (out, result);

  /* Validity reduce: AND-reduce 16 bytes; if all are 0xff the
   * result is 0xff. minv reads the minimum byte across the lane;
   * 0xff means every lane was 0xff. */
#if defined(__aarch64__) || defined(__arm64__)
  return (vminvq_u8 (any_mask) == 0xff) ? 0 : -1;
#else
  /* ARMv7 NEON has no minv; fall back to a pairwise reduction. */
  uint8x8_t lo = vget_low_u8 (any_mask);
  uint8x8_t hi = vget_high_u8 (any_mask);
  uint8x8_t both = vand_u8 (lo, hi);
  uint8x8_t r = vpmin_u8 (both, both);
  r = vpmin_u8 (r, r);
  r = vpmin_u8 (r, r);
  return (vget_lane_u8 (r, 0) == 0xff) ? 0 : -1;
#endif
}
#endif /* arm */
