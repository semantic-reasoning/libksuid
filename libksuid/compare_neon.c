/* SPDX-License-Identifier: LGPL-3.0-or-later
 *
 * NEON specialisation of the 20-byte compare. Same shape as the
 * SSE2 kernel: 16-byte vector compare for the head, scalar tail
 * for bytes 16..19. NEON is mandatory in the aarch64 ABI baseline,
 * so this TU is selected unconditionally on aarch64 / arm64.
 */
#if defined(__aarch64__) || defined(__arm64__) || \
    (defined(__ARM_NEON) && defined(__arm__))
#include <arm_neon.h>
#include <stdint.h>

#include <libksuid/compare_simd.h>

int
ksuid_compare20_neon (const uint8_t a[20], const uint8_t b[20])
{
  uint8x16_t va = vld1q_u8 (a);
  uint8x16_t vb = vld1q_u8 (b);
  uint8x16_t veq = vceqq_u8 (va, vb);
  /* Reduce: vminvq returns the smallest byte across the lane. If
   * any lane is 0 (mismatch), the min is 0. */
#if defined(__aarch64__) || defined(__arm64__)
  if (vminvq_u8 (veq) != 0xff) {
#else
  /* ARMv7 NEON has no minv; fall back to a pairwise reduction. */
  uint8x8_t lo = vget_low_u8 (veq);
  uint8x8_t hi = vget_high_u8 (veq);
  uint8x8_t both = vand_u8 (lo, hi);
  uint8x8_t r = vpmin_u8 (both, both);
  r = vpmin_u8 (r, r);
  r = vpmin_u8 (r, r);
  if (vget_lane_u8 (r, 0) != 0xff) {
#endif
    /* At least one of the first 16 bytes differs; find which. */
    for (int i = 0; i < 16; ++i) {
      if (a[i] != b[i])
        return (a[i] < b[i]) ? -1 : 1;
    }
    /* Unreachable -- we just proved vminvq found a 0 byte. */
  }
  /* Tail: bytes 16..19. */
  for (int i = 16; i < 20; ++i) {
    if (a[i] != b[i])
      return (a[i] < b[i]) ? -1 : 1;
  }
  return 0;
}
#endif /* arm */
