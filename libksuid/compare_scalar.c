/* SPDX-License-Identifier: LGPL-3.0-or-later
 *
 * Scalar reference for the 20-byte compare kernel. Always compiled
 * so the parity test in tests/test_compare_parity.c can drive both
 * the scalar and the SIMD path on every host.
 */
#include <libksuid/compare_simd.h>

#include <string.h>

int
ksuid_compare20_scalar (const uint8_t a[20], const uint8_t b[20])
{
  /* Same body the public ksuid_compare used to inline: byte-order
   * lexicographic compare normalised to {-1, 0, +1}. The SIMD
   * kernels must reproduce this contract bit-for-bit. */
  int r = memcmp (a, b, 20);
  return (r > 0) - (r < 0);
}
