/* SPDX-License-Identifier: LGPL-3.0-or-later
 *
 * SSE2 base62 16-byte translate-and-validate kernel.
 *
 * Three packed range tests in parallel on the 16-byte input:
 *   ('0'..'9') -> [0..9]    via  v - '0'
 *   ('A'..'Z') -> [10..35]  via  v - 'A' + 10
 *   ('a'..'z') -> [36..61]  via  v - 'a' + 36
 * Each range produces a "selected" mask (0xff where in-range) and a
 * value vector; the final result is OR'd. Bytes that fell outside
 * every range get the sentinel 0xff via the inverted any-mask.
 *
 * The validity flag is the 16-bit movemask of the union mask; if
 * any byte was out-of-range the corresponding bit is 0.
 *
 * SSE2 is part of the x86_64 ABI baseline (mandatory since the
 * AMD64 spec), so this TU may rely on the intrinsics being
 * available on every x86_64 host without a runtime CPU feature
 * check.
 */
#if defined(__x86_64__) || defined(_M_X64) || defined(__i386__)
#include <emmintrin.h>          /* SSE2 */
#include <stdint.h>

#include <libksuid/base62_simd.h>

int
ksuid_base62_translate16_sse2 (uint8_t out[16], const uint8_t in[16])
{
  /* _mm_loadu_si128 is the SSE2 unaligned-load intrinsic; the
   * (__m128i *) cast is a documented part of the API and does not
   * actually require 16-byte alignment. */
  /* NOLINTNEXTLINE(clang-diagnostic-cast-align) */
  __m128i v = _mm_loadu_si128 ((const __m128i *) in);

  /* digit: v in '0'..'9' */
  __m128i d = _mm_sub_epi8 (v, _mm_set1_epi8 ('0'));
  __m128i d_mask = _mm_cmpeq_epi8 (_mm_min_epu8 (d, _mm_set1_epi8 (9)), d);
  __m128i d_val = _mm_and_si128 (d_mask, d);

  /* upper: v in 'A'..'Z' -> base62 value v - 'A' + 10 */
  __m128i u = _mm_sub_epi8 (v, _mm_set1_epi8 ('A'));
  __m128i u_mask = _mm_cmpeq_epi8 (_mm_min_epu8 (u, _mm_set1_epi8 (25)), u);
  __m128i u_val = _mm_and_si128 (u_mask, _mm_add_epi8 (u, _mm_set1_epi8 (10)));

  /* lower: v in 'a'..'z' -> base62 value v - 'a' + 36 */
  __m128i l = _mm_sub_epi8 (v, _mm_set1_epi8 ('a'));
  __m128i l_mask = _mm_cmpeq_epi8 (_mm_min_epu8 (l, _mm_set1_epi8 (25)), l);
  __m128i l_val = _mm_and_si128 (l_mask, _mm_add_epi8 (l, _mm_set1_epi8 (36)));

  __m128i any_mask = _mm_or_si128 (_mm_or_si128 (d_mask, u_mask), l_mask);
  __m128i values = _mm_or_si128 (_mm_or_si128 (d_val, u_val), l_val);

  /* For bytes that were out-of-range, set the result to 0xff so the
   * scalar tail can detect them by sentinel. _mm_andnot computes
   * (~any_mask) & 0xff, which is 0xff exactly where any_mask=0. */
  __m128i invalid_fill =
      _mm_andnot_si128 (any_mask, _mm_set1_epi8 ((char) 0xff));
  __m128i result = _mm_or_si128 (values, invalid_fill);
  /* Mirror cast-alignment exemption: _mm_storeu_si128 is unaligned. */
  /* NOLINTNEXTLINE(clang-diagnostic-cast-align) */
  _mm_storeu_si128 ((__m128i *) out, result);

  /* movemask collects the high bits; for an all-0xff mask we expect
   * 0xffff (every byte's MSB is set). */
  return (_mm_movemask_epi8 (any_mask) == 0xffff) ? 0 : -1;
}
#endif /* x86 */
