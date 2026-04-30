/* SPDX-License-Identifier: LGPL-3.0-or-later
 *
 * SIMD/NEON kernels for the base62 decoder. Each kernel takes 16
 * ASCII bytes and produces 16 base62 values (0..61) or the
 * sentinel 0xff for any byte outside [0-9A-Za-z]. The return value
 * is 0 if every input byte was in-alphabet and -1 otherwise; this
 * lets the caller short-circuit a partial-write decode without
 * paying for a 16-way scalar branch chain.
 *
 * The scalar fallback is always compiled. The SSE2 kernel is
 * compiled only on x86_64 (where SSE2 is part of the ABI baseline);
 * the NEON kernel only on aarch64 / ARMv8 (likewise mandatory).
 * Choice is made at compile time via KSUID_HAVE_SSE2 /
 * KSUID_HAVE_NEON; runtime dispatch is unnecessary for those
 * baselines and the architect plan's atomic function-pointer
 * scaffolding is reserved for the eventual AVX2 / SVE upgrades.
 */
#ifndef KSUID_BASE62_SIMD_H
#define KSUID_BASE62_SIMD_H

#include <stddef.h>
#include <stdint.h>

int ksuid_base62_translate16_scalar (uint8_t out[16], const uint8_t in[16]);

#if defined(KSUID_HAVE_SSE2)
int ksuid_base62_translate16_sse2 (uint8_t out[16], const uint8_t in[16]);
#  define KSUID_TRANSLATE16(out, in) ksuid_base62_translate16_sse2 ((out), (in))
#elif defined(KSUID_HAVE_NEON)
int ksuid_base62_translate16_neon (uint8_t out[16], const uint8_t in[16]);
#  define KSUID_TRANSLATE16(out, in) ksuid_base62_translate16_neon ((out), (in))
#else
#  define KSUID_TRANSLATE16(out, in) ksuid_base62_translate16_scalar ((out), (in))
#endif

#endif /* KSUID_BASE62_SIMD_H */
