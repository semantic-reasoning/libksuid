/* SPDX-License-Identifier: LGPL-3.0-or-later
 *
 * Specialised 20-byte compare kernels used by ksuid_compare. The
 * scalar fallback is always compiled and is the parity reference for
 * the SSE2 / NEON kernels (every host with -DKSUID_TESTING runs the
 * differential test against it regardless of which path the
 * production library selects).
 *
 * Compile-time dispatch only: SSE2 is part of the x86_64 ABI baseline
 * and NEON is mandatory on aarch64, so a runtime feature check would
 * not buy anything. The atomic-pointer scaffolding lives in
 * encode_batch.c for the AVX2 bulk encode where AVX2 is NOT baseline.
 *
 * Contract for every kernel: returns -1 if a < b lexicographically,
 *   0 if a == b, +1 if a > b. Inputs are 20 bytes each. Same
 * semantics as ksuid_compare; see libksuid/ksuid.h for the public
 * documentation of the ordering invariant.
 */
#ifndef KSUID_COMPARE_SIMD_H
#define KSUID_COMPARE_SIMD_H

#include <stdint.h>

int ksuid_compare20_scalar (const uint8_t a[20], const uint8_t b[20]);

#if defined(KSUID_HAVE_SSE2)
int ksuid_compare20_sse2 (const uint8_t a[20], const uint8_t b[20]);
#  define KSUID_COMPARE20(a, b) ksuid_compare20_sse2 ((a), (b))
#elif defined(KSUID_HAVE_NEON)
int ksuid_compare20_neon (const uint8_t a[20], const uint8_t b[20]);
#  define KSUID_COMPARE20(a, b) ksuid_compare20_neon ((a), (b))
#else
#  define KSUID_COMPARE20(a, b) ksuid_compare20_scalar ((a), (b))
#endif

#endif /* KSUID_COMPARE_SIMD_H */
