/* SPDX-License-Identifier: LGPL-3.0-or-later
 *
 * Internal declarations for ksuid_string_batch and the dispatch
 * scaffolding it sits on. Public callers go through
 * libksuid/ksuid.h's KSUID_PUBLIC ksuid_string_batch.
 *
 * The pattern: a single _Atomic function pointer is initialised at
 * load time to a "trampoline" that, on first call, runs feature
 * detection (CPUID on x86_64), atomic-stores the resolved kernel
 * pointer, and tail-calls it. Idempotent: if N threads hit the
 * trampoline concurrently, all of them perform detection (cheap, one
 * CPUID) and all of them write the same pointer; the loser stores
 * are harmless. Subsequent calls take a single acquire-load and an
 * indirect call -- ~free vs the ~20 cycles of the encode body.
 */
#ifndef KSUID_ENCODE_BATCH_H
#define KSUID_ENCODE_BATCH_H

#include <stddef.h>

#include <libksuid/ksuid.h>

typedef void (*ksuid_string_batch_fn) (const ksuid_t * ids, char *out_27n,
    size_t n);

/* Always-compiled scalar reference. Used by tests as the parity
 * baseline regardless of which production kernel is selected. */
void ksuid_string_batch_scalar (const ksuid_t * ids, char *out_27n, size_t n);

#if defined(KSUID_HAVE_AVX2_BATCH)
/* AVX2 8-wide kernel. Linked in only when meson detects an x86_64
 * host with -Davx2_batch enabled. Tail (n % 8) handled by falling
 * through to the scalar loop inside the kernel itself. */
void ksuid_string_batch_avx2 (const ksuid_t * ids, char *out_27n, size_t n);
#endif

#endif /* KSUID_ENCODE_BATCH_H */
