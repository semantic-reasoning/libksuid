/* SPDX-License-Identifier: LGPL-3.0-or-later */
#ifndef KSUID_RAND_H
#define KSUID_RAND_H

#include <stddef.h>
#include <stdint.h>

/* Fill |buf| with |n| cryptographically-secure random bytes obtained
 * from the operating system's entropy source. Returns 0 on success
 * and -1 on failure (no entropy source available). The implementation
 * tries, in order: getrandom(2), getentropy(3), BCryptGenRandom (on
 * Windows), and finally a /dev/urandom read. None of these fall back
 * to a non-cryptographic source: a failure here MUST propagate to the
 * caller -- silently producing zero or low-entropy bytes from an ID
 * library would be a worst-case correctness bug. */
int ksuid_os_random_bytes (uint8_t * buf, size_t n);

/* Fill |buf| with |n| random bytes from the per-thread CSPRNG
 * (ChaCha20 keyed from ksuid_os_random_bytes). State is _Thread_local
 * so concurrent calls from distinct threads need no synchronisation;
 * concurrent calls from the same thread are NOT supported. The state
 * is reseeded on first use, after fork(), if the wall clock moves
 * backwards or runs forward by more than an hour, and after every 1
 * MiB of keystream. Returns 0 on success and -1 if the underlying OS
 * entropy source is unavailable at the moment of (re)seed. */
int ksuid_random_bytes (uint8_t * buf, size_t n);

/* For testing: force the calling thread's CSPRNG state to reseed on
 * its next ksuid_random_bytes call. */
void ksuid_random_force_reseed (void);

/* Issue #4 thread-exit hook. Wipes the calling thread's CSPRNG
 * state in place via ksuid_explicit_bzero so the 64-byte ChaCha20
 * state and the 64-byte keystream window do not survive the thread
 * after it exits.
 *
 * Commit 1 of the issue #4 series provides the function body; the
 * platform-specific automatic registration (__cxa_thread_atexit_impl
 * on glibc / libc++abi / MUSL >= 1.2.0; FlsAlloc on Windows) lands
 * in commit 2. Without that registration the function is reachable
 * only via the test harness or a manual call from a downstream
 * caller. */
void ksuid_random_thread_state_wipe (void);

#ifdef KSUID_TESTING
/* Test-only hooks compiled into the test binary via -DKSUID_TESTING=1
 * (set per-test in tests/meson.build). They give tests/test_rand_tls.c
 * a way to drive the wipe path deterministically without depending on
 * thread-exit timing, and to peek at the post-wipe TLS state to prove
 * the bytes were actually zeroed. None of these symbols are exported
 * from the library; production builds compile without -DKSUID_TESTING
 * and never see the prototypes. */

/* Atomic counter incremented on every entry to
 * ksuid_random_thread_state_wipe. The test asserts it ticks when the
 * destructor runs at thread exit. */
extern _Atomic int ksuid_thread_exit_wipes_observed;

/* Fill the calling thread's TLS RNG state with a known sentinel
 * pattern (0xa5 throughout, including the seeded flag) so the next
 * call to ksuid_random_thread_state_wipe has something non-zero to
 * erase. Must be called before any draw on the same thread. */
void ksuid_random_thread_state_set_sentinel_for_testing (void);

/* Copy the calling thread's TLS RNG state bytes into |out| (which
 * must be at least sizeof(ksuid_tls_rng_t) -- the test is allowed to
 * over-allocate). Used to assert the wipe actually zeroed the
 * region. */
void ksuid_random_thread_state_peek_for_testing (uint8_t * out, size_t out_len);

/* Size in bytes that a peek buffer must accommodate. */
size_t ksuid_random_thread_state_size_for_testing (void);
#endif

#endif /* KSUID_RAND_H */
