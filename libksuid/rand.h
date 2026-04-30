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

#endif /* KSUID_RAND_H */
