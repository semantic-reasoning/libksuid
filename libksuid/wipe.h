/* SPDX-License-Identifier: LGPL-3.0-or-later
 *
 * DSE-resistant zeroizer. Plain memset(p, 0, n) on a buffer that the
 * compiler proves is "dead" (never read again) is allowed -- and at
 * -O2 and beyond, encouraged -- to be elided entirely. For sensitive
 * material (CSPRNG seed, ChaCha20 internal state, freshly-drawn key
 * bytes) that is exactly the wrong outcome.
 *
 * ksuid_explicit_bzero picks the strongest DSE-immune primitive the
 * compile target offers, in this order:
 *
 *   1. explicit_bzero  (glibc 2.25+, MUSL, *BSD, macOS 14.4+)
 *      Documented to resist optimisation; canonical answer.
 *      Header lives in <strings.h> on Linux/FreeBSD/NetBSD;
 *      <string.h> on OpenBSD/macOS. Two meson probes pick.
 *
 *   2. SecureZeroMemory  (Windows, <windows.h>)
 *      MSDN explicitly guarantees the writes are not optimised
 *      away. Macro over RtlSecureZeroMemory.
 *
 *   3. memset_s  (C11 Annex K)
 *      Rare; gated behind __STDC_LIB_EXT1__. Required to be
 *      DSE-immune by the standard.
 *
 *   4. Portable fallback: indirect call through a `volatile`
 *      function pointer to memset, followed by a memory-clobber
 *      barrier. The volatile qualifier on the pointer forces the
 *      compiler to actually re-read it and emit the call; the
 *      barrier prevents post-call dead-code analysis from proving
 *      the writes are unobserved.
 *
 * The fallback is correct on every C11 toolchain we target but
 * empirically a few rungs slower than explicit_bzero / Secure-
 * ZeroMemory because it goes through an indirect call. CI on the
 * Linux GCC lane runs an objdump grep that fails the build if the
 * compiler elided the wipe.
 *
 * Issue #2 scope: short-lived locals (44-byte seed buffer in
 * rand_tls.c, 64-byte keystream chunks, 16-word ChaCha state).
 * Long-lived TLS state at thread-exit is issue #4.
 */
#ifndef KSUID_WIPE_H
#define KSUID_WIPE_H

#include <stddef.h>
#include <string.h>

/* The KSUID_FORCE_VOLATILE_FALLBACK build flag bypasses every
 * platform-specific primitive and forces the indirect-call-through-
 * volatile path. It exists so CI can exercise the fallback even on
 * a host that has explicit_bzero / SecureZeroMemory available --
 * without it the fallback ships unverified on every supported
 * matrix lane. Production builds never set this. */
#if !defined(KSUID_FORCE_VOLATILE_FALLBACK)
#  if defined(KSUID_HAVE_EXPLICIT_BZERO_STRINGS_H)
#    include <strings.h>
#  elif defined(KSUID_HAVE_EXPLICIT_BZERO_STRING_H)
/* explicit_bzero already pulled in by <string.h> above. */
#  elif defined(_WIN32) || defined(__CYGWIN__)
#    define WIN32_LEAN_AND_MEAN
#    include <windows.h>
#  elif defined(KSUID_HAVE_MEMSET_S)
/* __STDC_WANT_LIB_EXT1__ is set project-wide by meson when this
 * branch is selected -- defining it here would be too late, the
 * unconditional <string.h> include at the top of this header has
 * already burned the prototype set without it. */
#  endif
#endif

static inline void
ksuid_explicit_bzero (void *p, size_t n)
{
  if (p == NULL || n == 0)
    return;

#if !defined(KSUID_FORCE_VOLATILE_FALLBACK) && \
    (defined(KSUID_HAVE_EXPLICIT_BZERO_STRINGS_H) \
     || defined(KSUID_HAVE_EXPLICIT_BZERO_STRING_H))
  explicit_bzero (p, n);
#elif !defined(KSUID_FORCE_VOLATILE_FALLBACK) && \
    (defined(_WIN32) || defined(__CYGWIN__))
  SecureZeroMemory (p, n);
#elif !defined(KSUID_FORCE_VOLATILE_FALLBACK) \
    && defined(KSUID_HAVE_MEMSET_S)
  memset_s (p, n, 0, n);
#else
  /* Indirect-call-through-volatile fallback. The function pointer
   * is volatile-qualified, so the compiler must re-read it and
   * emit a real call -- it cannot inline memset and elide the
   * stores via DSE. The trailing memory clobber on GCC/Clang
   * blocks any post-call dead-code reasoning.
   *
   * On MSVC <intrin.h>'s _ReadWriteBarrier serves the same role,
   * but MSVC builds use the SecureZeroMemory branch above so this
   * fallback is GCC/Clang in practice. */
  static void *(*const volatile ksuid_memset_v) (void *, int, size_t) = memset;
  ksuid_memset_v (p, 0, n);
#  if defined(__GNUC__) || defined(__clang__)
  __asm__ __volatile__ (""::"r" (p):"memory");
#  endif
#endif
}

#endif /* KSUID_WIPE_H */
