/* SPDX-License-Identifier: LGPL-3.0-or-later
 *
 * ksuid_string_batch dispatcher and scalar reference. The AVX2
 * 8-wide kernel lives in encode_avx2.c (compiled only when meson
 * detects an x86_64 host with -Davx2_batch enabled, default auto).
 *
 * Dispatch idiom (libsodium-style "trampoline-as-initial-pointer"):
 *
 *   static _Atomic(fn_t) g_impl = &trampoline;
 *   void ksuid_string_batch(...) {
 *     fn_t f = atomic_load_explicit(&g_impl, memory_order_acquire);
 *     f(...);
 *   }
 *
 *   static void trampoline(...) {
 *     fn_t resolved = pick_best_kernel();   // CPUID + cpu_init
 *     atomic_store_explicit(&g_impl, resolved, memory_order_release);
 *     resolved(...);                        // tail-call
 *   }
 *
 * Race-free: N concurrent first-callers each run the trampoline
 * (cheap, one CPUID), each store the same resolved pointer, and the
 * extra stores are harmless. There is no allocation, so the loser
 * has nothing to leak. Subsequent calls see a single acquire load.
 *
 * On non-x86_64 hosts the resolver is a compile-time constant
 * (&ksuid_string_batch_scalar) and the AVX2 TU is excluded from the
 * build entirely.
 */
#include <libksuid/encode_batch.h>

#include <stdatomic.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>

#if defined(__x86_64__) || defined(_M_X64)
#  if defined(__GNUC__) || defined(__clang__)
#    include <cpuid.h>
#  endif
#endif

void
ksuid_string_batch_scalar (const ksuid_t *ids, char *out_27n, size_t n)
{
  /* Plain per-ID loop calling the existing scalar formatter. The
   * compiler can't auto-vectorise the long-division-by-62 inner
   * loop (the carry chain is sequential per ID) but it has every
   * other inlining opportunity available. */
  for (size_t i = 0; i < n; ++i)
    ksuid_format (&ids[i], out_27n + i * KSUID_STRING_LEN);
}

#if defined(KSUID_HAVE_AVX2_BATCH)

/* CPUID-based AVX2 detection. Two checks: bit 5 of EBX from leaf
 * 7 sub-leaf 0 (AVX2 instruction support) AND XGETBV bit 2 (the
 * kernel saves YMM state on context switches). Without the XGETBV
 * check, an AVX2-supporting CPU running on a kernel that doesn't
 * preserve YMM state (rare but real on misconfigured embedded
 * builds) would corrupt registers across system calls. */
static int
ksuid_cpu_supports_avx2 (void)
{
#  if defined(__GNUC__) || defined(__clang__)
  /* glibc's __builtin_cpu_supports requires __builtin_cpu_init
   * before its first invocation; the table it reads is populated
   * only by that call. */
  __builtin_cpu_init ();
  if (!__builtin_cpu_supports ("avx2"))
    return 0;
  /* __builtin_cpu_supports already checks XGETBV/OS-saves-YMM on
   * recent glibc, so there is no need to repeat the bit-2 test
   * here. The cost of the explicit check is negligible if a future
   * libc drops the OS-state guarantee. */
  unsigned eax, ebx, ecx, edx;
  if (__get_cpuid_count (7, 0, &eax, &ebx, &ecx, &edx) == 0)
    return 0;
  return (ebx & (1u << 5)) != 0;
#  elif defined(_MSC_VER)
  int regs[4];
  __cpuidex (regs, 7, 0);
  if ((regs[1] & (1 << 5)) == 0)
    return 0;
  /* MSVC: check XGETBV bit 2 directly. _xgetbv is in <immintrin.h>. */
  unsigned long long xcr = _xgetbv (0);
  return (xcr & 0x6) == 0x6;
#  else
  return 0;
#  endif
}

#endif /* KSUID_HAVE_AVX2_BATCH */

static void
ksuid_string_batch_init_trampoline (const ksuid_t * ids, char *out_27n,
    size_t n);

/* _Atomic-qualified pointer, not _Atomic(T) shorthand -- the latter
 * confuses gst-indent (it parses _Atomic(T) as a function call). */
static _Atomic ksuid_string_batch_fn g_batch_impl =
    &ksuid_string_batch_init_trampoline;

/* KSUID_FORCE_SCALAR override (Critic R11). Reading getenv on the
 * first dispatch only is safe -- the resolved pointer is cached for
 * the lifetime of the process and the env var is consulted exactly
 * once. The override exists so production deployments can pin the
 * scalar path at startup if a future regression in the AVX2 kernel
 * is discovered after rollout, without rebuilding the library.
 *
 * Recognised values: any non-empty, non-"0", non-"false" string
 * disables the AVX2 kernel. NULL or unset = use the best kernel
 * available on the host. */
static int
ksuid_force_scalar_env (void)
{
  const char *v = getenv ("KSUID_FORCE_SCALAR");
  if (v == NULL || v[0] == '\0')
    return 0;
  if (strcmp (v, "0") == 0 || strcmp (v, "false") == 0
      || strcmp (v, "FALSE") == 0)
    return 0;
  return 1;
}

static void
ksuid_string_batch_init_trampoline (const ksuid_t *ids, char *out_27n, size_t n)
{
  ksuid_string_batch_fn resolved = &ksuid_string_batch_scalar;
#if defined(KSUID_HAVE_AVX2_BATCH)
  if (!ksuid_force_scalar_env () && ksuid_cpu_supports_avx2 ())
    resolved = &ksuid_string_batch_avx2;
#else
  (void) ksuid_force_scalar_env;        /* silence unused-static warning */
#endif
  atomic_store_explicit (&g_batch_impl, resolved, memory_order_release);
  resolved (ids, out_27n, n);
}

void
ksuid_string_batch (const ksuid_t *ids, char *out_27n, size_t n)
{
  /* The n == 0 early-out lives here, before the dispatch indirect
   * call, so callers passing 0 don't pay for the atomic load. */
  if (n == 0)
    return;
  ksuid_string_batch_fn f =
      atomic_load_explicit (&g_batch_impl, memory_order_acquire);
  f (ids, out_27n, n);
}
