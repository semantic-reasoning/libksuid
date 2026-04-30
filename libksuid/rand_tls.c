/* SPDX-License-Identifier: LGPL-3.0-or-later
 *
 * Per-thread ChaCha20-keyed CSPRNG. _Thread_local state so concurrent
 * calls from distinct threads need no synchronisation; this is the
 * mechanism that makes libksuid thread-safe without ever taking a
 * lock or pulling in pthread.
 *
 * Reseed cadence (whichever fires first):
 *   - first use of the thread's state
 *   - PID change (fork detection)
 *   - wall clock moved backwards
 *   - wall clock moved forward by >= 3600 seconds
 *   - >= 1 MiB of keystream consumed since the last seed
 *
 * The PID and wall-clock checks are explicit because we deliberately
 * cannot use pthread_atfork. Caching getpid() per state and comparing
 * each call costs roughly one syscall per draw on Linux, which is
 * acceptable for a draw cadence dominated by the kernel CSPRNG seed
 * itself; if it ever shows up in profiling the obvious tightening is
 * to gate the getpid() call behind the bytes_emitted threshold.
 */
/* The for_testing helpers below are always defined; their
 * prototypes in rand.h are gated behind KSUID_TESTING so production
 * callers can't reach them. Setting KSUID_TESTING here -- before the
 * rand.h include -- pulls those prototypes into this TU and silences
 * the -Wmissing-prototypes warning that would otherwise fire on the
 * helper definitions further down. */
#define KSUID_TESTING 1
#include <libksuid/rand.h>

#include <stdbool.h>
#include <string.h>
#include <time.h>

/* Per-platform getpid abstraction: POSIX getpid(2) vs Windows
 * _getpid(3). Both return an int wide enough to hold the PID; we
 * widen to int64_t for storage so the comparison is unambiguous. */
#if defined(_WIN32)
#  include <process.h>
#  define KSUID_GETPID() ((int64_t) _getpid ())
#else
#  include <sys/types.h>
#  include <unistd.h>
#  define KSUID_GETPID() ((int64_t) getpid ())
#endif

#include <libksuid/chacha20.h>
#include <libksuid/wipe.h>

/* Thread-exit residue policy: the per-thread ksuid_tls_rng_t below
 * holds 64 bytes of ChaCha20 state plus a 64-byte keystream window.
 * On platforms with a thread-exit hook (glibc 2.18+
 * __cxa_thread_atexit_impl, MUSL >= 1.2.0, libc++abi on macOS, FLS
 * on Windows -- detected and registered in commit 2 of issue #4)
 * ksuid_random_thread_state_wipe is invoked automatically at thread
 * teardown. On platforms without such a hook the residue persists
 * until the OS reclaims the TLS block; callers requiring stronger
 * guarantees should call ksuid_random_force_reseed() before joining
 * the worker thread.
 *
 * The wipe entry point itself is implemented in this file (commit 1)
 * even when no platform hook fires, so the test harness can drive it
 * via the KSUID_TESTING-gated for_testing helpers added in commit 3.
 */

#define KSUID_RNG_RESEED_BYTES   (1u << 20)     /* 1 MiB                   */
#define KSUID_RNG_RESEED_SECONDS 3600   /* 1 hour                  */

typedef struct
{
  uint32_t state[16];
  uint8_t buf[64];
  size_t buf_pos;               /* bytes already consumed from |buf|     */
  uint64_t bytes_emitted;       /* since last seed                       */
  int64_t seed_time;            /* TIME_UTC seconds at last seed         */
  int64_t seed_pid;             /* getpid()/_getpid() at last seed       */
  bool seeded;
  bool destructor_registered;   /* thread-exit wipe registered yet?      */
} ksuid_tls_rng_t;

static _Thread_local ksuid_tls_rng_t ksuid_tls_rng_;

/* Re-entry guard for ksuid_random_thread_state_wipe. A future change
 * that adds, e.g., a debug-log call inside the wipe path could call
 * back into ksuid_random_bytes; the guarded ksuid_random_bytes path
 * returns the RNG-failure sentinel rather than reseeding into a slot
 * that is in the middle of being torn down. */
static _Thread_local bool ksuid_tls_in_destructor_;

/* Atomic counter incremented on every entry to
 * ksuid_random_thread_state_wipe. Always defined and always
 * incremented, regardless of KSUID_TESTING -- the cost is one
 * relaxed atomic increment per wipe (~5 ns on x86_64) and the
 * counter only matters to the test harness, which sees it through
 * the KSUID_TESTING-gated extern declaration in rand.h. */
#include <stdatomic.h>
_Atomic int ksuid_thread_exit_wipes_observed;

void
ksuid_random_thread_state_wipe (void)
{
  ksuid_tls_in_destructor_ = true;
  ksuid_explicit_bzero (&ksuid_tls_rng_, sizeof ksuid_tls_rng_);
  ksuid_tls_in_destructor_ = false;
  atomic_fetch_add_explicit (&ksuid_thread_exit_wipes_observed, 1,
      memory_order_relaxed);
}

void
ksuid_random_thread_state_set_sentinel_for_testing (void)
{
  /* The test must have already triggered registration on this
   * thread (via a real draw). We deliberately preserve the
   * destructor_registered flag so the previously-registered hook
   * still fires; the seeded flag is also kept true so the next
   * draw doesn't overwrite the sentinel through the seed path. */
  bool registered = ksuid_tls_rng_.destructor_registered;
  memset (&ksuid_tls_rng_, 0xa5, sizeof ksuid_tls_rng_);
  ksuid_tls_rng_.seeded = true;
  ksuid_tls_rng_.destructor_registered = registered;
}

void
ksuid_random_thread_state_peek_for_testing (uint8_t *out, size_t out_len)
{
  size_t n = sizeof ksuid_tls_rng_;
  if (out_len < n)
    n = out_len;
  memcpy (out, &ksuid_tls_rng_, n);
}

size_t
ksuid_random_thread_state_size_for_testing (void)
{
  return sizeof ksuid_tls_rng_;
}

/* Per-platform thread-exit registration. Glibc / libc++abi /
 * MUSL >= 1.2.0 expose __cxa_thread_atexit_impl, an undocumented
 * but stable libc entry point that runs callbacks at thread exit.
 * Windows uses FlsAlloc -- a Fiber Local Storage slot whose
 * destructor callback fires on thread teardown regardless of
 * static-vs-DLL link mode. Both paths are gated behind a meson
 * cc.links() probe (commit 2 of the issue #4 series); platforms
 * that don't match either branch fall through to the documented
 * residue policy in the public header. */
#if defined(KSUID_HAVE_CXA_THREAD_ATEXIT_IMPL)

/* Both identifiers below are reserved (double-underscore prefix), but
 * they're how glibc / libc++abi spell the symbols we have to call.
 * No public header declares them; we forward-declare them here. */
/* NOLINTNEXTLINE(bugprone-reserved-identifier,cert-dcl37-c,cert-dcl51-cpp) */
extern int __cxa_thread_atexit_impl (void (*fn) (void *), void *arg, void *dso);
/* NOLINTNEXTLINE(bugprone-reserved-identifier,cert-dcl37-c,cert-dcl51-cpp) */
extern void *__dso_handle;

static void
ksuid_tls_atexit_trampoline (void *unused)
{
  (void) unused;
  ksuid_random_thread_state_wipe ();
}

static void
ksuid_tls_register_thread_exit (ksuid_tls_rng_t *r)
{
  if (r->destructor_registered)
    return;
  r->destructor_registered = true;
  /* The third argument scopes the registration to this DSO so a
   * dlclose(libksuid.so) tears down its registrations cleanly.
   * __dso_handle is `void *`, so we pass its address (a `void **`)
   * cast to the `void *` ABI parameter via an explicit cast --
   * silencing bugprone-multi-level-implicit-pointer-conversion. */
  (void) __cxa_thread_atexit_impl (ksuid_tls_atexit_trampoline, NULL,
      (void *) &__dso_handle);
}

#elif defined(KSUID_HAVE_FLS)

#  define WIN32_LEAN_AND_MEAN
#  include <windows.h>

static DWORD ksuid_fls_index_ = FLS_OUT_OF_INDEXES;
static INIT_ONCE ksuid_fls_init_ = INIT_ONCE_STATIC_INIT;

/* FlsAlloc callback signature is (PVOID) under NTAPI calling
 * convention; mismatching it would corrupt the stack on x86_32 MSVC.
 * The slot value is just a non-NULL sentinel ("this thread
 * participated") -- the actual TLS state still lives in
 * _Thread_local storage and is reachable from the same thread
 * during teardown, before the runtime tears down its TLS. */
static VOID NTAPI
ksuid_fls_destroy (PVOID p)
{
  (void) p;
  ksuid_random_thread_state_wipe ();
}

static BOOL CALLBACK
ksuid_fls_init_once (PINIT_ONCE init_once, PVOID parameter, PVOID *context)
{
  (void) init_once;
  (void) parameter;
  (void) context;
  ksuid_fls_index_ = FlsAlloc (ksuid_fls_destroy);
  return TRUE;
}

static void
ksuid_tls_register_thread_exit (ksuid_tls_rng_t *r)
{
  if (r->destructor_registered)
    return;
  InitOnceExecuteOnce (&ksuid_fls_init_, ksuid_fls_init_once, NULL, NULL);
  if (ksuid_fls_index_ == FLS_OUT_OF_INDEXES)
    return;
  /* FlsSetValue with a non-NULL sentinel marks this thread as
   * participating; ksuid_fls_destroy fires on thread exit. */
  if (FlsSetValue (ksuid_fls_index_, (PVOID) (uintptr_t) 1))
    r->destructor_registered = true;
}

#else /* No thread-exit hook on this platform */

static void
ksuid_tls_register_thread_exit (ksuid_tls_rng_t *r)
{
  /* Documented residue path: nothing to register. The bounded
   * reseed cadence and ksuid_random_force_reseed are the only
   * mitigations. */
  (void) r;
}

#endif

/* Returns wall-clock seconds (TIME_UTC), or -1 on clock failure. The
 * sentinel makes the should-reseed predicate fall through to the
 * "now < seed_time" branch which forces a reseed -- the conservative
 * choice when the clock is unreadable. timespec_get is C11 standard
 * and available on glibc 2.16+, MSVC 2015+, and macOS 10.15+. */
static int64_t
ksuid_now_seconds (void)
{
  struct timespec ts;
  if (timespec_get (&ts, TIME_UTC) != TIME_UTC)
    return -1;
  return (int64_t) ts.tv_sec;
}

static int
ksuid_tls_rng_seed (ksuid_tls_rng_t *r)
{
  uint8_t kn[44];               /* 32 key + 12 nonce */
  if (ksuid_os_random_bytes (kn, sizeof kn) < 0) {
    /* Wipe partial seed bytes before returning. */
    ksuid_explicit_bzero (kn, sizeof kn);
    return -1;
  }
  r->state[0] = KSUID_CHACHA20_C0;
  r->state[1] = KSUID_CHACHA20_C1;
  r->state[2] = KSUID_CHACHA20_C2;
  r->state[3] = KSUID_CHACHA20_C3;
  for (int i = 0; i < 8; ++i) {
    r->state[4 + i] = (uint32_t) kn[i * 4 + 0]
        | ((uint32_t) kn[i * 4 + 1] << 8)
        | ((uint32_t) kn[i * 4 + 2] << 16)
        | ((uint32_t) kn[i * 4 + 3] << 24);
  }
  r->state[12] = 0;
  for (int i = 0; i < 3; ++i) {
    r->state[13 + i] = (uint32_t) kn[32 + i * 4 + 0]
        | ((uint32_t) kn[32 + i * 4 + 1] << 8)
        | ((uint32_t) kn[32 + i * 4 + 2] << 16)
        | ((uint32_t) kn[32 + i * 4 + 3] << 24);
  }
  /* Wipe seed material from local. The chacha state itself stays in
   * TLS, but at least we limit the residue from leaving on the
   * stack frame after this function returns. */
  ksuid_explicit_bzero (kn, sizeof kn);

  /* r->buf is about to be overwritten by the first chacha block; the
   * memset is initialisation, not secret-erasure, so plain memset is
   * fine here. */
  memset (r->buf, 0, sizeof r->buf);
  r->buf_pos = sizeof r->buf;   /* empty buffer, force first block */
  r->bytes_emitted = 0;
  r->seed_pid = KSUID_GETPID ();
  r->seed_time = ksuid_now_seconds ();
  /* Register the thread-exit wipe BEFORE flipping the seeded flag
   * -- if registration fails partway and the thread later exits we
   * must not have a half-wired state where the TLS slot looks
   * seeded but the destructor never fires. The registration is
   * idempotent via r->destructor_registered, so calling it on
   * every reseed is cheap. */
  ksuid_tls_register_thread_exit (r);
  r->seeded = true;
  return 0;
}

static bool
ksuid_tls_rng_should_reseed (const ksuid_tls_rng_t *r)
{
  if (!r->seeded)
    return true;
  if (r->bytes_emitted >= KSUID_RNG_RESEED_BYTES)
    return true;
  if (KSUID_GETPID () != r->seed_pid)
    return true;
  int64_t now = ksuid_now_seconds ();
  /* now == -1 (clock failure) makes this branch fire -- safer to
   * burn an extra reseed than to keep streaming from stale state. */
  if (now < r->seed_time)
    return true;
  if (now - r->seed_time >= KSUID_RNG_RESEED_SECONDS)
    return true;
  return false;
}

void
ksuid_random_force_reseed (void)
{
  ksuid_tls_rng_.seeded = false;
}

int
ksuid_random_bytes (uint8_t *buf, size_t n)
{
  /* Re-entry from inside ksuid_random_thread_state_wipe is a bug:
   * it would reseed into a TLS slot that is being torn down. Bail
   * with the RNG-failure sentinel so the caller surfaces the
   * problem. */
  if (ksuid_tls_in_destructor_)
    return -1;
  ksuid_tls_rng_t *r = &ksuid_tls_rng_;
  if (ksuid_tls_rng_should_reseed (r)) {
    if (ksuid_tls_rng_seed (r) < 0)
      return -1;
  }
  while (n > 0) {
    if (r->buf_pos == sizeof r->buf) {
      ksuid_chacha20_block (r->buf, r->state);
      r->buf_pos = 0;
    }
    size_t avail = sizeof r->buf - r->buf_pos;
    size_t chunk = (n < avail) ? n : avail;
    memcpy (buf, r->buf + r->buf_pos, chunk);
    /* Wipe consumed keystream to limit forward exposure if memory is
     * later inspected. ksuid_explicit_bzero blocks DSE here -- a
     * plain memset would be elided by -O2 because the wiped bytes
     * are not subsequently read. */
    ksuid_explicit_bzero (r->buf + r->buf_pos, chunk);
    r->buf_pos += chunk;
    buf += chunk;
    n -= chunk;
    r->bytes_emitted += chunk;
  }
  return 0;
}
