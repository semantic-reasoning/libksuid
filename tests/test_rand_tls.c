/* SPDX-License-Identifier: LGPL-3.0-or-later */
#include <libksuid/rand.h>
#include "test_util.h"

#include <threads.h>
#include <stdint.h>
#include <stdlib.h>
#ifdef KSUID_TESTING
#  include <stdatomic.h>
#endif

static void
test_two_calls_produce_distinct_output (void)
{
  uint8_t a[16], b[16];
  ASSERT_EQ_INT (ksuid_random_bytes (a, sizeof a), 0);
  ASSERT_EQ_INT (ksuid_random_bytes (b, sizeof b), 0);
  ASSERT_TRUE (memcmp (a, b, sizeof a) != 0);
}

static void
test_zero_length_call_is_noop (void)
{
  uint8_t buf[1] = { 0xab };
  ASSERT_EQ_INT (ksuid_random_bytes (buf, 0), 0);
  ASSERT_EQ_INT (buf[0], 0xab);
}

static void
test_large_buffer_spans_multiple_chacha_blocks (void)
{
  /* Each ChaCha20 block is 64 bytes. Asking for 1 MiB exercises the
   * reseed boundary too. */
  uint8_t *buf = malloc (1u << 20);
  ASSERT_TRUE (buf != NULL);
  ASSERT_EQ_INT (ksuid_random_bytes (buf, 1u << 20), 0);
  size_t nonzero = 0;
  for (size_t i = 0; i < (1u << 20); ++i)
    if (buf[i] != 0)
      ++nonzero;
  /* Heuristic: a real CSPRNG fills at least a third with nonzero. */
  ASSERT_TRUE (nonzero > (1u << 18));
  free (buf);
}

static void
test_force_reseed_stays_random (void)
{
  uint8_t a[16], b[16];
  ASSERT_EQ_INT (ksuid_random_bytes (a, sizeof a), 0);
  ksuid_random_force_reseed ();
  ASSERT_EQ_INT (ksuid_random_bytes (b, sizeof b), 0);
  ASSERT_TRUE (memcmp (a, b, sizeof a) != 0);
}

/* Each thread fills its own 64-byte buffer; the orchestrator then
 * verifies all four buffers are pairwise distinct. This is the
 * concrete demonstration that _Thread_local state isolates streams
 * without any pthread synchronisation. */
#define KSUID_TEST_THREADS 4
typedef struct
{
  uint8_t out[64];
  int rc;
} ksuid_thread_arg_t;

static int
thread_body (void *opaque)
{
  ksuid_thread_arg_t *a = opaque;
  a->rc = ksuid_random_bytes (a->out, sizeof a->out);
  return 0;
}

static void
test_threads_get_independent_streams (void)
{
  thrd_t t[KSUID_TEST_THREADS];
  ksuid_thread_arg_t args[KSUID_TEST_THREADS] = { 0 };
  for (size_t i = 0; i < KSUID_TEST_THREADS; ++i)
    ASSERT_EQ_INT (thrd_create (&t[i], thread_body, &args[i]), thrd_success);
  for (size_t i = 0; i < KSUID_TEST_THREADS; ++i)
    ASSERT_EQ_INT (thrd_join (t[i], NULL), thrd_success);

  for (size_t i = 0; i < KSUID_TEST_THREADS; ++i) {
    ASSERT_EQ_INT (args[i].rc, 0);
    for (size_t j = i + 1; j < KSUID_TEST_THREADS; ++j) {
      ASSERT_TRUE (memcmp (args[i].out, args[j].out, 64) != 0);
    }
  }
}

#ifdef KSUID_TESTING
/* Issue #4 thread-exit wipe regression test. The thread body sets a
 * 0xa5 sentinel pattern in the TLS state, peeks to confirm the
 * sentinel is in place, then exits. The platform-registered
 * destructor is supposed to fire during thrd_join, calling
 * ksuid_random_thread_state_wipe and incrementing the observed
 * counter. The main thread asserts the counter ticked.
 *
 * On platforms that don't have a thread-exit hook (the documented-
 * residue lane) the destructor never runs; meson does NOT compile
 * test_rand_tls with -DKSUID_TESTING on those lanes. The test is
 * skipped at compile time via the #ifdef KSUID_TESTING guard. */
static int
sentinel_thread_body (void *opaque)
{
  (void) opaque;
  /* A real draw triggers the seed path which registers the
   * thread-exit destructor on this thread (issue #4 commit 2).
   * Without this, set_sentinel runs into a slot whose
   * destructor_registered flag is false and the destructor never
   * fires on thread exit. */
  uint8_t one[1];
  if (ksuid_random_bytes (one, 1) != 0)
    return -1;
  /* Now overwrite the live state with the sentinel pattern. The
   * registered destructor still fires at thread exit and wipes
   * whatever is in the slot. */
  ksuid_random_thread_state_set_sentinel_for_testing ();
  /* Sanity check: the sentinel landed in the slot. */
  size_t n = ksuid_random_thread_state_size_for_testing ();
  uint8_t *peek = malloc (n);
  if (peek == NULL)
    return -1;
  ksuid_random_thread_state_peek_for_testing (peek, n);
  size_t a5_count = 0;
  for (size_t i = 0; i < n; ++i)
    if (peek[i] == 0xa5)
      ++a5_count;
  free (peek);
  /* At least 64 bytes of state[16] plus 64 bytes of buf must be
   * the sentinel (the bool flags read as 1, not 0xa5, but everything
   * else does). Use a conservative lower bound. */
  if (a5_count < 128)
    return -2;
  return 0;
}

static void
test_thread_exit_wipes_tls_state (void)
{
  int before = atomic_load_explicit (&ksuid_thread_exit_wipes_observed,
      memory_order_relaxed);
  thrd_t t;
  ASSERT_EQ_INT (thrd_create (&t, sentinel_thread_body, NULL), thrd_success);
  int rc = -999;
  ASSERT_EQ_INT (thrd_join (t, &rc), thrd_success);
  ASSERT_EQ_INT (rc, 0);
  /* The platform thread-exit hook runs ksuid_random_thread_state_wipe
   * inside thrd_join's teardown. The atomic counter must have ticked
   * by exactly 1. */
  int after = atomic_load_explicit (&ksuid_thread_exit_wipes_observed,
      memory_order_relaxed);
  ASSERT_EQ_INT (after - before, 1);
}
#endif

int
main (void)
{
  RUN_TEST (test_two_calls_produce_distinct_output);
  RUN_TEST (test_zero_length_call_is_noop);
  RUN_TEST (test_large_buffer_spans_multiple_chacha_blocks);
  RUN_TEST (test_force_reseed_stays_random);
  RUN_TEST (test_threads_get_independent_streams);
#ifdef KSUID_TESTING
  RUN_TEST (test_thread_exit_wipes_tls_state);
#endif
  TEST_MAIN_END ();
}
