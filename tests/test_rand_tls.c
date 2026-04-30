/* SPDX-License-Identifier: LGPL-3.0-or-later */
#include <libksuid/rand.h>
#include "test_util.h"

#include <threads.h>
#include <stdint.h>

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

int
main (void)
{
  RUN_TEST (test_two_calls_produce_distinct_output);
  RUN_TEST (test_zero_length_call_is_noop);
  RUN_TEST (test_large_buffer_spans_multiple_chacha_blocks);
  RUN_TEST (test_force_reseed_stays_random);
  RUN_TEST (test_threads_get_independent_streams);
  TEST_MAIN_END ();
}
