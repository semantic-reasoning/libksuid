/* SPDX-License-Identifier: LGPL-3.0-or-later */
#include <libksuid/ksuid.h>
#include "test_util.h"

static void
make_seed (ksuid_t *seed)
{
  /* Distinct nonzero pattern so we can tell the seed apart from the
   * sequence-applied counter bytes. */
  for (size_t i = 0; i < KSUID_BYTES; ++i)
    seed->b[i] = (uint8_t) (0x10 + i);
}

static void
test_sequence_first_writes_zero_counter (void)
{
  ksuid_sequence_t s;
  ksuid_t seed;
  make_seed (&seed);
  ksuid_sequence_init (&s, &seed);

  ksuid_t out;
  ASSERT_EQ_INT (ksuid_sequence_next (&s, &out), KSUID_OK);
  /* Leading 18 bytes preserved, last two are big-endian 0x0000. */
  ASSERT_EQ_BYTES (out.b, seed.b, KSUID_BYTES - 2);
  ASSERT_EQ_INT (out.b[KSUID_BYTES - 2], 0);
  ASSERT_EQ_INT (out.b[KSUID_BYTES - 1], 0);
}

static void
test_sequence_emits_big_endian_counter (void)
{
  ksuid_sequence_t s;
  ksuid_t seed;
  make_seed (&seed);
  ksuid_sequence_init (&s, &seed);

  /* Skip ahead to count = 0x0102, which exercises both bytes. */
  s.count = 0x0102;

  ksuid_t out;
  ASSERT_EQ_INT (ksuid_sequence_next (&s, &out), KSUID_OK);
  ASSERT_EQ_INT (out.b[KSUID_BYTES - 2], 0x01);
  ASSERT_EQ_INT (out.b[KSUID_BYTES - 1], 0x02);
  /* Leading 18 bytes still match the seed. */
  ASSERT_EQ_BYTES (out.b, seed.b, KSUID_BYTES - 2);
}

static void
test_sequence_exhausts_after_65536 (void)
{
  ksuid_sequence_t s;
  ksuid_t seed;
  make_seed (&seed);
  ksuid_sequence_init (&s, &seed);

  ksuid_t out;
  /* Fast-forward to the 65535th iteration without spinning a real loop. */
  s.count = UINT16_MAX;
  ASSERT_EQ_INT (ksuid_sequence_next (&s, &out), KSUID_OK);
  ASSERT_EQ_INT (out.b[KSUID_BYTES - 2], 0xff);
  ASSERT_EQ_INT (out.b[KSUID_BYTES - 1], 0xff);
  /* The 65537th call must fail. */
  ASSERT_EQ_INT (ksuid_sequence_next (&s, &out), KSUID_ERR_EXHAUSTED);
}

static void
test_sequence_emits_strictly_increasing (void)
{
  ksuid_sequence_t s;
  ksuid_t seed;
  make_seed (&seed);
  ksuid_sequence_init (&s, &seed);

  ksuid_t prev, cur;
  ASSERT_EQ_INT (ksuid_sequence_next (&s, &prev), KSUID_OK);
  for (size_t i = 1; i < 1024; ++i) {
    ASSERT_EQ_INT (ksuid_sequence_next (&s, &cur), KSUID_OK);
    ASSERT_TRUE (ksuid_compare (&prev, &cur) < 0);
    prev = cur;
  }
}

static void
test_sequence_bounds_match_documentation (void)
{
  ksuid_sequence_t s;
  ksuid_t seed;
  make_seed (&seed);
  ksuid_sequence_init (&s, &seed);

  ksuid_t lo, hi;
  /* Pre-iteration: min counter = 0, max counter = 0xFFFF. */
  ksuid_sequence_bounds (&s, &lo, &hi);
  ASSERT_EQ_INT (lo.b[KSUID_BYTES - 2], 0x00);
  ASSERT_EQ_INT (lo.b[KSUID_BYTES - 1], 0x00);
  ASSERT_EQ_INT (hi.b[KSUID_BYTES - 2], 0xff);
  ASSERT_EQ_INT (hi.b[KSUID_BYTES - 1], 0xff);

  /* Post-exhaustion: bounds clamps min counter to 0xFFFF. */
  s.count = UINT16_MAX + 5u;
  ksuid_sequence_bounds (&s, &lo, &hi);
  ASSERT_EQ_INT (lo.b[KSUID_BYTES - 2], 0xff);
  ASSERT_EQ_INT (lo.b[KSUID_BYTES - 1], 0xff);
  ASSERT_EQ_INT (ksuid_compare (&lo, &hi), 0);
}

int
main (void)
{
  RUN_TEST (test_sequence_first_writes_zero_counter);
  RUN_TEST (test_sequence_emits_big_endian_counter);
  RUN_TEST (test_sequence_exhausts_after_65536);
  RUN_TEST (test_sequence_emits_strictly_increasing);
  RUN_TEST (test_sequence_bounds_match_documentation);
  TEST_MAIN_END ();
}
