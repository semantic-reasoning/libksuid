/* SPDX-License-Identifier: LGPL-3.0-or-later */
#include <libksuid/chacha20.h>
#include "test_util.h"

/* RFC 8439 section 2.3.2 test vector.
 *   Key:     00:01:02:...:1f
 *   Counter: 0x00000001
 *   Nonce:   00:00:00:09:00:00:00:4a:00:00:00:00
 *   Expected keystream block: see below. */
static void
test_rfc8439_block (void)
{
  uint32_t state[16] = {
    KSUID_CHACHA20_C0, KSUID_CHACHA20_C1,
    KSUID_CHACHA20_C2, KSUID_CHACHA20_C3,
    /* key as 8 little-endian uint32s */
    0x03020100u, 0x07060504u, 0x0b0a0908u, 0x0f0e0d0cu,
    0x13121110u, 0x17161514u, 0x1b1a1918u, 0x1f1e1d1cu,
    /* counter, then nonce as 3 little-endian uint32s */
    0x00000001u,
    0x09000000u, 0x4a000000u, 0x00000000u,
  };

  static const uint8_t expected[64] = {
    0x10, 0xf1, 0xe7, 0xe4, 0xd1, 0x3b, 0x59, 0x15,
    0x50, 0x0f, 0xdd, 0x1f, 0xa3, 0x20, 0x71, 0xc4,
    0xc7, 0xd1, 0xf4, 0xc7, 0x33, 0xc0, 0x68, 0x03,
    0x04, 0x22, 0xaa, 0x9a, 0xc3, 0xd4, 0x6c, 0x4e,
    0xd2, 0x82, 0x64, 0x46, 0x07, 0x9f, 0xaa, 0x09,
    0x14, 0xc2, 0xd7, 0x05, 0xd9, 0x8b, 0x02, 0xa2,
    0xb5, 0x12, 0x9c, 0xd1, 0xde, 0x16, 0x4e, 0xb9,
    0xcb, 0xd0, 0x83, 0xe8, 0xa2, 0x50, 0x3c, 0x4e,
  };

  uint8_t out[64];
  ksuid_chacha20_block (out, state);
  ASSERT_EQ_BYTES (out, expected, 64);
  /* Counter should have advanced from 1 to 2. */
  ASSERT_EQ_INT (state[12], 2);
}

static void
test_block_increments_counter (void)
{
  uint32_t state[16] = {
    KSUID_CHACHA20_C0, KSUID_CHACHA20_C1,
    KSUID_CHACHA20_C2, KSUID_CHACHA20_C3,
    0, 0, 0, 0, 0, 0, 0, 0,
    0,                          /* counter */
    0, 0, 0,
  };
  uint8_t out[64];
  ksuid_chacha20_block (out, state);
  ASSERT_EQ_INT (state[12], 1);
  ksuid_chacha20_block (out, state);
  ASSERT_EQ_INT (state[12], 2);
}

static void
test_distinct_counters_yield_distinct_blocks (void)
{
  uint32_t s1[16] = {
    KSUID_CHACHA20_C0, KSUID_CHACHA20_C1,
    KSUID_CHACHA20_C2, KSUID_CHACHA20_C3,
    1, 2, 3, 4, 5, 6, 7, 8,
    0,
    9, 10, 11,
  };
  uint32_t s2[16];
  memcpy (s2, s1, sizeof s2);
  s2[12] = 1;                   /* different counter value */

  uint8_t b1[64], b2[64];
  ksuid_chacha20_block (b1, s1);
  ksuid_chacha20_block (b2, s2);
  ASSERT_TRUE (memcmp (b1, b2, 64) != 0);
}

int
main (void)
{
  RUN_TEST (test_rfc8439_block);
  RUN_TEST (test_block_increments_counter);
  RUN_TEST (test_distinct_counters_yield_distinct_blocks);
  TEST_MAIN_END ();
}
