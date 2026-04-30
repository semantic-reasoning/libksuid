/* SPDX-License-Identifier: LGPL-3.0-or-later
 *
 * Smoke test for libksuid/wipe.h. Proves the shim *zeroes* a buffer.
 * Does NOT prove the shim resists dead-store elimination -- that
 * property is verified by the objdump grep step in CI's Linux GCC
 * lane, which fails the build if the wipe call disappeared from the
 * library's optimised disassembly.
 */
#include <libksuid/wipe.h>
#include "test_util.h"

static void
test_wipe_zeroes_a_full_buffer (void)
{
  uint8_t buf[64];
  for (size_t i = 0; i < sizeof buf; ++i)
    buf[i] = (uint8_t) (i ^ 0xa5);
  ksuid_explicit_bzero (buf, sizeof buf);
  for (size_t i = 0; i < sizeof buf; ++i)
    ASSERT_EQ_INT (buf[i], 0);
}

static void
test_wipe_zeroes_a_subrange (void)
{
  uint8_t buf[16];
  memset (buf, 0xff, sizeof buf);
  ksuid_explicit_bzero (buf + 4, 8);
  ASSERT_EQ_INT (buf[3], 0xff);
  for (size_t i = 4; i < 12; ++i)
    ASSERT_EQ_INT (buf[i], 0);
  ASSERT_EQ_INT (buf[12], 0xff);
}

static void
test_wipe_handles_zero_length (void)
{
  uint8_t buf[4] = { 1, 2, 3, 4 };
  ksuid_explicit_bzero (buf, 0);
  ASSERT_EQ_INT (buf[0], 1);
  ASSERT_EQ_INT (buf[3], 4);
}

static void
test_wipe_handles_null_pointer (void)
{
  /* Documented contract: the shim is a no-op on (NULL, n) and on
   * (p, 0). Neither must crash. */
  ksuid_explicit_bzero (NULL, 0);
  ksuid_explicit_bzero (NULL, 64);
}

int
main (void)
{
  RUN_TEST (test_wipe_zeroes_a_full_buffer);
  RUN_TEST (test_wipe_zeroes_a_subrange);
  RUN_TEST (test_wipe_handles_zero_length);
  RUN_TEST (test_wipe_handles_null_pointer);
  TEST_MAIN_END ();
}
