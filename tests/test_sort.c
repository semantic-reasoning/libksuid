/* SPDX-License-Identifier: LGPL-3.0-or-later */
#include <ksuid.h>
#include "test_util.h"

static void
fill_pseudo_random (ksuid_t *id, uint64_t seed)
{
  uint64_t s = seed;
  for (size_t i = 0; i < KSUID_BYTES; ++i) {
    s = s * 6364136223846793005ULL + 1442695040888963407ULL;
    id->b[i] = (uint8_t) (s >> 56);
  }
}

static void
test_is_sorted_empty_and_single (void)
{
  ASSERT_TRUE (ksuid_is_sorted (NULL, 0));
  ksuid_t one = KSUID_NIL;
  ASSERT_TRUE (ksuid_is_sorted (&one, 1));
}

static void
test_is_sorted_pairs (void)
{
  ksuid_t pair[2];
  pair[0] = KSUID_NIL;
  pair[1] = KSUID_MAX;
  ASSERT_TRUE (ksuid_is_sorted (pair, 2));
  pair[0] = KSUID_MAX;
  pair[1] = KSUID_NIL;
  ASSERT_FALSE (ksuid_is_sorted (pair, 2));
  pair[0] = KSUID_NIL;
  pair[1] = KSUID_NIL;
  ASSERT_TRUE (ksuid_is_sorted (pair, 2));      /* duplicates allowed */
}

static void
test_sort_is_idempotent_on_sorted (void)
{
  ksuid_t arr[4];
  arr[0] = KSUID_NIL;
  for (size_t i = 1; i < 4; ++i) {
    arr[i] = arr[i - 1];
    ++arr[i].b[KSUID_BYTES - 1];
  }
  ASSERT_TRUE (ksuid_is_sorted (arr, 4));
  ksuid_t before[4];
  memcpy (before, arr, sizeof before);
  ksuid_sort (arr, 4);
  ASSERT_EQ_BYTES (arr, before, sizeof before);
}

static void
test_sort_normalizes_reverse (void)
{
  /* Upstream's quicksort hits O(n^2) on reverse-sorted input; this
   * test simply asserts correctness of the result, but is also the
   * scenario where qsort substantially out-performs upstream. */
  ksuid_t arr[8];
  for (size_t i = 0; i < 8; ++i) {
    arr[i] = KSUID_NIL;
    arr[i].b[KSUID_BYTES - 1] = (uint8_t) (8 - i);
  }
  ASSERT_FALSE (ksuid_is_sorted (arr, 8));
  ksuid_sort (arr, 8);
  ASSERT_TRUE (ksuid_is_sorted (arr, 8));
  for (size_t i = 0; i < 8; ++i)
    ASSERT_EQ_INT (arr[i].b[KSUID_BYTES - 1], (int) (i + 1));
}

#define KSUID_TEST_SORT_N 256

static void
test_sort_pseudo_random_array (void)
{
  ksuid_t arr[KSUID_TEST_SORT_N];
  for (size_t i = 0; i < KSUID_TEST_SORT_N; ++i)
    fill_pseudo_random (&arr[i],
        0x9e3779b97f4a7c15ULL ^ (i * 0x100000001b3ULL));
  ASSERT_FALSE (ksuid_is_sorted (arr, KSUID_TEST_SORT_N));
  ksuid_sort (arr, KSUID_TEST_SORT_N);
  ASSERT_TRUE (ksuid_is_sorted (arr, KSUID_TEST_SORT_N));
}

static void
test_sort_preserves_duplicates (void)
{
  ksuid_t arr[6];
  ksuid_t a, b;
  fill_pseudo_random (&a, 1);
  fill_pseudo_random (&b, 2);
  arr[0] = b;
  arr[1] = a;
  arr[2] = b;
  arr[3] = a;
  arr[4] = b;
  arr[5] = a;
  ksuid_sort (arr, 6);
  ASSERT_TRUE (ksuid_is_sorted (arr, 6));
  /* Three of each must remain. */
  size_t a_count = 0, b_count = 0;
  for (size_t i = 0; i < 6; ++i) {
    if (ksuid_compare (&arr[i], &a) == 0)
      ++a_count;
    else if (ksuid_compare (&arr[i], &b) == 0)
      ++b_count;
  }
  ASSERT_EQ_INT (a_count, 3);
  ASSERT_EQ_INT (b_count, 3);
}

int
main (void)
{
  RUN_TEST (test_is_sorted_empty_and_single);
  RUN_TEST (test_is_sorted_pairs);
  RUN_TEST (test_sort_is_idempotent_on_sorted);
  RUN_TEST (test_sort_normalizes_reverse);
  RUN_TEST (test_sort_pseudo_random_array);
  RUN_TEST (test_sort_preserves_duplicates);
  TEST_MAIN_END ();
}
