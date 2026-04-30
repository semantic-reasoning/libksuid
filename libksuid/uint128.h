/* SPDX-License-Identifier: LGPL-3.0-or-later AND MIT
 *
 * Internal 128-bit big-endian payload arithmetic used by ksuid_next /
 * ksuid_prev. Operates directly on the 16 payload bytes so we do not
 * pull in any wide-integer compiler extension (__uint128_t) and stay
 * portable across C11 implementations.
 *
 * Derived from segmentio/ksuid uint128.go (MIT, Copyright (c) 2017
 * Segment.io): same big-endian-payload semantics, same carry / borrow
 * propagation, same overflow predicate.
 */
#ifndef KSUID_UINT128_H
#define KSUID_UINT128_H

#include <stdbool.h>
#include <stdint.h>

#include <libksuid/byteorder.h>

/* Increment the 16-byte big-endian payload at |p| in place by 1.
 * Returns true iff the increment overflowed (i.e. all payload bytes
 * were 0xff and the post-state is all-zero). */
static inline bool
ksuid_payload_incr (uint8_t p[16])
{
  uint64_t hi = ksuid_be64_load (p);
  uint64_t lo = ksuid_be64_load (p + 8);
  uint64_t lo_new = lo + 1;
  uint64_t carry = (lo_new < lo) ? 1 : 0;
  uint64_t hi_new = hi + carry;
  bool overflow = (hi_new == 0) && (lo_new == 0);
  ksuid_be64_store (p, hi_new);
  ksuid_be64_store (p + 8, lo_new);
  return overflow;
}

/* Decrement the 16-byte big-endian payload at |p| in place by 1.
 * Returns true iff the decrement underflowed (i.e. all payload bytes
 * were 0x00 and the post-state is all-0xff). */
static inline bool
ksuid_payload_decr (uint8_t p[16])
{
  uint64_t hi = ksuid_be64_load (p);
  uint64_t lo = ksuid_be64_load (p + 8);
  uint64_t lo_new = lo - 1;
  uint64_t borrow = (lo_new > lo) ? 1 : 0;
  uint64_t hi_new = hi - borrow;
  bool underflow = (hi_new == UINT64_MAX) && (lo_new == UINT64_MAX);
  ksuid_be64_store (p, hi_new);
  ksuid_be64_store (p + 8, lo_new);
  return underflow;
}

#endif /* KSUID_UINT128_H */
