/* SPDX-License-Identifier: LGPL-3.0-or-later AND MIT
 *
 * Core KSUID type, constants, accessors, and ordering primitives.
 *
 * Derived from segmentio/ksuid (MIT, Copyright (c) 2017 Segment.io):
 *   - 20-byte layout, KSUID_NIL / KSUID_MAX semantics: ksuid.go:15-58
 *   - Compare = bytes.Compare(a, b):                   ksuid.go:308-311
 *   - FromBytes / FromParts / Timestamp / Payload:     ksuid.go:74-81, 247-294
 */
#include <ksuid.h>

#include <stdlib.h>
#include <string.h>

#include "base62.h"
#include "byteorder.h"
#include "uint128.h"

KSUID_PUBLIC const ksuid_t KSUID_NIL = {.b = {0} };

KSUID_PUBLIC const ksuid_t KSUID_MAX = {
  .b = {
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
      },
};

bool
ksuid_is_nil (const ksuid_t *id)
{
  static const uint8_t zero[KSUID_BYTES] = { 0 };
  return memcmp (id->b, zero, KSUID_BYTES) == 0;
}

int
ksuid_compare (const ksuid_t *a, const ksuid_t *b)
{
  /* memcmp returns the byte difference on glibc but the spec only
   * guarantees the sign; normalize to {-1, 0, +1} for portability. */
  int r = memcmp (a->b, b->b, KSUID_BYTES);
  return (r > 0) - (r < 0);
}

ksuid_err_t
ksuid_from_bytes (ksuid_t *out, const uint8_t *b, size_t n)
{
  if (n != KSUID_BYTES)
    return KSUID_ERR_SIZE;
  memcpy (out->b, b, KSUID_BYTES);
  return KSUID_OK;
}

ksuid_err_t
ksuid_from_parts (ksuid_t *out,
    int64_t unix_seconds, const uint8_t *payload, size_t payload_len)
{
  if (payload_len != KSUID_PAYLOAD_LEN)
    return KSUID_ERR_PAYLOAD_SIZE;
  int64_t corrected = unix_seconds - KSUID_EPOCH_SECONDS;
  if (corrected < 0 || corrected > (int64_t) UINT32_MAX)
    return KSUID_ERR_TIME_RANGE;
  ksuid_be32_store (out->b, (uint32_t) corrected);
  memcpy (out->b + KSUID_TIMESTAMP_LEN, payload, KSUID_PAYLOAD_LEN);
  return KSUID_OK;
}

ksuid_t
ksuid_from_bytes_or_nil (const uint8_t *b, size_t n)
{
  ksuid_t out;
  if (ksuid_from_bytes (&out, b, n) != KSUID_OK)
    return KSUID_NIL;
  return out;
}

ksuid_t
ksuid_from_parts_or_nil (int64_t unix_seconds,
    const uint8_t *payload, size_t payload_len)
{
  ksuid_t out;
  if (ksuid_from_parts (&out, unix_seconds, payload, payload_len) != KSUID_OK)
    return KSUID_NIL;
  return out;
}

uint32_t
ksuid_timestamp (const ksuid_t *id)
{
  return ksuid_be32_load (id->b);
}

int64_t
ksuid_time_unix (const ksuid_t *id)
{
  return (int64_t) ksuid_timestamp (id) + KSUID_EPOCH_SECONDS;
}

const uint8_t *
ksuid_payload (const ksuid_t *id)
{
  return id->b + KSUID_TIMESTAMP_LEN;
}

ksuid_err_t
ksuid_parse (ksuid_t *out, const char *s, size_t len)
{
  if (len != KSUID_STRING_LEN)
    return KSUID_ERR_STR_SIZE;
  return ksuid_base62_decode (out->b, (const uint8_t *) s);
}

ksuid_t
ksuid_parse_or_nil (const char *s, size_t len)
{
  ksuid_t out;
  if (ksuid_parse (&out, s, len) != KSUID_OK)
    return KSUID_NIL;
  return out;
}

void
ksuid_format (const ksuid_t *id, char out[KSUID_STRING_LEN])
{
  ksuid_base62_encode ((uint8_t *) out, id->b);
}

/* qsort callback. Stability is irrelevant for KSUIDs because compare
 * uses every byte of the 20-byte representation. */
static int
ksuid_qsort_compare (const void *a, const void *b)
{
  return ksuid_compare ((const ksuid_t *) a, (const ksuid_t *) b);
}

void
ksuid_sort (ksuid_t *ids, size_t n)
{
  /* Upstream Go ships a naive Lomuto quicksort that degrades to O(n^2)
   * on already-sorted or reverse-sorted input (ksuid.go:332-352). The
   * C library's qsort is allowed to use a worst-case O(n log n)
   * algorithm and avoids that hazard for the standard cost of an
   * indirect compare callback. */
  if (n > 1)
    qsort (ids, n, sizeof (ksuid_t), ksuid_qsort_compare);
}

bool
ksuid_is_sorted (const ksuid_t *ids, size_t n)
{
  for (size_t i = 1; i < n; ++i) {
    if (ksuid_compare (&ids[i - 1], &ids[i]) > 0)
      return false;
  }
  return true;
}

ksuid_t
ksuid_next (const ksuid_t *id)
{
  ksuid_t out = *id;
  if (ksuid_payload_incr (out.b + KSUID_TIMESTAMP_LEN)) {
    /* Payload wrapped from 2^128 - 1 back to 0. Bump the 32-bit
     * timestamp; if it also wraps the result is KSUID_NIL. Mirrors
     * upstream Next at ksuid.go:355-367. */
    uint32_t ts = ksuid_be32_load (out.b);
    ksuid_be32_store (out.b, ts + 1);
  }
  return out;
}

ksuid_t
ksuid_prev (const ksuid_t *id)
{
  ksuid_t out = *id;
  if (ksuid_payload_decr (out.b + KSUID_TIMESTAMP_LEN)) {
    /* Payload underflowed from 0 to 2^128 - 1; decrement the
     * timestamp. ksuid.go:370-382. */
    uint32_t ts = ksuid_be32_load (out.b);
    ksuid_be32_store (out.b, ts - 1);
  }
  return out;
}
