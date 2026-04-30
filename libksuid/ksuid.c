/* SPDX-License-Identifier: LGPL-3.0-or-later AND MIT
 *
 * Core KSUID type, constants, accessors, and ordering primitives.
 *
 * Derived from segmentio/ksuid (MIT, Copyright (c) 2017 Segment.io):
 *   - 20-byte layout, KSUID_NIL / KSUID_MAX semantics: ksuid.go:15-58
 *   - Compare = bytes.Compare(a, b):                   ksuid.go:308-311
 *   - FromBytes / FromParts / Timestamp / Payload:     ksuid.go:74-81, 247-294
 */
#include <libksuid/ksuid.h>

#include <stdatomic.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <libksuid/base62.h>
#include <libksuid/byteorder.h>
#include <libksuid/rand.h>
#include <libksuid/uint128.h>

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
  /* The decoder partially writes its destination before detecting an
   * overflow; route through a stack temporary so the caller's |*out|
   * is never observed in a half-decoded state, matching the size-error
   * "untouched on failure" guarantee. */
  ksuid_t tmp;
  ksuid_err_t e = ksuid_base62_decode (tmp.b, (const uint8_t *) s);
  if (e != KSUID_OK)
    return e;
  *out = tmp;
  return KSUID_OK;
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

/* Atomic-pointer overrides for ksuid_set_rand. Readers use acquire
 * loads, writers use release stores so a swap mid-flight cannot tear
 * the (fn, ctx) pair. The two atomics are independent, so a concurrent
 * swap during a draw can still observe one half from the old override
 * and the other half from the new -- documented as caller's
 * responsibility (the user must not flip rng sources mid-load).
 *
 * _Atomic is spelled as a type qualifier (rather than _Atomic(T)) so
 * gst-indent does not parse it as a function call and reflow the
 * declarations weirdly. Static storage zero-initializes both pointers
 * to NULL, which matches the "no override installed" state. */
static _Atomic ksuid_rng_fn g_rng_fn;
static void *_Atomic g_rng_ctx;

void
ksuid_set_rand (ksuid_rng_fn fn, void *ctx)
{
  atomic_store_explicit (&g_rng_ctx, ctx, memory_order_release);
  atomic_store_explicit (&g_rng_fn, fn, memory_order_release);
}

static int
ksuid_fill_payload (uint8_t *buf, size_t n)
{
  ksuid_rng_fn fn = atomic_load_explicit (&g_rng_fn, memory_order_acquire);
  if (fn != NULL) {
    void *ctx = atomic_load_explicit (&g_rng_ctx, memory_order_acquire);
    return fn (ctx, buf, n);
  }
  return ksuid_random_bytes (buf, n);
}

ksuid_err_t
ksuid_new_with_time (ksuid_t *out, int64_t unix_seconds)
{
  int64_t corrected = unix_seconds - KSUID_EPOCH_SECONDS;
  if (corrected < 0 || corrected > (int64_t) UINT32_MAX)
    return KSUID_ERR_TIME_RANGE;
  /* Fill the payload first into a temporary so a partial RNG failure
   * cannot leak half a payload into |*out|. */
  uint8_t payload[KSUID_PAYLOAD_LEN];
  if (ksuid_fill_payload (payload, KSUID_PAYLOAD_LEN) != 0)
    return KSUID_ERR_RNG;
  ksuid_be32_store (out->b, (uint32_t) corrected);
  memcpy (out->b + KSUID_TIMESTAMP_LEN, payload, KSUID_PAYLOAD_LEN);
  return KSUID_OK;
}

ksuid_err_t
ksuid_new (ksuid_t *out)
{
  /* Use timespec_get rather than time(NULL) for portability with
   * Windows CRT and to share the path tested in rand_tls.c. */
  struct timespec ts;
  if (timespec_get (&ts, TIME_UTC) != TIME_UTC)
    return KSUID_ERR_TIME_RANGE;
  return ksuid_new_with_time (out, (int64_t) ts.tv_sec);
}
