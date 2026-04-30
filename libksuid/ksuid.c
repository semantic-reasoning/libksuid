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
#include <string.h>
#include <time.h>

#include <libksuid/base62.h>
#include <libksuid/byteorder.h>
#include <libksuid/compare_simd.h>
#include <libksuid/rand.h>

/* Drive both definitions from the public KSUID_*_INIT macros so the
 * runtime symbols and the static-storage initializer form can never
 * drift out of byte-for-byte agreement -- the regression
 * test_init_macros_match_symbols pins the same equivalence at runtime
 * but a single source of truth at the definition site removes the
 * possibility entirely. */
KSUID_PUBLIC const ksuid_t KSUID_NIL = KSUID_NIL_INIT;
KSUID_PUBLIC const ksuid_t KSUID_MAX = KSUID_MAX_INIT;

bool
ksuid_is_nil (const ksuid_t *id)
{
  static const uint8_t zero[KSUID_BYTES] = { 0 };
  return memcmp (id->b, zero, KSUID_BYTES) == 0;
}

int
ksuid_compare (const ksuid_t *a, const ksuid_t *b)
{
  /* Dispatch through KSUID_COMPARE20 -- compile-time-selected
   * SSE2 / NEON / scalar kernel. All three implementations agree
   * on the {-1, 0, +1} contract and on lexicographic byte order;
   * tests/test_compare_parity.c pins the equivalence. */
  return KSUID_COMPARE20 (a->b, b->b);
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

void
ksuid_format (const ksuid_t *id, char out[KSUID_STRING_LEN])
{
  ksuid_base62_encode ((uint8_t *) out, id->b);
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
