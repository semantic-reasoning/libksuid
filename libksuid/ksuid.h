/* SPDX-License-Identifier: LGPL-3.0-or-later AND MIT
 *
 * libksuid -- pure C11 port of github.com/segmentio/ksuid.
 *
 * The KSUID specification, binary layout, base62 alphabet and encoding
 * scheme are derived from segmentio/ksuid (MIT, Copyright (c) 2017
 * Segment.io). See LICENSE.MIT and NOTICE in the project root.
 */
#ifndef KSUID_H
#define KSUID_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C"
{
#endif

#if defined(_WIN32) || defined(__CYGWIN__)
#  if defined(KSUID_BUILDING)
#    define KSUID_PUBLIC __declspec(dllexport)
#  else
#    define KSUID_PUBLIC __declspec(dllimport)
#  endif
#elif defined(__GNUC__) || defined(__clang__)
#  define KSUID_PUBLIC __attribute__((visibility("default")))
#else
#  define KSUID_PUBLIC
#endif

/* --------------------------------------------------------------------------
 * Wire-format constants (compatible with segmentio/ksuid).
 * -------------------------------------------------------------------------- */

#define KSUID_BYTES          20 /* binary length                         */
#define KSUID_STRING_LEN     27 /* base62 string length (no NUL)         */
#define KSUID_PAYLOAD_LEN    16 /* random payload length                 */
#define KSUID_TIMESTAMP_LEN  4  /* big-endian uint32 prefix              */
#define KSUID_EPOCH_SECONDS  1400000000LL       /* 2014-05-13 16:53:20 UTC       */

  typedef struct ksuid
  {
    uint8_t b[KSUID_BYTES];
  } ksuid_t;

  typedef enum ksuid_err
  {
    KSUID_OK = 0,
    KSUID_ERR_SIZE = -1,        /* bad binary length                     */
    KSUID_ERR_STR_SIZE = -2,    /* bad string length                     */
    KSUID_ERR_STR_VALUE = -3,   /* string contains non-base62 / overflow */
    KSUID_ERR_PAYLOAD_SIZE = -4,        /* payload != KSUID_PAYLOAD_LEN          */
    KSUID_ERR_RNG = -5,         /* OS random source unavailable          */
    KSUID_ERR_EXHAUSTED = -6,   /* sequence exhausted                    */
    KSUID_ERR_TIME_RANGE = -7   /* unix_seconds outside KSUID epoch range */
  } ksuid_err_t;

  KSUID_PUBLIC extern const ksuid_t KSUID_NIL;
  KSUID_PUBLIC extern const ksuid_t KSUID_MAX;

/* --------------------------------------------------------------------------
 * Predicates and ordering.
 * -------------------------------------------------------------------------- */

  KSUID_PUBLIC bool ksuid_is_nil (const ksuid_t * id);

/* Lexicographic comparison over the full 20-byte representation, matching
 * the Go implementation's bytes.Compare semantics. Returns <0, 0, or >0. */
  KSUID_PUBLIC int ksuid_compare (const ksuid_t * a, const ksuid_t * b);

/* --------------------------------------------------------------------------
 * Construction from raw inputs.
 * -------------------------------------------------------------------------- */

/* Copy the binary KSUID at |b| (which must be exactly KSUID_BYTES long) into
 * |out|. On error |out| is left untouched. */
  KSUID_PUBLIC ksuid_err_t ksuid_from_bytes (ksuid_t * out, const uint8_t * b,
      size_t n);

/* Build |out| from a Unix timestamp (in seconds) and a 16-byte payload. The
 * timestamp must lie within the closed interval [KSUID_EPOCH_SECONDS,
 * KSUID_EPOCH_SECONDS + UINT32_MAX] -- the full 32-bit lifetime of the KSUID
 * format. Out-of-range inputs return KSUID_ERR_TIME_RANGE. */
  KSUID_PUBLIC ksuid_err_t ksuid_from_parts (ksuid_t * out,
      int64_t unix_seconds, const uint8_t * payload, size_t payload_len);

/* Convenience wrappers that return KSUID_NIL on any error. */
  KSUID_PUBLIC ksuid_t ksuid_from_bytes_or_nil (const uint8_t * b, size_t n);
  KSUID_PUBLIC ksuid_t ksuid_from_parts_or_nil (int64_t unix_seconds,
      const uint8_t * payload, size_t payload_len);

/* --------------------------------------------------------------------------
 * Field accessors.
 * -------------------------------------------------------------------------- */

/* The KSUID's 32-bit big-endian timestamp, uncorrected for the custom epoch. */
  KSUID_PUBLIC uint32_t ksuid_timestamp (const ksuid_t * id);

/* The KSUID's timestamp interpreted as Unix seconds (i.e. timestamp + epoch). */
  KSUID_PUBLIC int64_t ksuid_time_unix (const ksuid_t * id);

/* Pointer into |id| to the 16-byte payload region (id->b + 4). The pointer is
 * borrowed from |id|; do not free, and do not use after |id| goes out of
 * scope. */
  KSUID_PUBLIC const uint8_t *ksuid_payload (const ksuid_t * id);

/* --------------------------------------------------------------------------
 * Base62 string conversion.
 * -------------------------------------------------------------------------- */

/* Decode |len| bytes of |s| (which must be exactly KSUID_STRING_LEN base62
 * characters, no NUL terminator required) into |out|. Returns
 * KSUID_ERR_STR_SIZE if |len| is wrong or KSUID_ERR_STR_VALUE if the input
 * contains a non-alphanumeric character or encodes a value greater than
 * KSUID_MAX. On any error the contents of |out| are guaranteed unchanged --
 * decoding writes to a stack temporary first and only copies into |out|
 * once the input has been fully validated. */
  KSUID_PUBLIC ksuid_err_t ksuid_parse (ksuid_t * out, const char *s,
      size_t len);
  KSUID_PUBLIC ksuid_t ksuid_parse_or_nil (const char *s, size_t len);

/* Write the 27-character base62 representation of |id| into |out|. The
 * output is NOT NUL-terminated; callers needing a C string should size
 * their buffer to KSUID_STRING_LEN + 1 and append '\0' themselves. */
  KSUID_PUBLIC void ksuid_format (const ksuid_t * id,
      char out[KSUID_STRING_LEN]);

/* --------------------------------------------------------------------------
 * Bulk ordering.
 * -------------------------------------------------------------------------- */

/* In-place ascending sort of |ids| (n elements) under ksuid_compare. */
  KSUID_PUBLIC void ksuid_sort (ksuid_t * ids, size_t n);

/* True iff |ids| is in non-decreasing order under ksuid_compare. An empty
 * array is sorted by definition. */
  KSUID_PUBLIC bool ksuid_is_sorted (const ksuid_t * ids, size_t n);

/* --------------------------------------------------------------------------
 * Walk: adjacent KSUIDs in lexicographic order.
 * -------------------------------------------------------------------------- */

/* The KSUID immediately after |id| under ksuid_compare. Increments the
 * 16-byte payload as a 128-bit big-endian integer; on overflow (payload
 * was all-0xff) the 32-bit timestamp prefix is bumped, wrapping around
 * to KSUID_NIL once the timestamp itself overflows. */
  KSUID_PUBLIC ksuid_t ksuid_next (const ksuid_t * id);

/* The KSUID immediately before |id| under ksuid_compare. Dual to
 * ksuid_next: payload underflow (payload was all zero) decrements the
 * timestamp, with the timestamp wrapping at zero. */
  KSUID_PUBLIC ksuid_t ksuid_prev (const ksuid_t * id);

/* --------------------------------------------------------------------------
 * Sequence: monotonic ordered KSUIDs from a single seed.
 *
 * Up to 65536 KSUIDs share the leading 18 bytes of the seed; the final
 * two bytes carry a 16-bit big-endian counter starting at 0. Sequence
 * values are NOT safe for concurrent use; one sequence per thread.
 * -------------------------------------------------------------------------- */

  typedef struct ksuid_sequence
  {
    ksuid_t seed;
    /* uint32_t (rather than uint16_t) so we can detect the overflow
     * after the 65536th call without relying on wraparound semantics. */
    uint32_t count;
  } ksuid_sequence_t;

  KSUID_PUBLIC void ksuid_sequence_init (ksuid_sequence_t * s,
      const ksuid_t * seed);
  KSUID_PUBLIC ksuid_err_t ksuid_sequence_next (ksuid_sequence_t * s,
      ksuid_t * out);
  KSUID_PUBLIC void ksuid_sequence_bounds (const ksuid_sequence_t * s,
      ksuid_t * min, ksuid_t * max);

/* --------------------------------------------------------------------------
 * Random KSUID generation.
 *
 * Random bytes come from the per-thread ChaCha20 CSPRNG keyed from
 * the OS entropy source (getrandom on Linux, getentropy on macOS,
 * BCryptGenRandom on Windows). Distinct threads draw independent
 * streams without synchronisation; concurrent calls from the *same*
 * thread are not supported. On entropy-source failure the function
 * returns KSUID_ERR_RNG and leaves |*out| untouched.
 * -------------------------------------------------------------------------- */

/* Generate a new KSUID stamped with the current wall-clock time. */
  KSUID_PUBLIC ksuid_err_t ksuid_new (ksuid_t * out);

/* Generate a new KSUID stamped with |unix_seconds|. The timestamp must
 * fall within [KSUID_EPOCH_SECONDS, KSUID_EPOCH_SECONDS + UINT32_MAX]
 * just like ksuid_from_parts; out-of-range returns
 * KSUID_ERR_TIME_RANGE. */
  KSUID_PUBLIC ksuid_err_t ksuid_new_with_time (ksuid_t * out,
      int64_t unix_seconds);

/* Replace the global random source. The default source is the
 * per-thread ChaCha20 CSPRNG; calling this with a non-NULL |fn|
 * routes ksuid_new through |fn(ctx, buf, n)| instead. |fn| must
 * return 0 on success and non-zero on failure. Passing NULL restores
 * the default source.
 *
 * The override is global and atomic-pointer-protected, so swapping
 * mid-flight is race-free; however, |fn| itself MUST be thread-safe
 * if multiple threads will call ksuid_new concurrently. */
  typedef int (*ksuid_rng_fn) (void *ctx, uint8_t * buf, size_t n);
  KSUID_PUBLIC void ksuid_set_rand (ksuid_rng_fn fn, void *ctx);

#ifdef __cplusplus
}                               /* extern "C" */
#endif

#endif                          /* KSUID_H */
