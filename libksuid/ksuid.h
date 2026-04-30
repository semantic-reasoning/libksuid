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

#include <libksuid/ksuid_version.h>

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

/* The static-storage initializer macros below assume ksuid_t is
 * exactly its byte array -- no padding, no extra fields. If a future
 * change adds a field, the assertion fails at compile time and forces
 * the macro author to update KSUID_NIL_INIT / KSUID_MAX_INIT in
 * lockstep. C11 spells the assertion `_Static_assert`; C++ since
 * C++11 spells it `static_assert`. Gate so the public header
 * compiles for both, since this file lives inside extern "C" for
 * C++ consumers. */
#ifdef __cplusplus
    static_assert (sizeof (ksuid_t) == KSUID_BYTES,
      "ksuid_t must be exactly KSUID_BYTES; KSUID_*_INIT macros depend on it");
#else
    _Static_assert (sizeof (ksuid_t) == KSUID_BYTES,
      "ksuid_t must be exactly KSUID_BYTES; KSUID_*_INIT macros depend on it");
#endif

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

/* Two forms of the same sentinel values:
 *
 *   - KSUID_NIL / KSUID_MAX (extern const ksuid_t)
 *       Use these for runtime comparison and parameter passing:
 *           if (ksuid_compare (&id, &KSUID_NIL) == 0) ...
 *
 *   - KSUID_NIL_INIT / KSUID_MAX_INIT (aggregate-initializer macros)
 *       Use these as constant expressions in a declaration:
 *           static const ksuid_t g_zero = KSUID_NIL_INIT;
 *       The macro form is REQUIRED on Windows DLL builds, where
 *       KSUID_PUBLIC expands to __declspec(dllimport) and the
 *       symbol is therefore not a constant expression in user TUs.
 *
 * The two forms are guaranteed byte-for-byte equal; tests/test_smoke.c
 * pins the equivalence with ASSERT_EQ_BYTES. */
  KSUID_PUBLIC extern const ksuid_t KSUID_NIL;
  KSUID_PUBLIC extern const ksuid_t KSUID_MAX;

#define KSUID_NIL_INIT { { 0 } }
#define KSUID_MAX_INIT                                                       \
  { { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,            \
      0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff } }

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

/* Write the 27-character base62 representation of |id| into |out|. The
 * output is NOT NUL-terminated; callers needing a C string should size
 * their buffer to KSUID_STRING_LEN + 1 and append '\0' themselves. */
  KSUID_PUBLIC void ksuid_format (const ksuid_t * id,
      char out[KSUID_STRING_LEN]);

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
 *
 * Thread-exit residue: the per-thread CSPRNG state holds 64 bytes
 * of ChaCha20 state plus a 64-byte keystream window. On platforms
 * with a thread-exit hook (glibc 2.18+ via __cxa_thread_atexit_impl,
 * MUSL >= 1.2.0, libc++abi on macOS, FLS on Windows) libksuid wipes
 * this state automatically when the owning thread exits. On other
 * platforms the state persists in the TLS block until the OS
 * reclaims it. Callers requiring stronger guarantees should call
 * ksuid_set_rand(NULL, NULL) to no-op the override path and then
 * draw + discard a single payload via ksuid_new() before joining
 * the worker thread; the next call from the same TLS slot sees a
 * fresh seed and the bounded reseed cadence (1 MiB / 1 hour /
 * fork) keeps the residue window small even without a thread-exit
 * hook.
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
