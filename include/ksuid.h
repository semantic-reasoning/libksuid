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
extern "C" {
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

#define KSUID_BYTES          20    /* binary length                         */
#define KSUID_STRING_LEN     27    /* base62 string length (no NUL)         */
#define KSUID_PAYLOAD_LEN    16    /* random payload length                 */
#define KSUID_TIMESTAMP_LEN  4     /* big-endian uint32 prefix              */
#define KSUID_EPOCH_SECONDS  1400000000LL  /* 2014-05-13 16:53:20 UTC       */

typedef struct ksuid {
    uint8_t b[KSUID_BYTES];
} ksuid_t;

typedef enum ksuid_err {
    KSUID_OK                =  0,
    KSUID_ERR_SIZE          = -1, /* bad binary length                     */
    KSUID_ERR_STR_SIZE      = -2, /* bad string length                     */
    KSUID_ERR_STR_VALUE     = -3, /* string contains non-base62 / overflow */
    KSUID_ERR_PAYLOAD_SIZE  = -4, /* payload != KSUID_PAYLOAD_LEN          */
    KSUID_ERR_RNG           = -5, /* OS random source unavailable          */
    KSUID_ERR_EXHAUSTED     = -6, /* sequence exhausted                    */
    KSUID_ERR_TIME_RANGE    = -7  /* unix_seconds outside KSUID epoch range*/
} ksuid_err_t;

KSUID_PUBLIC extern const ksuid_t KSUID_NIL;
KSUID_PUBLIC extern const ksuid_t KSUID_MAX;

/* --------------------------------------------------------------------------
 * Predicates and ordering.
 * -------------------------------------------------------------------------- */

KSUID_PUBLIC bool ksuid_is_nil(const ksuid_t *id);

/* Lexicographic comparison over the full 20-byte representation, matching
 * the Go implementation's bytes.Compare semantics. Returns <0, 0, or >0. */
KSUID_PUBLIC int  ksuid_compare(const ksuid_t *a, const ksuid_t *b);

/* --------------------------------------------------------------------------
 * Construction from raw inputs.
 * -------------------------------------------------------------------------- */

/* Copy the binary KSUID at |b| (which must be exactly KSUID_BYTES long) into
 * |out|. On error |out| is left untouched. */
KSUID_PUBLIC ksuid_err_t ksuid_from_bytes(ksuid_t *out, const uint8_t *b, size_t n);

/* Build |out| from a Unix timestamp (in seconds) and a 16-byte payload. The
 * timestamp must lie within the closed interval [KSUID_EPOCH_SECONDS,
 * KSUID_EPOCH_SECONDS + UINT32_MAX] -- the full 32-bit lifetime of the KSUID
 * format. Out-of-range inputs return KSUID_ERR_TIME_RANGE. */
KSUID_PUBLIC ksuid_err_t ksuid_from_parts(ksuid_t *out,
                                          int64_t unix_seconds,
                                          const uint8_t *payload,
                                          size_t payload_len);

/* Convenience wrappers that return KSUID_NIL on any error. */
KSUID_PUBLIC ksuid_t ksuid_from_bytes_or_nil(const uint8_t *b, size_t n);
KSUID_PUBLIC ksuid_t ksuid_from_parts_or_nil(int64_t unix_seconds,
                                             const uint8_t *payload,
                                             size_t payload_len);

/* --------------------------------------------------------------------------
 * Field accessors.
 * -------------------------------------------------------------------------- */

/* The KSUID's 32-bit big-endian timestamp, uncorrected for the custom epoch. */
KSUID_PUBLIC uint32_t ksuid_timestamp(const ksuid_t *id);

/* The KSUID's timestamp interpreted as Unix seconds (i.e. timestamp + epoch). */
KSUID_PUBLIC int64_t  ksuid_time_unix(const ksuid_t *id);

/* Pointer into |id| to the 16-byte payload region (id->b + 4). The pointer is
 * borrowed from |id|; do not free, and do not use after |id| goes out of
 * scope. */
KSUID_PUBLIC const uint8_t *ksuid_payload(const ksuid_t *id);

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* KSUID_H */
