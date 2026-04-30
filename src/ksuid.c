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

#include <string.h>

#include "byteorder.h"

KSUID_PUBLIC const ksuid_t KSUID_NIL = { .b = {0} };
KSUID_PUBLIC const ksuid_t KSUID_MAX = {
    .b = {
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    },
};

bool ksuid_is_nil(const ksuid_t *id) {
    static const uint8_t zero[KSUID_BYTES] = {0};
    return memcmp(id->b, zero, KSUID_BYTES) == 0;
}

int ksuid_compare(const ksuid_t *a, const ksuid_t *b) {
    /* memcmp returns the byte difference on glibc but the spec only
     * guarantees the sign; normalize to {-1, 0, +1} for portability. */
    int r = memcmp(a->b, b->b, KSUID_BYTES);
    return (r > 0) - (r < 0);
}

ksuid_err_t ksuid_from_bytes(ksuid_t *out, const uint8_t *b, size_t n) {
    if (n != KSUID_BYTES) return KSUID_ERR_SIZE;
    memcpy(out->b, b, KSUID_BYTES);
    return KSUID_OK;
}

ksuid_err_t ksuid_from_parts(ksuid_t *out,
                             int64_t unix_seconds,
                             const uint8_t *payload,
                             size_t payload_len) {
    if (payload_len != KSUID_PAYLOAD_LEN) return KSUID_ERR_PAYLOAD_SIZE;
    int64_t corrected = unix_seconds - KSUID_EPOCH_SECONDS;
    if (corrected < 0 || corrected > (int64_t)UINT32_MAX)
        return KSUID_ERR_TIME_RANGE;
    ksuid_be32_store(out->b, (uint32_t)corrected);
    memcpy(out->b + KSUID_TIMESTAMP_LEN, payload, KSUID_PAYLOAD_LEN);
    return KSUID_OK;
}

ksuid_t ksuid_from_bytes_or_nil(const uint8_t *b, size_t n) {
    ksuid_t out;
    if (ksuid_from_bytes(&out, b, n) != KSUID_OK) return KSUID_NIL;
    return out;
}

ksuid_t ksuid_from_parts_or_nil(int64_t unix_seconds,
                                const uint8_t *payload,
                                size_t payload_len) {
    ksuid_t out;
    if (ksuid_from_parts(&out, unix_seconds, payload, payload_len) != KSUID_OK)
        return KSUID_NIL;
    return out;
}

uint32_t ksuid_timestamp(const ksuid_t *id) {
    return ksuid_be32_load(id->b);
}

int64_t ksuid_time_unix(const ksuid_t *id) {
    return (int64_t)ksuid_timestamp(id) + KSUID_EPOCH_SECONDS;
}

const uint8_t *ksuid_payload(const ksuid_t *id) {
    return id->b + KSUID_TIMESTAMP_LEN;
}
