/* SPDX-License-Identifier: LGPL-3.0-or-later */
#include <ksuid.h>
#include "test_util.h"

static const uint8_t kSampleBytes[KSUID_BYTES] = {
    /* 0ujtsYcgvSTl8PAuAdqWYSMnLOv -- segmentio/ksuid README */
    0x06, 0x69, 0xF7, 0xEF,
    0xB5, 0xA1, 0xCD, 0x34, 0xB5, 0xF9, 0x9D, 0x11,
    0x54, 0xFB, 0x68, 0x53, 0x34, 0x5C, 0x97, 0x35,
};
#define SAMPLE_TS UINT32_C(107608047)  /* 0x0669F7EF */

static void test_from_bytes_round_trip(void) {
    ksuid_t id = KSUID_NIL;
    ASSERT_EQ_INT(ksuid_from_bytes(&id, kSampleBytes, KSUID_BYTES), KSUID_OK);
    ASSERT_EQ_BYTES(id.b, kSampleBytes, KSUID_BYTES);
}

static void test_from_bytes_size_errors(void) {
    ksuid_t id = KSUID_MAX;
    ASSERT_EQ_INT(ksuid_from_bytes(&id, kSampleBytes, 0),  KSUID_ERR_SIZE);
    ASSERT_EQ_INT(ksuid_from_bytes(&id, kSampleBytes, 19), KSUID_ERR_SIZE);
    ASSERT_EQ_INT(ksuid_from_bytes(&id, kSampleBytes, 21), KSUID_ERR_SIZE);
    /* On error the output must not be silently mutated. */
    ASSERT_EQ_BYTES(id.b, KSUID_MAX.b, KSUID_BYTES);
}

static void test_from_bytes_or_nil_returns_nil_on_error(void) {
    ksuid_t bad = ksuid_from_bytes_or_nil(kSampleBytes, 19);
    ASSERT_TRUE(ksuid_is_nil(&bad));
    ksuid_t ok = ksuid_from_bytes_or_nil(kSampleBytes, KSUID_BYTES);
    ASSERT_EQ_BYTES(ok.b, kSampleBytes, KSUID_BYTES);
}

static void test_from_parts_writes_be_timestamp_and_payload(void) {
    ksuid_t id = KSUID_NIL;
    int64_t unix_s = (int64_t)SAMPLE_TS + KSUID_EPOCH_SECONDS;
    ASSERT_EQ_INT(
        ksuid_from_parts(&id, unix_s,
                         kSampleBytes + KSUID_TIMESTAMP_LEN, KSUID_PAYLOAD_LEN),
        KSUID_OK);
    ASSERT_EQ_BYTES(id.b, kSampleBytes, KSUID_BYTES);
}

static void test_from_parts_rejects_short_payload(void) {
    ksuid_t id = KSUID_MAX;
    int64_t unix_s = KSUID_EPOCH_SECONDS;
    ASSERT_EQ_INT(
        ksuid_from_parts(&id, unix_s, kSampleBytes + KSUID_TIMESTAMP_LEN, 15),
        KSUID_ERR_PAYLOAD_SIZE);
    ASSERT_EQ_BYTES(id.b, KSUID_MAX.b, KSUID_BYTES);
}

static void test_from_parts_rejects_out_of_range_time(void) {
    ksuid_t id;
    uint8_t pl[KSUID_PAYLOAD_LEN] = {0};
    /* Before epoch is invalid. */
    ASSERT_EQ_INT(ksuid_from_parts(&id, 0, pl, KSUID_PAYLOAD_LEN),
                  KSUID_ERR_TIME_RANGE);
    /* Past epoch + UINT32_MAX is invalid. */
    int64_t past = KSUID_EPOCH_SECONDS + (int64_t)UINT32_MAX + 1;
    ASSERT_EQ_INT(ksuid_from_parts(&id, past, pl, KSUID_PAYLOAD_LEN),
                  KSUID_ERR_TIME_RANGE);
    /* Both endpoints are valid (closed interval). */
    ASSERT_EQ_INT(ksuid_from_parts(&id, KSUID_EPOCH_SECONDS,
                                   pl, KSUID_PAYLOAD_LEN), KSUID_OK);
    ASSERT_EQ_INT(ksuid_from_parts(&id,
                                   KSUID_EPOCH_SECONDS + (int64_t)UINT32_MAX,
                                   pl, KSUID_PAYLOAD_LEN), KSUID_OK);
}

static void test_accessors(void) {
    ksuid_t id;
    ASSERT_EQ_INT(ksuid_from_bytes(&id, kSampleBytes, KSUID_BYTES), KSUID_OK);
    ASSERT_EQ_INT(ksuid_timestamp(&id), SAMPLE_TS);
    ASSERT_EQ_INT(ksuid_time_unix(&id),
                  (int64_t)SAMPLE_TS + KSUID_EPOCH_SECONDS);
    ASSERT_EQ_BYTES(ksuid_payload(&id),
                    kSampleBytes + KSUID_TIMESTAMP_LEN, KSUID_PAYLOAD_LEN);
}

static void test_nil_and_max_accessors(void) {
    ASSERT_EQ_INT(ksuid_timestamp(&KSUID_NIL), 0);
    ASSERT_EQ_INT(ksuid_timestamp(&KSUID_MAX), UINT32_MAX);
    ASSERT_EQ_INT(ksuid_time_unix(&KSUID_NIL), KSUID_EPOCH_SECONDS);
    ASSERT_EQ_INT(ksuid_time_unix(&KSUID_MAX),
                  KSUID_EPOCH_SECONDS + (int64_t)UINT32_MAX);
}

int main(void) {
    RUN_TEST(test_from_bytes_round_trip);
    RUN_TEST(test_from_bytes_size_errors);
    RUN_TEST(test_from_bytes_or_nil_returns_nil_on_error);
    RUN_TEST(test_from_parts_writes_be_timestamp_and_payload);
    RUN_TEST(test_from_parts_rejects_short_payload);
    RUN_TEST(test_from_parts_rejects_out_of_range_time);
    RUN_TEST(test_accessors);
    RUN_TEST(test_nil_and_max_accessors);
    TEST_MAIN_END();
}
