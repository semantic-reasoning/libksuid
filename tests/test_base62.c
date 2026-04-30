/* SPDX-License-Identifier: LGPL-3.0-or-later */
#include "../src/base62.h"
#include "test_util.h"

/* Golden vectors from segmentio/ksuid:
 *   - Nil:    27 '0' chars  / 20 zero bytes              (ksuid.go:34)
 *   - Max:    "aWgEPTl1...80V" / 20 0xff bytes           (ksuid.go:37)
 *   - Sample: "0ujtsYcgvSTl8PAuAdqWYSMnLOv"              (README.md)
 *             raw 0669F7EFB5A1CD34B5F99D1154FB6853345C9735
 */
static const uint8_t kNilBytes[KSUID_BYTES] = {0};
static const char *const kNilStr = "000000000000000000000000000";

static const uint8_t kMaxBytes[KSUID_BYTES] = {
    0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,
    0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,
};
static const char *const kMaxStr = "aWgEPTl1tmebfsQzFP4bxwgy80V";

static const uint8_t kSampleBytes[KSUID_BYTES] = {
    0x06,0x69,0xF7,0xEF,
    0xB5,0xA1,0xCD,0x34,0xB5,0xF9,0x9D,0x11,
    0x54,0xFB,0x68,0x53,0x34,0x5C,0x97,0x35,
};
static const char *const kSampleStr = "0ujtsYcgvSTl8PAuAdqWYSMnLOv";

static void encode_one(const uint8_t in[KSUID_BYTES], const char *expected) {
    uint8_t out[KSUID_STRING_LEN];
    ksuid_base62_encode(out, in);
    ASSERT_EQ_STRN((const char *)out, expected, KSUID_STRING_LEN);
}

static void decode_one(const char *in, const uint8_t expected[KSUID_BYTES]) {
    uint8_t out[KSUID_BYTES];
    ksuid_err_t e = ksuid_base62_decode(out, (const uint8_t *)in);
    ASSERT_EQ_INT(e, KSUID_OK);
    ASSERT_EQ_BYTES(out, expected, KSUID_BYTES);
}

static void test_encode_golden_vectors(void) {
    encode_one(kNilBytes,    kNilStr);
    encode_one(kMaxBytes,    kMaxStr);
    encode_one(kSampleBytes, kSampleStr);
}

static void test_decode_golden_vectors(void) {
    decode_one(kNilStr,    kNilBytes);
    decode_one(kMaxStr,    kMaxBytes);
    decode_one(kSampleStr, kSampleBytes);
}

static void test_decode_rejects_non_alphanumeric(void) {
    uint8_t out[KSUID_BYTES];
    /* '!' is not in [0-9A-Za-z]. */
    char s[KSUID_STRING_LEN];
    memset(s, '0', KSUID_STRING_LEN);
    s[26] = '!';
    ASSERT_EQ_INT(ksuid_base62_decode(out, (const uint8_t *)s),
                  KSUID_ERR_STR_VALUE);
    /* High-bit byte. */
    s[26] = (char)0x80;
    ASSERT_EQ_INT(ksuid_base62_decode(out, (const uint8_t *)s),
                  KSUID_ERR_STR_VALUE);
    /* Below '0'. */
    s[26] = '/';
    ASSERT_EQ_INT(ksuid_base62_decode(out, (const uint8_t *)s),
                  KSUID_ERR_STR_VALUE);
    /* Between '9' and 'A'. */
    s[26] = ':';
    ASSERT_EQ_INT(ksuid_base62_decode(out, (const uint8_t *)s),
                  KSUID_ERR_STR_VALUE);
}

static void test_decode_rejects_overflow(void) {
    /* "aWgEPTl1tmebfsQzFP4bxwgy80W" is one increment past KSUID_MAX's
     * encoding ('V' -> 'W'); its decoded value is 2^160 which does not
     * fit in 20 bytes. Upstream's fastDecodeBase62 returns
     * errShortBuffer; libksuid maps that to KSUID_ERR_STR_VALUE. */
    static const char *const overflow = "aWgEPTl1tmebfsQzFP4bxwgy80W";
    uint8_t out[KSUID_BYTES];
    ASSERT_EQ_INT(ksuid_base62_decode(out, (const uint8_t *)overflow),
                  KSUID_ERR_STR_VALUE);
    /* All 'z's = far past max -- must also reject. */
    char zs[KSUID_STRING_LEN];
    memset(zs, 'z', KSUID_STRING_LEN);
    ASSERT_EQ_INT(ksuid_base62_decode(out, (const uint8_t *)zs),
                  KSUID_ERR_STR_VALUE);
}

static void test_round_trip_pseudo_random(void) {
    /* Linear-congruential pattern (no entropy needed -- we are testing
     * encode . decode == identity, not randomness). */
    uint8_t in[KSUID_BYTES];
    for (size_t trial = 0; trial < 256; ++trial) {
        uint64_t s = 0x9e3779b97f4a7c15ULL ^ (trial * 0x100000001b3ULL);
        for (size_t i = 0; i < KSUID_BYTES; ++i) {
            s = s * 6364136223846793005ULL + 1442695040888963407ULL;
            in[i] = (uint8_t)(s >> 56);
        }
        uint8_t enc[KSUID_STRING_LEN];
        ksuid_base62_encode(enc, in);
        uint8_t dec[KSUID_BYTES];
        ASSERT_EQ_INT(ksuid_base62_decode(dec, enc), KSUID_OK);
        ASSERT_EQ_BYTES(dec, in, KSUID_BYTES);
    }
}

static void test_encoding_is_lex_sortable(void) {
    /* Pairs of ascending byte arrays must encode to ascending strings.
     * This is the property that lets KSUIDs sort correctly as strings. */
    uint8_t lo[KSUID_BYTES] = {0};
    uint8_t hi[KSUID_BYTES] = {0};
    for (int i = 0; i < KSUID_BYTES; ++i) {
        lo[i] = (uint8_t)(i * 7);
        hi[i] = (uint8_t)(i * 7 + 1);
    }
    uint8_t lo_s[KSUID_STRING_LEN];
    uint8_t hi_s[KSUID_STRING_LEN];
    ksuid_base62_encode(lo_s, lo);
    ksuid_base62_encode(hi_s, hi);
    ASSERT_TRUE(memcmp(lo_s, hi_s, KSUID_STRING_LEN) < 0);
}

int main(void) {
    RUN_TEST(test_encode_golden_vectors);
    RUN_TEST(test_decode_golden_vectors);
    RUN_TEST(test_decode_rejects_non_alphanumeric);
    RUN_TEST(test_decode_rejects_overflow);
    RUN_TEST(test_round_trip_pseudo_random);
    RUN_TEST(test_encoding_is_lex_sortable);
    TEST_MAIN_END();
}
