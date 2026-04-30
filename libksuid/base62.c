/* SPDX-License-Identifier: LGPL-3.0-or-later AND MIT
 *
 * Scalar base62 encode/decode for the 20-byte KSUID payload.
 *
 * Derived from segmentio/ksuid (MIT, Copyright (c) 2017 Segment.io):
 *   - alphabet, 5 x uint32 long division by 62:    base62.go:8-82
 *   - 27-digit long division by 2^32, validation:  base62.go:102-175
 *
 * Both routines are inherently sequential along the long-division
 * carry chain and do not benefit from SIMD; vectorization opportunities
 * for libksuid live in input-character validation and bulk operations,
 * not the divide-and-emit core that runs here.
 */
#include <libksuid/base62.h>

#include <string.h>

#include <libksuid/byteorder.h>

/* The NUL terminator at index 62 is intentionally kept (no [62] fixed
 * size) so gcc -Wunterminated-string-initialization is satisfied; the
 * encode loop only ever indexes 0..61. */
static const char kB62Alphabet[]
    = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";

/* ASCII -> base62 digit value, with 0xFF as the invalid sentinel. The
 * table is deliberately built at compile time so the hot path stays
 * branchless and so a future SIMD validation pass can use the same
 * values. */
static const uint8_t kB62Value[256] = {
  /* 0x00 */ 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
  /* 0x08 */ 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
  /* 0x10 */ 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
  /* 0x18 */ 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
  /* 0x20 */ 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
  /* 0x28 */ 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
  /* '0'..'9' = 0..9 */
  /* 0x30 */ 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
  /* 0x38 */ 0x08, 0x09, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
  /* 0x40 */ 0xff,
  /* 'A'..'Z' = 10..35 */
  0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
  /* 0x48 */ 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
  /* 0x50 */ 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20,
  /* 0x58 */ 0x21, 0x22, 0x23, 0xff, 0xff, 0xff, 0xff, 0xff,
  /* 0x60 */ 0xff,
  /* 'a'..'z' = 36..61 */
  0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a,
  /* 0x68 */ 0x2b, 0x2c, 0x2d, 0x2e, 0x2f, 0x30, 0x31, 0x32,
  /* 0x70 */ 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3a,
  /* 0x78 */ 0x3b, 0x3c, 0x3d, 0xff, 0xff, 0xff, 0xff, 0xff,
  /* 0x80..0xff: all invalid */
  [128] = 0xff,[129] = 0xff,[130] = 0xff,[131] = 0xff,[132] = 0xff,[133] = 0xff,
  [134] = 0xff,[135] = 0xff,[136] = 0xff,[137] = 0xff,[138] = 0xff,[139] = 0xff,
  [140] = 0xff,[141] = 0xff,[142] = 0xff,[143] = 0xff,[144] = 0xff,[145] = 0xff,
  [146] = 0xff,[147] = 0xff,[148] = 0xff,[149] = 0xff,[150] = 0xff,[151] = 0xff,
  [152] = 0xff,[153] = 0xff,[154] = 0xff,[155] = 0xff,[156] = 0xff,[157] = 0xff,
  [158] = 0xff,[159] = 0xff,[160] = 0xff,[161] = 0xff,[162] = 0xff,[163] = 0xff,
  [164] = 0xff,[165] = 0xff,[166] = 0xff,[167] = 0xff,[168] = 0xff,[169] = 0xff,
  [170] = 0xff,[171] = 0xff,[172] = 0xff,[173] = 0xff,[174] = 0xff,[175] = 0xff,
  [176] = 0xff,[177] = 0xff,[178] = 0xff,[179] = 0xff,[180] = 0xff,[181] = 0xff,
  [182] = 0xff,[183] = 0xff,[184] = 0xff,[185] = 0xff,[186] = 0xff,[187] = 0xff,
  [188] = 0xff,[189] = 0xff,[190] = 0xff,[191] = 0xff,[192] = 0xff,[193] = 0xff,
  [194] = 0xff,[195] = 0xff,[196] = 0xff,[197] = 0xff,[198] = 0xff,[199] = 0xff,
  [200] = 0xff,[201] = 0xff,[202] = 0xff,[203] = 0xff,[204] = 0xff,[205] = 0xff,
  [206] = 0xff,[207] = 0xff,[208] = 0xff,[209] = 0xff,[210] = 0xff,[211] = 0xff,
  [212] = 0xff,[213] = 0xff,[214] = 0xff,[215] = 0xff,[216] = 0xff,[217] = 0xff,
  [218] = 0xff,[219] = 0xff,[220] = 0xff,[221] = 0xff,[222] = 0xff,[223] = 0xff,
  [224] = 0xff,[225] = 0xff,[226] = 0xff,[227] = 0xff,[228] = 0xff,[229] = 0xff,
  [230] = 0xff,[231] = 0xff,[232] = 0xff,[233] = 0xff,[234] = 0xff,[235] = 0xff,
  [236] = 0xff,[237] = 0xff,[238] = 0xff,[239] = 0xff,[240] = 0xff,[241] = 0xff,
  [242] = 0xff,[243] = 0xff,[244] = 0xff,[245] = 0xff,[246] = 0xff,[247] = 0xff,
  [248] = 0xff,[249] = 0xff,[250] = 0xff,[251] = 0xff,[252] = 0xff,[253] = 0xff,
  [254] = 0xff,[255] = 0xff,
};

void
ksuid_base62_encode (uint8_t out[KSUID_STRING_LEN],
    const uint8_t in[KSUID_BYTES])
{
  /* Treat the 20-byte input as five base-2^32 limbs, MSB first. */
  uint32_t bp[5] = {
    ksuid_be32_load (in + 0),
    ksuid_be32_load (in + 4),
    ksuid_be32_load (in + 8),
    ksuid_be32_load (in + 12),
    ksuid_be32_load (in + 16),
  };
  size_t bp_len = 5;
  uint32_t bq[5];

  int n = KSUID_STRING_LEN;
  while (bp_len > 0) {
    size_t bq_len = 0;
    uint64_t remainder = 0;
    for (size_t i = 0; i < bp_len; ++i) {
      uint64_t value = (uint64_t) bp[i] + remainder * UINT64_C (4294967296);
      uint64_t digit = value / 62;
      remainder = value % 62;
      if (bq_len != 0 || digit != 0) {
        bq[bq_len++] = (uint32_t) digit;
      }
    }
    --n;
    out[n] = (uint8_t) kB62Alphabet[remainder];
    memcpy (bp, bq, bq_len * sizeof (uint32_t));
    bp_len = bq_len;
  }
  /* Pad head with '0' for any bytes not yet written. */
  if (n > 0) {
    memset (out, '0', (size_t) n);
  }
}

ksuid_err_t
ksuid_base62_decode (uint8_t out[KSUID_BYTES],
    const uint8_t in[KSUID_STRING_LEN])
{
  /* Translate ASCII -> base62 value, rejecting anything outside the
   * 62-character alphabet. */
  uint8_t bp[KSUID_STRING_LEN];
  for (size_t i = 0; i < KSUID_STRING_LEN; ++i) {
    uint8_t v = kB62Value[in[i]];
    if (v == 0xff)
      return KSUID_ERR_STR_VALUE;
    bp[i] = v;
  }
  size_t bp_len = KSUID_STRING_LEN;
  uint8_t bq[KSUID_STRING_LEN];

  int n = KSUID_BYTES;
  while (bp_len > 0) {
    size_t bq_len = 0;
    uint64_t remainder = 0;
    for (size_t i = 0; i < bp_len; ++i) {
      uint64_t value = (uint64_t) bp[i] + remainder * 62;
      uint64_t digit = value / UINT64_C (4294967296);
      remainder = value % UINT64_C (4294967296);
      if (bq_len != 0 || digit != 0) {
        bq[bq_len++] = (uint8_t) digit;
      }
    }
    /* If we still have a non-empty quotient but the destination
     * cannot hold another 4-byte limb, the input encodes a number
     * greater than 2^160 - 1. Upstream emits errShortBuffer here
     * which Parse re-maps to errStrValue. */
    if (n < 4)
      return KSUID_ERR_STR_VALUE;
    out[n - 4] = (uint8_t) (remainder >> 24);
    out[n - 3] = (uint8_t) (remainder >> 16);
    out[n - 2] = (uint8_t) (remainder >> 8);
    out[n - 1] = (uint8_t) (remainder);
    n -= 4;
    memcpy (bp, bq, bq_len);
    bp_len = bq_len;
  }
  /* Zero-pad the head if the value didn't span the full 20 bytes. */
  if (n > 0) {
    memset (out, 0, (size_t) n);
  }
  return KSUID_OK;
}
