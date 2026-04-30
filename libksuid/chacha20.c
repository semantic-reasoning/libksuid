/* SPDX-License-Identifier: LGPL-3.0-or-later
 *
 * Portable ChaCha20 block function (IETF variant, RFC 8439). This is
 * the reference scalar implementation; SIMD-accelerated variants live
 * under src/arch/ once added.
 *
 * Algorithm by D. J. Bernstein, public domain reference at
 * http://cr.yp.to/chacha.html. This translation is contributed under
 * LGPL-3.0-or-later.
 */
#include <libksuid/chacha20.h>

#include <string.h>

#define ROTL32(x, n) (((x) << (n)) | ((x) >> (32 - (n))))

#define QR(a, b, c, d) do {                     \
    (a) += (b); (d) ^= (a); (d) = ROTL32 ((d), 16);     \
    (c) += (d); (b) ^= (c); (b) = ROTL32 ((b), 12);     \
    (a) += (b); (d) ^= (a); (d) = ROTL32 ((d), 8);      \
    (c) += (d); (b) ^= (c); (b) = ROTL32 ((b), 7);      \
  } while (0)

void
ksuid_chacha20_block (uint8_t out[64], uint32_t state[16])
{
  uint32_t x[16];
  memcpy (x, state, sizeof x);

  /* 20 rounds = 10 iterations of (column round + diagonal round). */
  for (int i = 0; i < 10; ++i) {
    QR (x[0], x[4], x[8], x[12]);
    QR (x[1], x[5], x[9], x[13]);
    QR (x[2], x[6], x[10], x[14]);
    QR (x[3], x[7], x[11], x[15]);
    QR (x[0], x[5], x[10], x[15]);
    QR (x[1], x[6], x[11], x[12]);
    QR (x[2], x[7], x[8], x[13]);
    QR (x[3], x[4], x[9], x[14]);
  }

  /* Add the original input then serialize little-endian. */
  for (int i = 0; i < 16; ++i) {
    uint32_t v = x[i] + state[i];
    out[i * 4 + 0] = (uint8_t) (v);
    out[i * 4 + 1] = (uint8_t) (v >> 8);
    out[i * 4 + 2] = (uint8_t) (v >> 16);
    out[i * 4 + 3] = (uint8_t) (v >> 24);
  }

  /* Increment 32-bit block counter; carry into nonce on overflow. In
   * practice the per-thread RNG reseeds every 1 MiB (= 2^14 blocks),
   * so state[12] never gets near 2^32. The carry path is here for
   * paranoia, not for hot-path correctness. */
  state[12]++;
  if (state[12] == 0)
    state[13]++;
}
