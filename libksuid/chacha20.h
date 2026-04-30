/* SPDX-License-Identifier: LGPL-3.0-or-later
 *
 * Internal ChaCha20 block function used by libksuid's per-thread CSPRNG.
 * IETF variant (RFC 8439): 32-bit block counter at state[12], 96-bit
 * nonce at state[13..15]. The block function emits 64 bytes of
 * keystream and increments state[12] with overflow into state[13]
 * (well past the 1 MiB reseed cadence, so in practice never reached).
 *
 * Algorithm by D. J. Bernstein (public domain reference at
 * http://cr.yp.to/chacha.html); this implementation is contributed
 * under LGPL-3.0-or-later along with the rest of libksuid.
 */
#ifndef KSUID_CHACHA20_H
#define KSUID_CHACHA20_H

#include <stdint.h>

/* ChaCha20 IETF block constants ("expand 32-byte k", little-endian). */
#define KSUID_CHACHA20_C0 0x61707865u
#define KSUID_CHACHA20_C1 0x3320646eu
#define KSUID_CHACHA20_C2 0x79622d32u
#define KSUID_CHACHA20_C3 0x6b206574u

/* Run one ChaCha20 block. |state| is 16 32-bit words; on entry it holds
 * the block input (constants, key, counter, nonce); on exit |out| is
 * filled with 64 bytes of keystream and |state[12]| has been
 * incremented by 1 (with carry into |state[13]|). */
void ksuid_chacha20_block (uint8_t out[64], uint32_t state[16]);

#endif /* KSUID_CHACHA20_H */
