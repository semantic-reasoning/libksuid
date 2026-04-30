/* SPDX-License-Identifier: LGPL-3.0-or-later
 *
 * Internal big-endian helpers. Always byte-shift -- never type-pun --
 * so the same code is correct on big- and little-endian hosts and on
 * targets with strict alignment requirements.
 */
#ifndef KSUID_BYTEORDER_H
#define KSUID_BYTEORDER_H

#include <stdint.h>

#include <limits.h>

_Static_assert (CHAR_BIT == 8, "libksuid requires 8-bit bytes");
_Static_assert (sizeof (uint32_t) == 4, "uint32_t must be exactly 4 bytes");
_Static_assert (sizeof (uint64_t) == 8, "uint64_t must be exactly 8 bytes");

static inline uint32_t
ksuid_be32_load (const uint8_t *p)
{
  return ((uint32_t) p[0] << 24)
      | ((uint32_t) p[1] << 16)
      | ((uint32_t) p[2] << 8)
      | ((uint32_t) p[3]);
}

static inline void
ksuid_be32_store (uint8_t *p, uint32_t v)
{
  p[0] = (uint8_t) (v >> 24);
  p[1] = (uint8_t) (v >> 16);
  p[2] = (uint8_t) (v >> 8);
  p[3] = (uint8_t) (v);
}

static inline uint64_t
ksuid_be64_load (const uint8_t *p)
{
  return ((uint64_t) p[0] << 56)
      | ((uint64_t) p[1] << 48)
      | ((uint64_t) p[2] << 40)
      | ((uint64_t) p[3] << 32)
      | ((uint64_t) p[4] << 24)
      | ((uint64_t) p[5] << 16)
      | ((uint64_t) p[6] << 8)
      | ((uint64_t) p[7]);
}

static inline void
ksuid_be64_store (uint8_t *p, uint64_t v)
{
  p[0] = (uint8_t) (v >> 56);
  p[1] = (uint8_t) (v >> 48);
  p[2] = (uint8_t) (v >> 40);
  p[3] = (uint8_t) (v >> 32);
  p[4] = (uint8_t) (v >> 24);
  p[5] = (uint8_t) (v >> 16);
  p[6] = (uint8_t) (v >> 8);
  p[7] = (uint8_t) (v);
}

#endif /* KSUID_BYTEORDER_H */
