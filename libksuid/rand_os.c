/* SPDX-License-Identifier: LGPL-3.0-or-later
 *
 * Operating system entropy source for libksuid. Per-platform path:
 *
 *   Windows: BCryptGenRandom with BCRYPT_USE_SYSTEM_PREFERRED_RNG.
 *            No POSIX fallback chain is compiled in; if the call
 *            fails the only sane outcome is to surface KSUID_ERR_RNG.
 *
 *   POSIX (Linux, *BSD, macOS): try in order
 *     1. getrandom(2)  -- Linux >=3.17, FreeBSD >=12, glibc >=2.25,
 *                          MUSL >=1.1.20, macOS >=12. Cryptographic.
 *     2. getentropy(3) -- macOS >=10.12, OpenBSD. Capped at 256
 *                          bytes per call; loops to fill bigger.
 *     3. /dev/urandom  -- legacy Linux / portable POSIX fallback.
 *
 * On any failure the function returns -1 and the caller must surface
 * the error rather than degrading to a non-cryptographic source --
 * silently producing predictable bytes from an ID generator is a far
 * worse outcome than a clean error.
 */
#include <libksuid/rand.h>

#if defined(KSUID_HAVE_BCRYPT)
/* Windows path: BCryptGenRandom is the documented modern API for
 * cryptographic randomness. Linking is handled by meson via Bcrypt.lib. */
#  define WIN32_LEAN_AND_MEAN
#  include <windows.h>
#  include <bcrypt.h>
#  ifndef STATUS_SUCCESS
#    define STATUS_SUCCESS ((NTSTATUS) 0x00000000L)
#  endif
#else /* POSIX */
#  include <errno.h>
#  if defined(KSUID_HAVE_GETRANDOM)
#    include <sys/random.h>
#  endif
#  if defined(KSUID_HAVE_GETENTROPY)
#    include <unistd.h>
#  endif
/* /dev/urandom fallback always present on POSIX-ish hosts. */
#  include <fcntl.h>
#  include <sys/stat.h>
#  include <sys/types.h>
#  include <unistd.h>
#endif

#if defined(KSUID_HAVE_BCRYPT)

static int
ksuid_random_via_bcrypt (uint8_t *buf, size_t n)
{
  /* BCryptGenRandom takes a ULONG length. On 64-bit Windows ULONG
   * stays 32 bits, so we loop for buffers >= 4 GiB even though the
   * libksuid hot path never asks for that much. */
  while (n > 0) {
    ULONG chunk = (n > 0xffffffffu) ? 0xffffffffu : (ULONG) n;
    NTSTATUS s = BCryptGenRandom (NULL, buf, chunk,
        BCRYPT_USE_SYSTEM_PREFERRED_RNG);
    if (s != STATUS_SUCCESS)
      return -1;
    buf += chunk;
    n -= chunk;
  }
  return 0;
}

int
ksuid_os_random_bytes (uint8_t *buf, size_t n)
{
  if (n == 0)
    return 0;
  return ksuid_random_via_bcrypt (buf, n);
}

#else /* POSIX path */

#  if defined(KSUID_HAVE_GETRANDOM)
static int
ksuid_random_via_getrandom (uint8_t *buf, size_t n)
{
  size_t off = 0;
  while (off < n) {
    ssize_t r = getrandom (buf + off, n - off, 0);
    if (r < 0) {
      if (errno == EINTR)
        continue;
      return -1;
    }
    off += (size_t) r;
  }
  return 0;
}
#  endif

#  if defined(KSUID_HAVE_GETENTROPY)
static int
ksuid_random_via_getentropy (uint8_t *buf, size_t n)
{
  /* getentropy() is documented to fail for n > 256. */
  size_t off = 0;
  while (off < n) {
    size_t chunk = (n - off > 256) ? 256 : (n - off);
    if (getentropy (buf + off, chunk) != 0)
      return -1;
    off += chunk;
  }
  return 0;
}
#  endif

static int
ksuid_random_via_urandom (uint8_t *buf, size_t n)
{
  int fd;
  do {
    fd = open ("/dev/urandom", O_RDONLY | O_CLOEXEC);
  } while (fd < 0 && errno == EINTR);
  if (fd < 0)
    return -1;
  size_t off = 0;
  int rc = 0;
  while (off < n) {
    ssize_t r = read (fd, buf + off, n - off);
    if (r < 0) {
      if (errno == EINTR)
        continue;
      rc = -1;
      break;
    }
    if (r == 0) {
      /* /dev/urandom does not return EOF in normal operation; treat
       * this as a hard failure. */
      rc = -1;
      break;
    }
    off += (size_t) r;
  }
  close (fd);
  return rc;
}

int
ksuid_os_random_bytes (uint8_t *buf, size_t n)
{
  if (n == 0)
    return 0;

#  if defined(KSUID_HAVE_GETRANDOM)
  if (ksuid_random_via_getrandom (buf, n) == 0)
    return 0;
#  endif

#  if defined(KSUID_HAVE_GETENTROPY)
  if (ksuid_random_via_getentropy (buf, n) == 0)
    return 0;
#  endif

  return ksuid_random_via_urandom (buf, n);
}

#endif /* POSIX path */
