# libksuid

A pure C11 port of [`segmentio/ksuid`](https://github.com/segmentio/ksuid)
focused on small footprint, lock-free thread safety, and SIMD/NEON
acceleration where the underlying algorithms admit it.

## Status

Early development. The public API and ABI are unstable until 1.0.

## Goals

- **Pure C11.** No pthread; thread safety via `_Thread_local` storage and
  `<stdatomic.h>` only.
- **meson + ninja** build. Both static and shared libraries plus a
  `ksuid-gen` CLI for round-trip generation and parsing.
- **Wire-compatible** with upstream `segmentio/ksuid` — same 20-byte
  binary layout, same 27-character base62 string encoding, same epoch
  (1400000000 = 2014-05-13 16:53:20 UTC), same ordering invariants.
- **Honest SIMD**: the base62 long-division core is sequential and is
  not vectorizable; SSE2/NEON paths accelerate input validation,
  20-byte comparison, and big-endian byte-swaps.
- **Small footprint**: no heap allocations on the hot path; no
  third-party runtime dependencies.

## Licensing

libksuid is distributed under the **GNU Lesser General Public License,
version 3 or later** (see [`LICENSE`](LICENSE)). It is a derivative
work that ports algorithms and binary formats from `segmentio/ksuid`,
which is distributed under the **MIT License** (see
[`LICENSE.MIT`](LICENSE.MIT) for the upstream text). The combined
attribution requirements are described in [`NOTICE`](NOTICE).

Source files derived from upstream Go code carry the SPDX header

```
SPDX-License-Identifier: LGPL-3.0-or-later AND MIT
```

and a pointer back to the upstream source they were ported from.

## Building

```sh
meson setup build
meson compile -C build
meson test    -C build
```

## Layout

The repository follows the libsoup-style single-source-directory
convention. All public and private library code lives under
`libksuid/`, and every C file -- inside the library, in tests, and in
examples -- includes its dependencies with the prefixed form

```c
#include <libksuid/ksuid.h>          /* the public umbrella */
#include <libksuid/base62.h>         /* internal helper */
```

After install the public header lands at
`${prefix}/include/libksuid/ksuid.h`, so downstream consumers use the
exact same include line that the in-tree sources do.

```
libksuid/        library source + headers (public ksuid.h here too)
examples/        example consumers; ksuid-gen CLI
tests/           unit + integration tests
tools/           build tooling (gst-indent)
hooks/           git hooks (pre-commit code-style check)
```

## Acknowledgements

The KSUID specification, base62 alphabet, encoding scheme, and reference
test vectors all originate from
[`segmentio/ksuid`](https://github.com/segmentio/ksuid) (MIT License,
Copyright (c) 2017 Segment.io). This project would not exist without
that prior art.
