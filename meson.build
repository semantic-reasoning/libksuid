project('libksuid', 'c',
  version : '0.1.0',
  license : 'LGPL-3.0-or-later AND MIT',
  meson_version : '>=1.1.0',
  default_options : [
    'c_std=c11',
    'warning_level=3',
    'b_ndebug=if-release',
    'default_library=both',
  ],
)

cc = meson.get_compiler('c')
pkg = import('pkgconfig')

# Hardening / portability flags applied to all our TUs. Compiler-
# specific defaults split between gcc/clang and MSVC: visibility
# control + POSIX feature macros only mean anything on the GCC-style
# command line, and MSVC needs an explicit opt-in to C11 atomics
# until they leave experimental status.
common_args = ['-DKSUID_BUILDING=1']
if cc.get_argument_syntax() == 'msvc'
  # MSVC's <stdatomic.h> is gated behind /experimental:c11atomics
  # until C11 atomics ship as fully supported (Microsoft Learn:
  # /experimental:c11atomics). Without it the header emits
  # #error: "C atomic support is not enabled".
  common_args += ['/experimental:c11atomics']
else
  common_args += [
    '-D_DEFAULT_SOURCE',
    '-D_POSIX_C_SOURCE=200809L',
    '-fvisibility=hidden',
  ]
endif

# OS entropy source detection. Per-host: at most one of these is
# preferred at runtime; the others either are not present (Windows has
# neither getrandom nor getentropy) or are kept compiled-in as a
# secondary fallback (urandom on POSIX).
if cc.has_function('getrandom', prefix : '#include <sys/random.h>')
  common_args += '-DKSUID_HAVE_GETRANDOM=1'
endif
if cc.has_function('getentropy', prefix : '#include <unistd.h>')
  common_args += '-DKSUID_HAVE_GETENTROPY=1'
endif

# DSE-resistant wipe primitive (issue #2). The explicit_bzero
# prototype lives in different headers on different platforms:
# modern glibc (2.25+), macOS 14.4+, and OpenBSD declare it in
# <string.h>; FreeBSD, NetBSD, and some older glibc / MUSL builds
# put it in <strings.h>. Probe <string.h> first (the common case)
# and fall back to <strings.h>.
#
# Pass _DEFAULT_SOURCE explicitly because meson does not inherit
# add_project_arguments() into has_function() probes, and glibc
# gates the prototype behind that feature macro.
#
# memset_s is the C11 Annex K third option; rarely shipped.
# Windows uses SecureZeroMemory unconditionally (the macro lives
# in <windows.h> and cc.has_function lies on macros, so detect by
# host system instead).
wipe_backend = 'volatile-fallback'
if cc.has_function('explicit_bzero',
    prefix : '#include <string.h>',
    args   : ['-D_DEFAULT_SOURCE'])
  common_args += '-DKSUID_HAVE_EXPLICIT_BZERO_STRING_H=1'
  wipe_backend = 'explicit_bzero (<string.h>)'
elif cc.has_function('explicit_bzero',
    prefix : '#include <strings.h>',
    args   : ['-D_DEFAULT_SOURCE'])
  common_args += '-DKSUID_HAVE_EXPLICIT_BZERO_STRINGS_H=1'
  wipe_backend = 'explicit_bzero (<strings.h>)'
elif host_machine.system() == 'windows'
  wipe_backend = 'SecureZeroMemory'
elif cc.has_function('memset_s',
    prefix : '#define __STDC_WANT_LIB_EXT1__ 1\n#include <string.h>')
  common_args += '-DKSUID_HAVE_MEMSET_S=1'
  # Annex K's memset_s prototype is gated behind __STDC_WANT_LIB_EXT1__
  # on every libc that provides it (glibc, Apple libc, MUSL...).
  # Defining the opt-in macro project-wide -- not just inside wipe.h
  # -- guarantees it is set before <string.h> is first included by
  # ANY translation unit, since wipe.h cannot rewind a prior include
  # that already pulled <string.h> in without the opt-in.
  common_args += '-D__STDC_WANT_LIB_EXT1__=1'
  wipe_backend = 'memset_s (C11 Annex K)'
endif
summary({'wipe backend' : wipe_backend}, section : 'libksuid')

# Issue #4 thread-exit wipe registration. Probe via cc.links() with
# an explicit prototype rather than cc.has_function() because
# __cxa_thread_atexit_impl is a private libc symbol that no public
# header declares -- has_function would either spuriously fail
# (no prototype) or spuriously pass (linker found a different
# weak alias). Linking with the explicit prototype is the only
# honest signal that the actual ABI matches what we're going to
# call.
thread_exit_backend = 'documented residue (no automatic wipe)'
cxa_thread_atexit_test = '''
extern int __cxa_thread_atexit_impl(void (*fn)(void *), void *arg, void *dso);
extern void *__dso_handle;
static void wipe(void *p) { (void)p; }
int main(void) {
  return __cxa_thread_atexit_impl(wipe, (void *)0, &__dso_handle);
}
'''
if cc.links(cxa_thread_atexit_test,
    name : '__cxa_thread_atexit_impl + __dso_handle')
  common_args += '-DKSUID_HAVE_CXA_THREAD_ATEXIT_IMPL=1'
  thread_exit_backend = '__cxa_thread_atexit_impl'
elif host_machine.system() == 'windows'
  common_args += '-DKSUID_HAVE_FLS=1'
  thread_exit_backend = 'FlsAlloc (Windows)'
endif
summary({'thread-exit wipe' : thread_exit_backend}, section : 'libksuid')

# Windows: the supported entropy source is BCryptGenRandom. The whole
# /dev/urandom + getrandom + getentropy chain doesn't apply, and
# rand_os.c switches to a Bcrypt-only path when KSUID_HAVE_BCRYPT is
# defined.
extra_link_deps = []
if host_machine.system() == 'windows'
  bcrypt_dep = cc.find_library('bcrypt', required : true)
  extra_link_deps += bcrypt_dep
  common_args += '-DKSUID_HAVE_BCRYPT=1'
endif
if cc.get_argument_syntax() != 'msvc'
  foreach a : ['-Wshadow', '-Wstrict-prototypes', '-Wpointer-arith',
               '-Wcast-align', '-Wconversion', '-Wmissing-prototypes']
    if cc.has_argument(a)
      common_args += a
    endif
  endforeach
endif

# libsoup-style layout: the project root is on the include path so
# every #include uses the <libksuid/foo.h> form, which works
# uniformly for in-tree builds, downstream consumers, and the
# generated install tree (${prefix}/include/libksuid/ksuid.h).
inc = include_directories('.')
public_headers = files('libksuid/ksuid.h')

# Generate libksuid/ksuid_version.h alongside the source tree's
# libksuid/. The configure_file lives in libksuid/meson.build so
# its output lands at ${MESON_BUILD_ROOT}/libksuid/ksuid_version.h
# and resolves through |inc| as <libksuid/ksuid_version.h>.
subdir('libksuid')

core_sources = files(
  'libksuid/ksuid.c',
  'libksuid/base62.c',
  'libksuid/sequence.c',
  'libksuid/rand_os.c',
  'libksuid/rand_tls.c',
  'libksuid/chacha20.c',
  'libksuid/compare_scalar.c',
  'libksuid/encode_batch.c',
)

# SIMD / NEON acceleration. SSE2 is part of the x86_64 ABI baseline
# (mandatory since the AMD64 spec) and likewise NEON for aarch64,
# so we compile the per-arch kernel TU directly into core_sources
# without runtime feature detection. ARMv7 NEON is opt-in via
# -mfpu=neon. Other hosts fall back to the scalar translate path
# that lives unconditionally in base62.c.
host_cpu = host_machine.cpu_family()
if get_option('simd') != 'none'
  if host_cpu == 'x86_64'
    core_sources += files(
      'libksuid/base62_sse2.c',
      'libksuid/compare_sse2.c',
    )
    common_args += '-DKSUID_HAVE_SSE2=1'
  elif host_cpu in ['aarch64', 'arm64']
    core_sources += files(
      'libksuid/base62_neon.c',
      'libksuid/compare_neon.c',
    )
    common_args += '-DKSUID_HAVE_NEON=1'
  elif host_cpu == 'arm' and cc.has_argument('-mfpu=neon')
    core_sources += files(
      'libksuid/base62_neon.c',
      'libksuid/compare_neon.c',
    )
    common_args += '-DKSUID_HAVE_NEON=1'
  endif
endif

# AVX2 8-wide ksuid_string_batch kernel. Compiled in its own static
# library with -mavx2 (or /arch:AVX2 on MSVC) so the rest of libksuid
# keeps the SSE2 baseline ABI; the kernel is selected at runtime via
# CPUID inside the dispatcher (libksuid/encode_batch.c). Non-x86_64
# hosts skip this entirely; non-AVX2 x86_64 hosts compile the TU but
# never call into it.
have_avx2_batch = false
avx2_arg = ''
if get_option('simd') != 'none' and host_cpu == 'x86_64'
  if get_option('avx2_batch').allowed()
    if cc.get_argument_syntax() == 'msvc'
      candidate = '/arch:AVX2'
    else
      candidate = '-mavx2'
    endif
    if cc.has_argument(candidate)
      have_avx2_batch = true
      avx2_arg = candidate
      common_args += '-DKSUID_HAVE_AVX2_BATCH=1'
    endif
  endif
endif

# Apply collected defines + warnings only after the per-arch SIMD
# section has had its chance to push KSUID_HAVE_SSE2 / _NEON /
# _AVX2_BATCH.
add_project_arguments(common_args, language : 'c')

avx2_lib_dep = []
if have_avx2_batch
  # PIC required so the same objects can land in both the static and
  # shared variants of `both_libraries('ksuid', ...)` below.
  ksuid_avx2_lib = static_library('ksuid_avx2_batch',
    'libksuid/encode_avx2.c',
    include_directories : inc,
    c_args              : [avx2_arg],
    pic                 : true,
    install             : false,
  )
  # link_whole forces every object from the AVX2 static lib into the
  # final library archive even though the call site (the trampoline
  # in encode_batch.c) only ever takes the address of the kernel
  # behind a runtime CPUID check; without link_whole the linker may
  # GC the symbol on shared-library link.
  avx2_lib_dep = [ksuid_avx2_lib]
endif

ksuid_lib = both_libraries('ksuid', core_sources,
  include_directories : inc,
  dependencies        : extra_link_deps,
  link_whole          : avx2_lib_dep,
  version             : meson.project_version(),
  soversion           : '0',
  install             : true,
)

install_headers(public_headers, subdir : 'libksuid')

# License + attribution artifacts MUST ship with every redistribution
# of libksuid in source or binary form: LGPL-3.0-or-later requires the
# LGPL text, and the upstream MIT terms (LICENSE.MIT) require the
# permission notice "be included in all copies or substantial portions
# of the Software". NOTICE documents how the two combine.
license_dir = get_option('datadir') / 'doc' / 'libksuid'
install_data(
  files('LICENSE', 'LICENSE.MIT', 'NOTICE'),
  install_dir : license_dir,
)

pkg.generate(ksuid_lib.get_shared_lib(),
  name        : 'libksuid',
  description : 'Pure C11 port of segmentio/ksuid',
  version     : meson.project_version(),
  filebase    : 'libksuid',
)

if get_option('cli')
  ksuid_gen = executable('ksuid-gen',
    'examples/ksuid-gen.c',
    include_directories : inc,
    link_with : ksuid_lib.get_static_lib(),
    install : true,
  )
endif

if get_option('tests')
  subdir('tests')
endif
