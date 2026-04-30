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

# Hardening / portability flags applied to all our TUs.
common_args = [
  '-D_DEFAULT_SOURCE',
  '-D_POSIX_C_SOURCE=200809L',
  '-fvisibility=hidden',
  '-DKSUID_BUILDING=1',
]

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
foreach a : ['-Wshadow', '-Wstrict-prototypes', '-Wpointer-arith',
             '-Wcast-align', '-Wconversion', '-Wmissing-prototypes']
  if cc.has_argument(a)
    common_args += a
  endif
endforeach

# libsoup-style layout: the project root is on the include path so
# every #include uses the <libksuid/foo.h> form, which works
# uniformly for in-tree builds, downstream consumers, and the
# generated install tree (${prefix}/include/libksuid/ksuid.h).
inc = include_directories('.')
public_headers = files('libksuid/ksuid.h')

core_sources = files(
  'libksuid/ksuid.c',
  'libksuid/base62.c',
  'libksuid/sequence.c',
  'libksuid/rand_os.c',
  'libksuid/rand_tls.c',
  'libksuid/chacha20.c',
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
    core_sources += files('libksuid/base62_sse2.c')
    common_args += '-DKSUID_HAVE_SSE2=1'
  elif host_cpu in ['aarch64', 'arm64']
    core_sources += files('libksuid/base62_neon.c')
    common_args += '-DKSUID_HAVE_NEON=1'
  elif host_cpu == 'arm' and cc.has_argument('-mfpu=neon')
    core_sources += files('libksuid/base62_neon.c')
    common_args += '-DKSUID_HAVE_NEON=1'
  endif
endif

# Apply collected defines + warnings only after the per-arch SIMD
# section has had its chance to push KSUID_HAVE_SSE2 / _NEON.
add_project_arguments(common_args, language : 'c')

ksuid_lib = both_libraries('ksuid', core_sources,
  include_directories : inc,
  dependencies        : extra_link_deps,
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
