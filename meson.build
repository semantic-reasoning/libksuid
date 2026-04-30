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
foreach a : ['-Wshadow', '-Wstrict-prototypes', '-Wpointer-arith',
             '-Wcast-align', '-Wconversion', '-Wmissing-prototypes']
  if cc.has_argument(a)
    common_args += a
  endif
endforeach
add_project_arguments(common_args, language : 'c')

inc = include_directories('include')
public_headers = files('include/ksuid.h')

core_sources = files(
  'src/ksuid.c',
  'src/base62.c',
)

ksuid_lib = both_libraries('ksuid', core_sources,
  include_directories : inc,
  version  : meson.project_version(),
  soversion : '0',
  install  : true,
)

install_headers(public_headers)

pkg.generate(ksuid_lib.get_shared_lib(),
  name        : 'libksuid',
  description : 'Pure C11 port of segmentio/ksuid',
  version     : meson.project_version(),
  filebase    : 'libksuid',
)

if get_option('tests')
  subdir('tests')
endif
