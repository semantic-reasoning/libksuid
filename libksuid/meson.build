# Generate libksuid/ksuid_version.h from meson.project_version() so
# downstream consumers can guard new API surface with `#if
# KSUID_VERSION >= ...`. Output lands at
# ${MESON_BUILD_ROOT}/libksuid/ksuid_version.h, which the parent
# include_directories('.') puts on the search path so the umbrella
# header can resolve <libksuid/ksuid_version.h> uniformly in-tree
# and post-install.

ver_parts = meson.project_version().split('.')
assert(ver_parts.length() >= 3,
  'libksuid project version must be MAJOR.MINOR.PATCH (got: '
  + meson.project_version() + ')')

# Drop a possible "-prerelease" / "+build" suffix from the patch
# component before .to_int() validates that the three numeric macros
# really are integers. The full original string still rides through
# KSUID_VERSION_STRING so callers that care can read the suffix.
ver_patch_clean = ver_parts[2].split('-')[0].split('+')[0]

ver_conf = configuration_data()
ver_conf.set('VERSION_MAJOR',  ver_parts[0].to_int())
ver_conf.set('VERSION_MINOR',  ver_parts[1].to_int())
ver_conf.set('VERSION_PATCH',  ver_patch_clean.to_int())
ver_conf.set('VERSION_STRING', meson.project_version())

ksuid_version_h = configure_file(
  input         : 'ksuid_version.h.in',
  output        : 'ksuid_version.h',
  configuration : ver_conf,
  install       : true,
  install_dir   : get_option('includedir') / 'libksuid',
)
