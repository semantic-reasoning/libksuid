test_inc = include_directories('.', '..')

test_link = ksuid_lib.get_static_lib()

# C11 <threads.h> is not available on Apple Clang's libc shipped with
# macOS through at least Xcode 16 (April 2026); the rest of the
# library is C11-clean but the threaded RNG test relies on it. Skip
# the test rather than carry a pthread dependency just for one test.
have_threads_h = cc.has_header('threads.h')
threads_dep = dependency('threads', required : false)

base_tests = ['test_smoke', 'test_parts', 'test_base62', 'test_parse_format',
              'test_sequence', 'test_rand_os',
              'test_chacha20', 'test_new', 'test_simd_parity',
              'test_wipe', 'test_compare_parity']

foreach t : base_tests
  exe = executable(t, t + '.c',
    include_directories : test_inc,
    link_with : test_link,
  )
  test(t, exe, timeout : 30)
endforeach

if have_threads_h and threads_dep.found()
  # test_rand_tls compiles with -DKSUID_TESTING=1 only when the
  # platform exposes a thread-exit hook to assert against (issue #4
  # commit 3). KSUID_TESTING reveals the prototypes of the
  # for_testing helpers + the atomic ksuid_thread_exit_wipes_observed
  # counter in libksuid/rand.h. The library itself unconditionally
  # defines those symbols (cost: one relaxed atomic increment per
  # wipe, ~5 ns on x86_64), so the test only needs the prototype to
  # see them; no separate testing-enabled library object is
  # required.
  thread_exit_test_args = []
  has_cxa = cc.get_define('KSUID_HAVE_CXA_THREAD_ATEXIT_IMPL',
      args : common_args) == '1'
  has_fls = cc.get_define('KSUID_HAVE_FLS',
      args : common_args) == '1'
  if has_cxa or has_fls
    thread_exit_test_args += '-DKSUID_TESTING=1'
  endif
  exe = executable('test_rand_tls', 'test_rand_tls.c',
    include_directories : test_inc,
    link_with : test_link,
    dependencies : threads_dep,
    c_args : thread_exit_test_args,
  )
  test('test_rand_tls', exe, timeout : 30)
else
  message('Skipping test_rand_tls -- <threads.h> not available on this host')
endif

# Issue #1 (KSUID_NIL_INIT / KSUID_MAX_INIT) is specifically about
# Windows DLL consumers, where KSUID_PUBLIC expands to
# __declspec(dllimport) and the public sentinel symbols stop being
# constant expressions in user TUs. Every other test in this
# directory links the static archive (where KSUID_BUILDING stays
# defined and dllimport never triggers), so they DO NOT exercise
# the regression issue #1 was filed against.
#
# This dedicated TU links the SHARED library and explicitly undefines
# KSUID_BUILDING so the public header sees the dllimport / hidden-
# visibility consumer code path. On Windows this catches the original
# bug; on Linux/macOS it exercises shared-library export semantics
# uniformly.
if cc.get_argument_syntax() == 'msvc'
  test_init_shared_args = ['/UKSUID_BUILDING']
else
  test_init_shared_args = ['-UKSUID_BUILDING']
endif
exe = executable('test_init_shared', 'test_init_shared.c',
  include_directories : test_inc,
  link_with : ksuid_lib.get_shared_lib(),
  c_args : test_init_shared_args,
)
test('test_init_shared', exe, timeout : 30)

# Integration test for the ksuid-gen CLI; only registered when the
# CLI is built (default on). meson resolves File objects and build
# targets to absolute paths automatically when they appear in test()
# args, so we pass them as-is rather than calling .full_path() (which
# is not available on File objects in the meson shipped with Ubuntu
# noble).
if get_option('cli')
  sh = find_program('sh', required : true)
  test('test_cli',
    sh,
    args : [files('test_cli.sh')[0], ksuid_gen],
    timeout : 30,
  )
endif
