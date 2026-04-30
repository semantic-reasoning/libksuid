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
              'test_chacha20', 'test_new', 'test_simd_parity']

foreach t : base_tests
  exe = executable(t, t + '.c',
    include_directories : test_inc,
    link_with : test_link,
  )
  test(t, exe, timeout : 30)
endforeach

if have_threads_h and threads_dep.found()
  exe = executable('test_rand_tls', 'test_rand_tls.c',
    include_directories : test_inc,
    link_with : test_link,
    dependencies : threads_dep,
  )
  test('test_rand_tls', exe, timeout : 30)
else
  message('Skipping test_rand_tls -- <threads.h> not available on this host')
endif

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
