test_inc = include_directories('.', '..')

test_link = ksuid_lib.get_static_lib()

threads_dep = dependency('threads')

# Tests that need C11 <threads.h> link against the threads dep; others
# don't need to.
threaded_tests = ['test_rand_tls']

foreach t : ['test_smoke', 'test_parts', 'test_base62', 'test_parse_format',
             'test_sort', 'test_next_prev', 'test_sequence', 'test_rand_os',
             'test_chacha20', 'test_rand_tls', 'test_new', 'test_simd_parity']
  deps = []
  if threaded_tests.contains(t)
    deps += threads_dep
  endif
  exe = executable(t, t + '.c',
    include_directories : test_inc,
    link_with : test_link,
    dependencies : deps,
  )
  test(t, exe, timeout : 30)
endforeach

# Integration test for the ksuid-gen CLI; only registered when the
# CLI is built (default on).
if get_option('cli')
  sh = find_program('sh', required : true)
  test('test_cli',
    sh,
    args : [files('test_cli.sh')[0].full_path(), ksuid_gen.full_path()],
    timeout : 30,
  )
endif
