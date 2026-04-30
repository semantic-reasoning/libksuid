test_inc = include_directories('.', '..' / 'include')

test_link = ksuid_lib.get_static_lib()

foreach t : ['test_smoke', 'test_parts', 'test_base62', 'test_parse_format',
             'test_sort']
  exe = executable(t, t + '.c',
    include_directories : test_inc,
    link_with : test_link,
  )
  test(t, exe, timeout : 30)
endforeach
