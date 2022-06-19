# Copyright (c) PLUMgrid, Inc.
# Licensed under the Apache License, Version 2.0 (the "License")

include_directories(${PROJECT_SOURCE_DIR}/src/cc)
include_directories(${PROJECT_SOURCE_DIR}/src/cc/api)
if (CMAKE_USE_LIBBPF_PACKAGE AND LIBBPF_FOUND)
include_directories(${PROJECT_SOURCE_DIR}/src/cc/compat)
else()
include_directories(${PROJECT_SOURCE_DIR}/src/cc/libbpf/include/uapi)
endif()
include_directories(${PROJECT_SOURCE_DIR}/tests/python/include)

add_executable(test_static test_static.c)
if(NOT CMAKE_USE_LIBBPF_PACKAGE)
  target_link_libraries(test_static bcc-static)
else()
  target_link_libraries(test_static bcc-shared)
endif()

add_test(NAME c_test_static COMMAND ${TEST_WRAPPER} c_test_static sudo ${CMAKE_CURRENT_BINARY_DIR}/test_static)
add_compile_options(-DCMAKE_CURRENT_BINARY_DIR="${CMAKE_CURRENT_BINARY_DIR}")

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wno-unused-result -fPIC")
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wno-unused-result -fPIC")

if(ENABLE_USDT)
set(TEST_LIBBCC_SOURCES
	test_libbcc.cc
	test_c_api.cc
	test_array_table.cc
	test_bpf_table.cc
	test_cg_storage.cc
	test_hash_table.cc
	test_map_in_map.cc
	test_perf_event.cc
	test_pinned_table.cc
	test_prog_table.cc
	test_queuestack_table.cc
	test_shared_table.cc
	test_sk_storage.cc
	test_sock_table.cc
	test_usdt_args.cc
	test_usdt_probes.cc
	utils.cc
	test_parse_tracepoint.cc
	test_zip.cc)

file(COPY dummy_proc_map.txt DESTINATION ${CMAKE_CURRENT_BINARY_DIR})
add_library(usdt_test_lib SHARED usdt_test_lib.cc)
add_library(debuginfo_test_lib SHARED debuginfo_test_lib.cc)

add_custom_command(OUTPUT debuginfo.so
                   COMMAND ${CMAKE_OBJCOPY}
                   ARGS --add-symbol debuginfo_only_symbol=.text:0
                   ${CMAKE_CURRENT_BINARY_DIR}/libdebuginfo_test_lib.so
                   ${CMAKE_CURRENT_BINARY_DIR}/debuginfo.so
                   DEPENDS debuginfo_test_lib)
add_custom_target(debuginfo DEPENDS debuginfo.so)

add_custom_command(OUTPUT with_gnu_debuglink.so
                   COMMAND ${CMAKE_OBJCOPY}
                   ARGS --add-gnu-debuglink=debuginfo.so
                   ${CMAKE_CURRENT_BINARY_DIR}/libdebuginfo_test_lib.so
                   ${CMAKE_CURRENT_BINARY_DIR}/with_gnu_debuglink.so
                   DEPENDS debuginfo debuginfo_test_lib)
add_custom_target(with_gnu_debuglink DEPENDS with_gnu_debuglink.so)
SET(DEBUGINFO_TARGETS debuginfo_test_lib debuginfo with_gnu_debuglink)

if(LIBLZMA_FOUND)
  add_custom_command(OUTPUT debuginfo.so.xz
                     COMMAND xz
                     ARGS -k ${CMAKE_CURRENT_BINARY_DIR}/debuginfo.so
                     DEPENDS debuginfo)
  add_custom_target(debuginfo_xz DEPENDS debuginfo.so.xz)

  add_custom_command(OUTPUT with_gnu_debugdata.so
       