# Copyright (c) PLUMgrid, Inc.
# Licensed under the Apache License, Version 2.0 (the "License")

include_directories(${CMAKE_CURRENT_BINARY_DIR})
include_directories(${CMAKE_CURRENT_SOURCE_DIR})
# to be removed
include_directories(${CMAKE_CURRENT_BINARY_DIR}/frontends/b)
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/frontends/b)
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/frontends/clang)
include_directories(${LLVM_INCLUDE_DIRS})
include_directories(${LIBELF_INCLUDE_DIRS})
if (LIBLZMA_FOUND)
  include_directories(${LIBLZMA_INCLUDE_DIRS})
endif(LIBLZMA_FOUND)
if (LIBDEBUGINFOD_FOUND AND ENABLE_LIBDEBUGINFOD)
  include_directories(${LIBDEBUGINFOD_INCLUDE_DIRS})
endif (LIBDEBUGINFOD_FOUND AND ENABLE_LIBDEBUGINFOD)
# todo: if check for kernel version
if (CMAKE_USE_LIBBPF_PACKAGE AND LIBBPF_FOUND)
  include_directories(${LIBBPF_INCLUDE_DIRS})
  # create up-to-date linux/bpf.h from virtual_bpf.h (remove string wrapper);
  # when libbpf is built as a submodule we use its version of linux/bpf.h
  # so this does similar for the libbpf package, removing reliance on the
  # system uapi header which can be out of date.
  execute_process(COMMAND sh -c "cd ${CMAKE_CURRENT_SOURCE_DIR}/compat/linux && grep -ve '\\*\\*\\*\\*' virtual_bpf.h > bpf.h")
  include_directories(${CMAKE_CURRENT_SOURCE_DIR}/compat)
else()
  include_directories(${CMAKE_CURRENT_SOURCE_DIR}/libbpf/include)
  include_directories(${CMAKE_CURRENT_SOURCE_DIR}/libbpf/include/uapi)
endif()

# add_definitions has a problem parsing "-D_GLIBCXX_USE_CXX11_ABI=0", this is safer
separate_arguments(LLVM_DEFINITIONS)
add_compile_options(${LLVM_DEFINITIONS})

configure_file(libbcc.pc.in libbcc.pc @ONLY)
configure_file(bcc_version.h.in bcc_version.h @ONLY)

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fPIC -DBCC_PROG_TAG_DIR='\"${BCC_PROG_TAG_DIR}\"'")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wno-unused-result")
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fPIC -Wno-unused-result")

if (NOT HAVE_REALLOCARRAY_SUPPORT)
  set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -DCOMPAT_NEED_REALLOCARRAY")
endif()

string(REGEX MATCH "^([0-9]+).*" _ ${LLVM_PACKAGE_VERSION})
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -DLLVM_MAJOR_VERSION=${CMAKE_MATCH_1}")

include(static_libstdc++)

if(LIBBPF_INCLUDE_DIR)
  # Add user libbpf include and notify compilation
  # that we are using external libbpf. It's checked
  # in src/cc/libbpf.h and proper files are included.
  include_directories(${LIBBPF_INCLUDE_DIR})
  add_definitions(-DHAVE_EXTERNAL_LIBBPF)
endif()

if(NOT CMAKE_USE_LIBBPF_PACKAGE)
  if(LIBBPF_FOUND)
    set(extract_dir ${CMAKE_CURRENT_BINARY_DIR}/libbpf_a_extract)
    execute_process(COMMAND sh -c "mkdir -p ${extract_dir} && cd ${extract_dir} && ${CMAKE_AR} x ${LIBBPF_STATIC_LIBRARIES}")
    file(GLOB libbpf_sources "${extract_dir}/*.o")
  else()
    file(GLOB libbpf_sources "libbpf/src/*.c")
  endif()

  set(libbpf_uapi libbpf/include/uapi/linux/)
endif()

set(bcc_common_sources bcc_common.cc bpf_module.cc bcc_btf.cc exported_files.cc)
if (${LLVM_PACKAGE_VERSION} VERSION_EQUAL 6 OR ${LLVM_PACKAGE_VERSION} VERSION_GREATER 6)
  set(bcc_common_sources ${bcc_common_sources} bcc_debug.cc)
endif()

if(ENABLE_LLVM_NATIVECODEGEN)
set(bcc_common_sources ${bcc_common_sources} bpf_module_rw_engine.cc)
else()
set(bcc_common_sources ${bcc_common_sources} bpf_module_rw_engine_disabled.cc)
endif()

set(bcc_table_sources table_storage.cc shared_table.cc bpffs_table.cc json_map_decl_visitor.cc)
set(bcc_util_sources common.cc)
set(bcc_sym_sources bcc_syms.cc bcc_elf.c bcc_perf_map.c bcc_proc.c bcc_zip.c)
set(bcc_common_headers libbpf.h perf_reader.h "${CMAKE_CURRENT_BINARY_DIR}/bcc_version.h")
set(bcc_table_headers file_desc.h table_desc.h table_storage.h)
set(bcc_api_headers bcc_common.h bpf_module.h bcc_exception.h bcc_syms.h bcc_proc.h bcc_elf.h)
if(LIBBPF_FOUND)
  set(bcc_common_sources ${bcc_common_sources} libbpf.c perf_reader.c)
endif()

if(ENABLE_CLANG_JIT)
add_library(bcc-shared SHARED
  link_all.cc ${bcc_common_sources} ${bcc_table_sources} ${bcc_sym_sources}
  ${bcc_util_sources})
set_target_properties(bcc-shared