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
  set(CMAKE_C_FLAGS "${CM