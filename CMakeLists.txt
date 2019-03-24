# Copyright (c) PLUMgrid, Inc.
# Licensed under the Apache License, Version 2.0 (the "License")
cmake_minimum_required(VERSION 2.8.12)

if(${CMAKE_VERSION} VERSION_EQUAL 3.12.0 OR ${CMAKE_VERSION} VERSION_GREATER 3.12.0)
  cmake_policy(SET CMP0074 NEW)
endif()

project(bcc)
if(NOT CMAKE_BUILD_TYPE)
  set(CMAKE_BUILD_TYPE Release)
endif()

if(CMAKE_SANITIZE_TYPE)
  add_compile_options(-fsanitize=${CMAKE_SANITIZE_TYPE})
  add_link_options(-fsanitize=${CMAKE_SANITIZE_TYPE})
endif()

if(CMAKE_INSTALL_PREFIX_INITIALIZED_TO_DEFAULT)
  set(CMAKE_INSTALL_PREFIX "/usr" CACHE PATH "path to install" FORCE)
endif()

enable_testing()

execute_process(COMMAND git config --global --add safe.directory ${CMAKE_CURRENT_SOURCE_DIR}
                WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
                RESULT_VARIABLE CONFIG_RESULT)
if(CONFIG_RESULT AND NOT CONFIG_RESULT EQUAL 0)
  message(WARNING "Failed to add root source directory to safe.directory")
endif()

# populate submodule blazesym
if(NOT NO_BLAZESYM)
  execute_process(COMMAND git config --global --add safe.directory ${CMAKE_CURRENT_SOURCE_DIR}/libbpf-tools/blazesym
                  WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
                  RESULT_VARIABLE CONFIG_RESULT)
  if(CONFIG_RESULT AND NOT CONFIG_RESULT EQUAL 0)
    message(WARNING "Failed to add blazesym source directory to safe.directory")
  endif()

  execute_process(COMMAND git submodule update --init --recursive -- libbpf-tools/blazesym
                  WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
                  RESULT_VARIABLE UPDATE_RESULT)
  if(UPDATE_RESULT AND NOT UPDATE_RESULT EQUAL 0)
    message(WARNING "Failed to update submodule blazesym")
  endif()
endif()

# populate submodules (libbpf)
if(NOT CMAKE_USE_LIBBPF_PACKAGE)
  execute_process(COMMAND git config --global --add safe.directory ${CMAKE_CURRENT_SOURCE_DIR}/src/cc/libbpf
                  WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
                  RESULT_VARIABLE CONFIG_RESULT)
  if(CONFIG_RESULT AND NOT CONFIG_RESULT EQUAL 0)
    message(WARNING "Failed to add libbpf source directory to safe.directory")
  endif()
  execute_process(COMMAND git config --global --add safe.directory ${CMAKE_CURRENT_SOURCE_DIR}/libbpf-tools/bpftool
                  WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
                  RESULT_VARIABLE CONFIG_RESULT)
  if(CONFIG_RESULT AND NOT CONFIG_RESULT EQUAL 0)
    message(WARNING "Failed to add bpftool source directory to safe.directory")
  endif()

  if(NOT EXISTS ${CMAKE_CURRENT_SOURCE_DIR}/src/cc/libbpf/src)
    execute_process(COMMAND git submodule update --init --recursive
                    WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
                    RESULT_VARIABLE UPDATE_RESULT)
    if(UPDATE_RESULT AND NOT UPDATE_RESULT EQUAL 0)
      message(WARNING "Failed to update submodule libbpf")
    endif()
  else()
    execute_process(COMMAND git diff --shortstat ${CMAKE_CURRENT_SOURCE_DIR}/src/cc/libbpf/
                    OUTPUT_VARIABLE DIFF_STATUS)
    if("${DIFF_STATUS}" STREQUAL "")
      execute_process(COMMAND git submodule update --init --recursive
                      WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
                      RESULT_VARIABLE UPDATE_RESULT)
      if(UPDATE_RESULT AND NOT UPDATE_RESULT EQUAL 0)
        message(WARNING "Failed to update submodule libbpf")
      endif()
    else()
      message(WARNING "submodule libbpf dirty, so no sync")
    endif()
  endif()
endif()

# It's possible to use other kernel headers with
# KERNEL_INCLUDE_DIRS build variable, like:
#  $ cd <kernel-dir>
#  $ make INSTALL_HDR_PATH=/tmp/headers headers_install
#  $ cd <bcc-dir>
#  $ cmake -DKERNEL_INCLUDE_DIRS=/tmp/headers/include/ ...
include_directories(${KERNEL_INCLUDE_DIRS})

option(ENABLE_NO_PIE "Build bcc-lua without PIE" ON)

include(cmake/GetGitRevisionDescription.cmake)
include(cmake/version.cmake)
include(CMakeDependentOption)
include(GNUInstallDirs)
include(CheckCXXCompilerFlag)
include(cmake/FindCompilerFlag.cmake)

option(ENABLE_LLVM_NATIVECODEGEN "Enable use of llvm nativecodegen module (needed by rw-engine)" ON)
option(ENABLE_RTTI "Enable compiling with real time type information" OFF)
option(ENABLE_LLVM_SHARED "Enable linking LLVM as a shared library" OFF)
option(ENABLE_CLANG_JIT "Enable Loading BPF through Clang Frontend" ON)
option(ENABLE_USDT "Enable User-level Statically Defined Tracing" ON)
option(ENABLE_EXAMPLES "Build examples" ON)
option(ENABLE_MAN "Build man pages" ON)
option(ENABLE_TESTS "Build tests" ON)
option(RUN_LUA_TESTS "Run lua tests" ON)
option(ENABLE_LIBDEBUGINFOD "Use libdebuginfod as a source of debug symbols" ON)
CMAKE_DEPENDENT_OPTION(ENABLE_CPP_API "Enable C++ API" ON "ENABLE_USDT" OFF)

set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} ${CMAKE_CURRENT_SOURCE_DIR}/cmake)

if(ENABLE_TESTS)
  find_package(KernelHeaders)
endif()

if(CMAKE_USE_LIBBPF_PACKAGE)
  find_package(LibBpf)
endif()

if(NOT PYTHON_ONLY)
  find_package(LLVM REQUIRED CONFIG)
  message(STATUS "Found LLVM: ${LLVM_INCLUDE_DIRS} ${LLVM_PACKAGE_VERSION} (Use LLVM_ROOT envronment variable for another version of LLVM)")

  if(ENABLE_CLANG_JIT)
    find_package(BISON)
    find_package(FLEX)
    find_package(LibElf REQUIRED)
    find_package(LibDebuginfod)
    find_package(LibLzma)
    if(CLANG_DIR)
      set(CMAKE_FIND_ROOT_PATH "${CLANG_DIR}")
      include_directories("${CLANG_DIR}/include")
    endif()

    # clang is linked as a library, but the library path searching is
    # primitively supported, unlike libLLVM
    set(CLANG_SEARCH "/opt/local/llvm/lib;/usr/lib/llvm-3.7/lib;${LLVM_LIBRARY_DIRS}")
    find_library(libclangAnalysis NAMES clangAnalysis cla