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
                  RESULT_VARIABLE UPDAT