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
  target_link_libr