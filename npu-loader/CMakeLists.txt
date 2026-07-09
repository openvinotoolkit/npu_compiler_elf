#
# Copyright (C) 2026 Intel Corporation.
# SPDX-License-Identifier: Apache-2.0
#

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

set(TARGET_NAME npu-loader)

set(NPU_LOADER_SHA_PATTERN ${CMAKE_CURRENT_SOURCE_DIR}/include/npu_loader_version.hpp.inc)
set(NPU_LOADER_VERSION_FILE ${CMAKE_CURRENT_BINARY_DIR}/npu_loader_version.hpp)
set(NPU_LOADER_SHA_CACHE ${CMAKE_CURRENT_BINARY_DIR}/npu_loader_sha_cache.txt)

add_custom_target(npu_loader_update_version ALL
    COMMAND ${CMAKE_COMMAND}
        -D CMAKE_SOURCE_DIR=${CMAKE_CURRENT_SOURCE_DIR}
        -D NPU_LOADER_SHA_PATTERN=${NPU_LOADER_SHA_PATTERN}
        -D NPU_LOADER_VERSION_FILE=${NPU_LOADER_VERSION_FILE}
        -D NPU_LOADER_SHA_CACHE=${NPU_LOADER_SHA_CACHE}
        -P ${CMAKE_CURRENT_SOURCE_DIR}/cmake/npu_loader_version.cmake
    COMMENT "Updating version..."
    BYPRODUCTS ${NPU_LOADER_VERSION_FILE} ${NPU_LOADER_SHA_CACHE}
)

add_library(npu_loader_version INTERFACE)
target_include_directories(npu_loader_version INTERFACE ${CMAKE_CURRENT_BINARY_DIR})
add_dependencies(npu_loader_version npu_loader_update_version)

include(${CMAKE_SOURCE_DIR}/cmake/gflags.cmake)

source_group(TREE ${CMAKE_CURRENT_SOURCE_DIR} FILES main.cpp)

add_executable(${TARGET_NAME} main.cpp)
target_link_libraries(${TARGET_NAME}
    gflags
    allocator_utils
    npu_loader_version
)

install(TARGETS ${TARGET_NAME} RUNTIME DESTINATION bin COMPONENT ${TARGET_NAME})
