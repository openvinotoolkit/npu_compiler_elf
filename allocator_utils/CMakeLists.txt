#
# Copyright (C) 2026 Intel Corporation.
# SPDX-License-Identifier: Apache-2.0
#

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

set(TARGET_NAME allocator_utils)

set(SOURCES
    src/blob_scanner.cpp
    src/buffer_managers.cpp
    src/io_container.cpp
)

source_group(TREE ${CMAKE_CURRENT_SOURCE_DIR} FILES ${SOURCES})

add_library(${TARGET_NAME} ${SOURCES})
target_include_directories(${TARGET_NAME} PUBLIC include)
target_link_libraries(${TARGET_NAME} PUBLIC npu_elf)

install(TARGETS ${TARGET_NAME} ARCHIVE DESTINATION lib COMPONENT ${TARGET_NAME})
