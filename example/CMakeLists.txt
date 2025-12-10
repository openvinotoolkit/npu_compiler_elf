# Copyright (C) 2023-2025 Intel Corporation
# SPDX-License-Identifier: Apache-2.0

set (EXAMPLES simplereader simplewriter)

foreach(TARGET_NAME ${EXAMPLES})
    source_group(TREE ${CMAKE_CURRENT_SOURCE_DIR} FILES ${TARGET_NAME}.cpp)
    add_executable(${TARGET_NAME} ${CMAKE_CURRENT_SOURCE_DIR}/${TARGET_NAME}/${TARGET_NAME}.cpp)

    enable_warnings_as_errors(${TARGET_NAME} WIN_STRICT)
    target_link_libraries(${TARGET_NAME} npu_elf)
endforeach()
