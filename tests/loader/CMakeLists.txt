#
# Copyright (C) 2025-2026 Intel Corporation.
# SPDX-License-Identifier: Apache-2.0
#

set(TARGET_NAME loader_tests)

add_executable(
    ${TARGET_NAME}
    ./loader_tests.cpp
)

target_include_directories(${TARGET_NAME} PUBLIC
    ${PROJECT_SOURCE_DIR}/core/include/
    ${PROJECT_SOURCE_DIR}/loader/include/
    ${PROJECT_SOURCE_DIR}/3rdparty/nnrt/
)

target_link_libraries(
    ${TARGET_NAME}
    GTest::gtest_main
    helpers
    npu_elf
    allocator_utils
)

gtest_discover_tests(${TARGET_NAME})
