#
# Copyright (C) 2026 Intel Corporation.
# SPDX-License-Identifier: Apache-2.0
#

set(LIB_NAME helpers)

add_library(
    ${LIB_NAME}
    ./test_blob/test_blob.cpp
)

target_include_directories(
    ${LIB_NAME} PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}>
)

target_link_libraries(
    ${LIB_NAME}
    GTest::gtest_main
    npu_elf
)

set(TARGET_NAME test_blob_tests)

add_executable(
    ${TARGET_NAME}
    ./test_blob_tests.cpp
)

target_link_libraries(
    ${TARGET_NAME}
    GTest::gtest_main
    helpers
    npu_elf
)

gtest_discover_tests(${TARGET_NAME})
