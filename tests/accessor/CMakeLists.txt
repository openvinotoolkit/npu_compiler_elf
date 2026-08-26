#
# Copyright (C) 2026 Intel Corporation.
# SPDX-License-Identifier: Apache-2.0
#

set(TARGET_NAME accessor_tests)

add_executable(
    ${TARGET_NAME}
    ./accessor_tests.cpp
)

target_include_directories(${TARGET_NAME} PUBLIC
    ${PROJECT_SOURCE_DIR}/core/include/
    ${PROJECT_SOURCE_DIR}/loader/include/
    ${PROJECT_SOURCE_DIR}/3rdparty/nnrt/
)

target_link_libraries(
    ${TARGET_NAME}
    GTest::gtest_main
    npu_elf
)

gtest_discover_tests(${TARGET_NAME})
