#
# Copyright (C) 2025 Intel Corporation.
# SPDX-License-Identifier: Apache-2.0
#

set(TARGET_NAME test_gtest)

add_executable(
    ${TARGET_NAME}
    ./test_gtest.cpp
)

target_link_libraries(
    ${TARGET_NAME}
    GTest::gtest_main
)

gtest_discover_tests(${TARGET_NAME})
