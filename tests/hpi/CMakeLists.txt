#
# Copyright (C) 2026 Intel Corporation.
# SPDX-License-Identifier: Apache-2.0
#

set(TARGET_NAME hpi_tests)

add_executable(
    ${TARGET_NAME}
    ./hpi_tests.cpp
)

target_link_libraries(
    ${TARGET_NAME}
    GTest::gtest_main
    helpers
    allocator_utils
)

gtest_discover_tests(${TARGET_NAME})
