//
// Copyright (C) 2025 Intel Corporation.
// SPDX-License-Identifier: Apache-2.0
//

#include <gtest/gtest.h>

#include <string>

TEST(TestExample, ExpectTrue) {
    std::string var = "test example";
    EXPECT_TRUE(var.find("test") != std::string::npos);
}

TEST(TestExample, ExpectFalse) {
    std::string var = "test example";
    EXPECT_FALSE(var.find("elf") != std::string::npos);
}
