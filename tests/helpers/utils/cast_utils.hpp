//
// Copyright (C) 2026 Intel Corporation.
// SPDX-License-Identifier: Apache-2.0
//

#pragma once

#include <stdexcept>

#include "utils/printing.hpp"

template <typename To, typename From>
To dyn_cast_or_throw(From from, const char* message = "Unexpected type received") {
    auto result = dynamic_cast<To>(from);

    if (result == nullptr) {
        throw std::runtime_error(message + std::string("Expected: ") + Printing::demangle(typeid(To).name()));
    }

    return result;
}

template <typename To, typename From>
void assert_isa(From from, const char* message = "Unexpected type received") {
    (void)dyn_cast_or_throw<To>(from, message);
}
