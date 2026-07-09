//
// Copyright (C) 2026 Intel Corporation.
// SPDX-License-Identifier: Apache-2.0
//

#pragma once

#include <iostream>
#include <memory>
#include <sstream>
#include <string>

#if defined(__clang__) || defined(__GNUC__)
#include <cxxabi.h>
#endif

class Printing {
public:
    static std::string demangle(const char* name) {
#if defined(__clang__) || defined(__GNUC__)
        int status = -1;
        std::unique_ptr<char[], void (*)(void*)> res{abi::__cxa_demangle(name, NULL, NULL, &status), std::free};
        return (status == 0) ? res.get() : name;
#endif
        return name;
    }

    static std::string getHexString(const long& value) {
        std::stringstream stream;
        stream << "0x" << std::hex << value;
        return stream.str();
    }
};
