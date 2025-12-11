//
// Copyright (C) 2025 Intel Corporation
// SPDX-License-Identifier: Apache-2.0
//

#pragma once

#include <vpux_headers/serial_struct_base.hpp>

namespace elf {
struct CompilerHashInfo {
    std::vector<uint8_t> mCompilerHash;

    CompilerHashInfo() = default;
    CompilerHashInfo(const std::string& compilerHashString) {
        mCompilerHash.assign(compilerHashString.begin(), compilerHashString.end());
    }
};

class SerialCompilerInfo : public SerialStructBase {
public:
    SerialCompilerInfo(elf::CompilerHashInfo& compilerHashInfo) {
        addElementVector(compilerHashInfo.mCompilerHash);
    }
};

using CompilerHashSerialization = SerialAccess<CompilerHashInfo, SerialCompilerInfo>;

}  // namespace elf
