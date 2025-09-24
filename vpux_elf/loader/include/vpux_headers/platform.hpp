//
// Copyright (C) 2023-2025 Intel Corporation
// SPDX-License-Identifier: Apache-2.0
//

#pragma once

#include <cstring>
#include <memory>
#include <string>
#include <unordered_map>
#include <vector>
#include <vpux_headers/serial_struct_base.hpp>

namespace elf {

namespace platform {

enum class ArchKind : uint64_t {
    UNKNOWN = 0,
    VPUX30XX = 1,
    VPUX37XX = 3,
    VPUX40XX = 4,
};

const std::unordered_map<std::string, elf::platform::ArchKind>& getKnownArchitectures();
elf::platform::ArchKind mapArchStringToArchKind(const std::string& archName);
std::string stringifyArchKind(const elf::platform::ArchKind& arch);
uint8_t getHardwareTileCount(const elf::platform::ArchKind& arch);

struct PlatformInfo {
    ArchKind mArchKind;
};

static_assert(sizeof(PlatformInfo) == 8, "PlatformInfo size != 8");

class SerialPlatformInfo : public elf::SerialStructBase {
public:
    SerialPlatformInfo(PlatformInfo& platformInfo) {
        addElement(platformInfo.mArchKind);
    }
};

using PlatformInfoSerialization = SerialAccess<PlatformInfo, SerialPlatformInfo>;

}  // namespace platform

}  // namespace elf
