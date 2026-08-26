//
// Copyright (C) 2023-2026 Intel Corporation
// SPDX-License-Identifier: Apache-2.0
//

#include <unordered_map>
#include <vpux_headers/platform.hpp>

namespace elf {

namespace platform {

const std::unordered_map<std::string, elf::platform::ArchKind>& getKnownArchitectures() {
    static const std::unordered_map<std::string, elf::platform::ArchKind> knownArch = {
            {"UNKNOWN", elf::platform::ArchKind::UNKNOWN}, {"VPUX30XX", elf::platform::ArchKind::VPUX30XX},
            {"NPU3720", elf::platform::ArchKind::NPU3720}, {"NPU4000", elf::platform::ArchKind::NPU4000},
            {"NPU5010", elf::platform::ArchKind::NPU5010}, {"NPU5020", elf::platform::ArchKind::NPU5020},
    };

    return knownArch;
}

elf::platform::ArchKind mapArchStringToArchKind(const std::string& archName) {
    auto& knownArch = getKnownArchitectures();
    auto retArch = knownArch.find(archName);
    if (retArch != knownArch.end()) {
        return retArch->second;
    } else {
        return elf::platform::ArchKind::UNKNOWN;
    }
}

std::string stringifyArchKind(const elf::platform::ArchKind& arch) {
    auto& knownArch = getKnownArchitectures();
    for (const auto& archIt : knownArch) {
        if (archIt.second == arch) {
            return archIt.first;
        }
    }
    return std::string("UNKNOWN");
}

uint64_t getHardwareTileCount(const elf::platform::ArchKind& arch) {
    // map between archKind and maximum hardware tile count
    static const std::unordered_map<elf::platform::ArchKind, uint8_t> hardwareTileCountsMap = {
            {elf::platform::ArchKind::UNKNOWN, 0}, {elf::platform::ArchKind::VPUX30XX, 2},
            {elf::platform::ArchKind::NPU3720, 2}, {elf::platform::ArchKind::NPU4000, 6},
            {elf::platform::ArchKind::NPU5010, 3}, {elf::platform::ArchKind::NPU5020, 1},
    };
    // get maximum hardware tile count, archKind has already been checked before
    return hardwareTileCountsMap.find(arch)->second;
}

}  // namespace platform

}  // namespace elf
