//
// Copyright (C) 2026 Intel Corporation
// SPDX-License-Identifier: Apache-2.0
//

#include "hpi_common_interface.hpp"
#include "vpux_elf/utils/error.hpp"
#include "vpux_elf/utils/version.hpp"
#include "vpux_headers/platform.hpp"
#include "vpux_hpi.hpp"

#include "compat_string_parser.hpp"

#include <sstream>

namespace elf {
namespace {

platform::ArchKind archFromPlatform(uint64_t platform) {
    switch (platform) {
    case 3720:
        return platform::ArchKind::VPUX37XX;
    case 4000:
        return platform::ArchKind::VPUX40XX;
    case 5010:
        return platform::ArchKind::VPUX501X;
    case 5020:
        return platform::ArchKind::VPUX502X;
    }
    VPUX_ELF_THROW(RuntimeError, "Invalid platform");
}

uint64_t parseInt(const std::string& str) {
    size_t pos = 0;
    uint64_t value = std::stoull(str, &pos);
    if (pos != str.size()) {
        throw std::runtime_error("Invalid integer: " + str);
    }
    return value;
}

// parse X.Y.Z, where X, Y and Z are unsigned 4-byte integers
Version parseVersion(const std::string& str) {
    const auto consume = [&str](size_t offset) {
        const auto substr = str.substr(offset);

        size_t pos = 0;
        const auto value = std::stoul(substr, &pos);

        return std::pair(value, offset + pos);
    };

    const auto [major, majorEnd] = consume(0);
    if (majorEnd >= str.size() || str[majorEnd] != '.') {
        throw std::runtime_error("Invalid version format: " + str);
    }

    const auto [minor, minorEnd] = consume(majorEnd + 1);
    if (minorEnd >= str.size() || str[minorEnd] != '.') {
        throw std::runtime_error("Invalid version format: " + str);
    }

    const auto [patch, patchEnd] = consume(minorEnd + 1);
    if (patchEnd != str.size()) {
        throw std::runtime_error("Invalid version format: " + str);
    }

    const auto version = Version(major, minor, patch);
    if (!version.checkValidity()) {
        throw std::runtime_error("Invalid version: " + str);
    }

    return version;
}

}  // namespace

void checkCompatibilityString(const DeviceDescriptor& deviceDescriptor, const std::string& compatibilityString) {
    compat::Parser parser(compatibilityString, std::array{"compiler", "npu", "t", "elf", "mi"});

    // compatibility string contains NPU Platform, which is a enum different from ArchKind
    const auto blobPlatform = parseInt(parser.getAttribute("npu"));
    const auto blobArchKind = archFromPlatform(blobPlatform);
    const auto blobTileCount = parseInt(parser.getAttribute("t"));
    const auto blobElfVersion = parseVersion(parser.getAttribute("elf"));
    const auto blobMIVersion = parseVersion(parser.getAttribute("mi"));

    const auto hwArchKind = archFromDeviceId(deviceDescriptor.deviceID);
    const auto archHpi = HostParsedInferenceCommon::getArchSpecificHPI(hwArchKind);
    const auto libElfVersion = archHpi->getELFLibABIVersion();
    const auto libMIVersion = archHpi->getStaticMIVersion();

    checkPlatformCompatibility(blobArchKind, hwArchKind);
    checkTileCountCompatibility(blobTileCount, deviceDescriptor.tileCount);
    Version::checkVersionCompatibility(libElfVersion, blobElfVersion, VersionType::ELF_ABI_VERSION);
    Version::checkVersionCompatibility(libMIVersion, blobMIVersion, VersionType::MAPPED_INFERENCE_VERSION);
}

}  // namespace elf
