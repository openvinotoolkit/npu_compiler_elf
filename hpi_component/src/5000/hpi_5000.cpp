
//
// Copyright (C) 2025-2026 Intel Corporation
// SPDX-License-Identifier: Apache-2.0
//

// clang-format off
#include <hpi_5000.hpp>

// clang-format on

namespace elf {

namespace {

constexpr uint32_t VPUX50XX_VERSION_MAJOR = 2;
constexpr uint32_t VPUX50XX_VERSION_MINOR = 2;
constexpr uint32_t VPUX50XX_VERSION_PATCH = 0;

// 2.2.0
// - Enable direct MMI support
//
// 2.1.0
// - Add support for DMA symbol section for dynamic strides
//
// 2.0.0:
// - Bump ELF major version to reject all pre-PV NPU5 blobs
//
// 1.2.7:
// - Add support for elf::OVNodeType::I2
// - Add support for elf::OVNodeType::U2
//
// 1.2.6:
// - Add support for elf::DType::F8E8M0
// - Rename elf::DType::FP8 -> elf::DType::F8EM5M2
// - Rename elf::DType::HF8 -> elf::DType::F8E4M3FN

}  // namespace

// By building base HostParsedInference_4000 with default ctor we ensure special CMX symtabs are initialized empty
HostParsedInference_5000::HostParsedInference_5000(elf::platform::ArchKind archKind): HostParsedInference_4000_Base() {
    archKind_ = archKind;
}

elf::Version HostParsedInference_5000::getELFLibABIVersion() const {
    switch (archKind_) {
    case elf::platform::ArchKind::VPUX501X:
        return {VPUX50XX_VERSION_MAJOR, VPUX50XX_VERSION_MINOR, VPUX50XX_VERSION_PATCH};
    default:
        break;
    }
    VPUX_ELF_THROW(RangeError, (elf::platform::stringifyArchKind(archKind_) + " arch is not supported").c_str());
    return {0, 0, 0};
}

}  // namespace elf
