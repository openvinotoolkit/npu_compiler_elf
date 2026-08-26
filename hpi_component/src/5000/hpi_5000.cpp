
//
// Copyright (C) 2025-2026 Intel Corporation
// SPDX-License-Identifier: Apache-2.0
//

// clang-format off
#include <hpi_5000.hpp>

// clang-format on

namespace elf {

namespace {

constexpr uint32_t NPU_ABI_VERSION_MAJOR = 2;
constexpr uint32_t NPU_ABI_VERSION_MINOR = 4;
constexpr uint32_t NPU_ABI_VERSION_PATCH = 0;

// 2.4.0
// - Add relocations for dynamic strides bit relocations.
//
// 2.3.1
// - Remove legacy elf::platform::ArchKind encodings
//
// 2.3.0
// - Add support for VPU_SHT_HPI section with direct HostParsedInference consumption path
//
// 2.2.7
// - Add NPU* product-ID encodings
//
// 2.2.6
// - Fix DMA address multiplication overflow in calculateDmaAddress
//
// 2.2.5
// - allow normalized 0 alignment
//
// 2.2.4
// - Fix DMA JIT user-stride copy size to avoid out-of-bounds read
//
// 2.2.3
// - Add support for VPU_SHT_COMPATIBILITY_STRING section type
//
// 2.2.2
// - Fix header offset overflow in Reader when section table offset is close to file size limit
// 2.2.1
// - Fix security vulnerabilities

//
// 2.2.0
// - Enable direct MMI support
//
// 2.1.0
// - Add support for DMA symbol section for dynamic strides
//
// 2.0.0
// - Bump ELF major version to reject all pre-PV NPU5 blobs
//
// 1.2.7
// - Add support for elf::OVNodeType::I2
// - Add support for elf::OVNodeType::U2
//
// 1.2.6
// - Add support for elf::DType::F8E8M0
// - Rename elf::DType::FP8 -> elf::DType::F8EM5M2
// - Rename elf::DType::HF8 -> elf::DType::F8E4M3FN

}  // namespace

// By building base HostParsedInference_4000 with default ctor we ensure special CMX symtabs are initialized empty
HostParsedInference_5000::HostParsedInference_5000(elf::platform::ArchKind archKind): HostParsedInference_4000_Base() {
    archKind_ = archKind;
}

elf::Version HostParsedInference_5000::getELFLibABIVersion() const {
    return {NPU_ABI_VERSION_MAJOR, NPU_ABI_VERSION_MINOR, NPU_ABI_VERSION_PATCH};
}

}  // namespace elf
