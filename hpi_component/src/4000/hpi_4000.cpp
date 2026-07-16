
//
// Copyright (C) 2023-2026 Intel Corporation
// SPDX-License-Identifier: Apache-2.0
//

// clang-format off
#include <cstdint>
#include <vpux_elf/utils/utils.hpp>
#include <vpux_elf/utils/log.hpp>
#include <vpux_elf/utils/error.hpp>
#include <vpux_elf/types/section_header.hpp>
#include <vpux_elf/types/vpu_extensions.hpp>
#include <hpi_4000.hpp>

#include <vector>
#include <string>
#include <vector>
#include <array>
#include <cstring>

#include <api/vpu_nnrt_api.h>

// clang-format on

namespace { // NNRT api defines. Must not be changed. Required for LNL PV
            // compatibility.
constexpr uint32_t VPU_METADATA_STORAGE_ADDR = 0x40203c00;
constexpr uint32_t VPU_WORKSPACE_ADDR = 0x40218000;
constexpr uint32_t VPU_WORKSPACE_SIZE_IN_BYTES = 1440 * 1024;
constexpr uint32_t VPU_MAX_TILES = 6;
} // namespace


namespace elf {

namespace {
// Base of frequency values used in tables (in MHz).
constexpr uint32_t FREQ_BASE = 700;
// Step of frequency for each entry in tables (in MHz).
constexpr uint32_t FREQ_STEP = 100;
// Base of bandwidth values used in tables (in MB/s).
constexpr uint32_t BW_BASE = 2000;
// Step of bandwidth values used in tables (in MB/s).
constexpr uint32_t BW_STEP = 100;

// value in [0.0..1.0] range indicating scalability of network for a given DDR bandwidth.
const std::array<float, VPU_SCALABILITY_VALUES_PER_FREQ> byBWScales({0.0F, 0.2F, 0.4F, 0.6F, 0.8F});
// expected ticks (based on FRC @37.5MHz) an inference should take for a given DDR bandwidth.
const std::array<uint64_t, VPU_SCALABILITY_VALUES_PER_FREQ> byBWTicks({10UL, 12UL, 14UL, 16UL, 18UL});

}  // namespace

namespace {

constexpr uint32_t VPUX40XX_VERSION_MAJOR = 1;
constexpr uint32_t VPUX40XX_VERSION_MINOR = 3;
constexpr uint32_t VPUX40XX_VERSION_PATCH = 2;

// 1.3.2
// - Fix header offset overflow in Reader when section table offset is close to file size limit
//
// 1.3.1
// - Fix security vulnerabilities
//
// 1.3.0
// - Add support for DMA symbol section for dynamic strides
//
// 1.2.6
// - Adding FP8 data types

}  // namespace

void setDefaultPerformanceMetrics(VpuPerformanceMetrics& metrics) {
    metrics.bw_base = BW_BASE;
    metrics.bw_step = BW_STEP;
    metrics.freq_base = FREQ_BASE;
    metrics.freq_step = FREQ_STEP;

    for (uint32_t i = 0; i < VPU_SCALABILITY_NUM_OF_FREQ; ++i) {
        std::copy(byBWScales.begin(), byBWScales.end(), std::begin(metrics.scalability[i]));
        std::copy(byBWTicks.begin(), byBWTicks.end(), std::begin(metrics.ticks[i]));
    }
}

HostParsedInference_4000_Base::HostParsedInference_4000_Base(elf::platform::ArchKind archKind): archKind_(archKind) {
}

std::vector<SymbolEntry> HostParsedInference_4000_Base::getSymbolTable(uint8_t) const {
    // For NPU 4000 we only have one symtab
    return symTab_;
}

std::vector<elf::Elf_Word> HostParsedInference_4000_Base::getSymbolSectionTypes() const {
    return secTypeContainers_;
}

bool HostParsedInference_4000_Base::getExplicitAllocationsEnabled() const {
    return true;
}

BufferSpecs HostParsedInference_4000_Base::getParsedInferenceBufferSpecs() {
    return BufferSpecs(DEFAULT_ALIGN, utils::alignUp(sizeof(nn_public::VpuHostParsedInference), DEFAULT_ALIGN),
                       SHF_EXECINSTR);
}

void HostParsedInference_4000_Base::setHostParsedInference(DeviceBuffer& devBuffer,
                                                           const std::vector<uint64_t>& mapped_entry,
                                                           const ResourceRequirements& resReq,
                                                           const uint64_t* perf_metrics, const elf::Version& version,
                                                           uint64_t perfSectionSize) {
    auto hpi = reinterpret_cast<nn_public::VpuHostParsedInference*>(devBuffer.cpu_addr());
    *hpi = {};

    hpi->resource_requirements_.nn_slice_count_ = resReq.nn_slice_count_;
    hpi->resource_requirements_.nn_barriers_ = resReq.nn_barriers_;
    hpi->resource_requirements_.nn_slice_length_ = resReq.nn_slice_length_;

    if (perf_metrics) {
        VPUX_ELF_THROW_UNLESS((perfSectionSize >= sizeof(VpuPerformanceMetrics)), ArgsError,
                              "Performance metrics section size is smaller than expected!");
        memcpy(static_cast<void*>(&hpi->performance_metrics_), static_cast<const void*>(perf_metrics),
               sizeof(VpuPerformanceMetrics));
    } else {
        setDefaultPerformanceMetrics(hpi->performance_metrics_);
    }

    hpi->mmi_access_ = static_cast<nn_public::VpuHostParsedInference::VpuMmiAccessMode>(version.getMIFormat());
    VPUX_ELF_THROW_WHEN(mapped_entry.empty(), ArgsError, "mapped_entry vector is empty");
    hpi->mapped_.address = mapped_entry[0];
    hpi->mapped_.count = mapped_entry.size();
}

elf::Version HostParsedInference_4000_Base::getELFLibABIVersion() const {
    return {VPUX40XX_VERSION_MAJOR, VPUX40XX_VERSION_MINOR, VPUX40XX_VERSION_PATCH};
}

elf::Version HostParsedInference_4000_Base::getStaticMIVersion() const {
    return {VPU_NNRT_40XX_API_VER_MAJOR, VPU_NNRT_40XX_API_VER_MINOR, VPU_NNRT_40XX_API_VER_PATCH};
}

uint32_t HostParsedInference_4000_Base::getArchTilesCount() const {
    return VPU_MAX_TILES;
}

HostParsedInference_4000::HostParsedInference_4000(elf::platform::ArchKind archKind)
        : HostParsedInference_4000_Base(archKind) {
    symTab_.reserve(2);
    secTypeContainers_.reserve(2);
    {
        SymbolEntry metadata;
        metadata.st_info = static_cast<unsigned char>(elf64STInfo(elf::STB_GLOBAL, elf::STT_OBJECT));
        metadata.st_other = STV_DEFAULT;
        metadata.st_shndx = 0;
        metadata.st_value = static_cast<uint64_t>(VPU_METADATA_STORAGE_ADDR);
        metadata.st_size = 0;
        metadata.st_name = 0;

        symTab_.push_back(metadata);
        secTypeContainers_.push_back(elf::VPU_SHT_CMX_METADATA);
    }

    {
        SymbolEntry cmxWorkspace;
        cmxWorkspace.st_info = static_cast<unsigned char>(elf64STInfo(elf::STB_GLOBAL, elf::STT_OBJECT));
        cmxWorkspace.st_other = STV_DEFAULT;
        cmxWorkspace.st_shndx = 0;
        cmxWorkspace.st_value = VPU_WORKSPACE_ADDR;
        cmxWorkspace.st_size = VPU_WORKSPACE_SIZE_IN_BYTES;
        cmxWorkspace.st_name = 0;

        symTab_.push_back(cmxWorkspace);
        secTypeContainers_.push_back(elf::VPU_SHT_CMX_WORKSPACE);
    }
}

}  // namespace elf
