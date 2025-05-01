
//
// Copyright (C) 2023 Intel Corporation
// SPDX-License-Identifier: Apache 2.0
//

// clang-format off
#include <vpux_elf/utils/utils.hpp>
#include <vpux_elf/utils/log.hpp>
#include <vpux_elf/utils/error.hpp>
#include <vpux_elf/types/section_header.hpp>
#include <vpux_elf/types/vpu_extensions.hpp>
#include <vector>
#include <hpi_4000.hpp>
#include <api/vpu_nnrt_api_40xx.h>
#include <api/vpu_cmx_info_40xx.h>
#include <api/vpu_pwrmgr_api.h>
#include <string>
#include <vector>
#include <array>
#include <cstring>
// clang-format on

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
constexpr uint32_t VPUX40XX_VERSION_MINOR = 2;
constexpr uint32_t VPUX40XX_VERSION_PATCH = 5;



} // namespace

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

HostParsedInference_4000::HostParsedInference_4000(elf::platform::ArchKind archKind) :  archKind_(archKind) {
    symTab_.reserve(2);
    secTypeContainers_.reserve(2);
    {
        const auto metadataStart =
                nn_public::align_storage(alignof(nn_public::VpuDPUInvariant), nn_public::VPU_METADATA_STORAGE_ADDR);

        SymbolEntry metadata;
        metadata.st_info = static_cast<unsigned char>(elf64STInfo(elf::STB_GLOBAL, elf::STT_OBJECT));
        metadata.st_other = STV_DEFAULT;
        metadata.st_shndx = 0;
        metadata.st_value = static_cast<uint64_t>(metadataStart);
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
        cmxWorkspace.st_value = nn_public::VPU_WORKSPACE_ADDR;
        cmxWorkspace.st_size = nn_public::VPU_WORKSPACE_SIZE;
        cmxWorkspace.st_name = 0;

        symTab_.push_back(cmxWorkspace);
        secTypeContainers_.push_back(elf::VPU_SHT_CMX_WORKSPACE);
    }
}

std::vector<SymbolEntry> HostParsedInference_4000::getSymbolTable(uint8_t) const {
    // For NPU 4000 we only have one symtab
    return symTab_;
}

std::vector<elf::Elf_Word> HostParsedInference_4000::getSymbolSectionTypes() const {
    return secTypeContainers_;
}

BufferSpecs HostParsedInference_4000::getParsedInferenceBufferSpecs() {
    return BufferSpecs(DEFAULT_ALIGN, utils::alignUp(sizeof(nn_public::VpuHostParsedInference), DEFAULT_ALIGN),
                       SHF_EXECINSTR);
}

uint32_t HostParsedInference_4000::getArchTilesCount() const {
    return nn_public::VPU_MAX_TILES;
}

void HostParsedInference_4000::setHostParsedInference(DeviceBuffer& devBuffer,
                                                      const std::vector<uint64_t>& mapped_entry,
                                                      ResourceRequirements resReq, const uint64_t* perf_metrics) {
    auto hpi = reinterpret_cast<nn_public::VpuHostParsedInference*>(devBuffer.cpu_addr());
    *hpi = {};

    hpi->resource_requirements_.nn_slice_count_ = resReq.nn_slice_count_;
    hpi->resource_requirements_.nn_barriers_ = resReq.nn_barriers_;
    hpi->resource_requirements_.nn_slice_length_ = resReq.nn_slice_length_;

    if (perf_metrics) {
        memcpy(static_cast<void*>(&hpi->performance_metrics_), static_cast<const void*>(perf_metrics),
               sizeof(VpuPerformanceMetrics));
    } else {
        setDefaultPerformanceMetrics(hpi->performance_metrics_);
    }

    hpi->mapped_.address = mapped_entry[0];
    hpi->mapped_.count = mapped_entry.size();
}

elf::Version HostParsedInference_4000::getELFLibABIVersion() const {
    switch (archKind_) {
        case elf::platform::ArchKind::VPUX40XX:
            return {VPUX40XX_VERSION_MAJOR, VPUX40XX_VERSION_MINOR, VPUX40XX_VERSION_PATCH};
        default:
            break;
    }
    VPUX_ELF_THROW(RangeError, (elf::platform::stringifyArchKind(archKind_) + " arch is not supported").c_str());
    return {0, 0, 0};
}

elf::Version HostParsedInference_4000::getStaticMIVersion() const {
    return {VPU_NNRT_40XX_API_VER_MAJOR, VPU_NNRT_40XX_API_VER_MINOR, VPU_NNRT_40XX_API_VER_PATCH};
}

}  // namespace elf
