//
// Copyright (C) 2023-2025 Intel Corporation
// SPDX-License-Identifier: Apache-2.0
//

// clang-format off
#include <vpux_elf/utils/utils.hpp>
#include <vpux_elf/utils/log.hpp>
#include <vpux_elf/utils/error.hpp>
#include <vpux_elf/types/section_header.hpp>
#include <vpux_elf/types/vpu_extensions.hpp>
#include <vector>
#include <hpi_3720.hpp>
#include <api/vpu_nnrt_api_37xx.h>
#include <api/vpu_cmx_info_37xx.h>
#include <api/vpu_pwrmgr_api.h>
#include <array>
#include <cstring>
// clang-format on

namespace elf {

static constexpr uint8_t N_TABS = nn_public::VPU_MAX_TILES + 1;
static constexpr size_t SPECIAL_SYMTAB_SIZE = 8;

namespace {
// Base of frequency values used in tables (in MHz).
static constexpr uint32_t FREQ_BASE = 700;
// Step of frequency for each entry in tables (in MHz).
static constexpr uint32_t FREQ_STEP = 100;
// Base of bandwidth values used in tables (in MB/s).
static constexpr uint32_t BW_BASE = 2000;
// Step of bandwidth values used in tables (in MB/s).
static constexpr uint32_t BW_STEP = 100;

// value in [0.0..1.0] range indicating scalability of network for a given DDR bandwidth.
static const std::array<float, VPU_SCALABILITY_VALUES_PER_FREQ> byBWScales({0.0F, 0.2F, 0.4F, 0.6F, 0.8F});
// expected ticks (based on FRC @37.5MHz) an inference should take for a given DDR bandwidth.
static const std::array<uint64_t, VPU_SCALABILITY_VALUES_PER_FREQ> byBWTicks({10UL, 12UL, 14UL, 16UL, 18UL});

}  // namespace

static void setDefaultPerformanceMetrics(VpuPerformanceMetrics& metrics) {
    metrics.bw_base = BW_BASE;
    metrics.bw_step = BW_STEP;
    metrics.freq_base = FREQ_BASE;
    metrics.freq_step = FREQ_STEP;

    for (uint32_t i = 0; i < VPU_SCALABILITY_NUM_OF_FREQ; ++i) {
        std::copy(byBWScales.begin(), byBWScales.end(), std::begin(metrics.scalability[i]));
        std::copy(byBWTicks.begin(), byBWTicks.end(), std::begin(metrics.ticks[i]));
    }
}

std::vector<SymbolEntry> HostParsedInference_3720::getSymbolTable(uint8_t index) const {
    SymbolEntry symTab_[N_TABS][SPECIAL_SYMTAB_SIZE];

    uint32_t inv_addr[] = {nn_public::METADATA0_STORAGE_ADDR + offsetof(nn_public::VpuMetadataMapSingle, inv_storage),
                           nn_public::METADATA1_STORAGE_ADDR + offsetof(nn_public::VpuMetadataMapSingle, inv_storage),
                           nn_public::METADATA0_STORAGE_ADDR + offsetof(nn_public::VpuMetadataMapDual0, inv_storage)};

    uint32_t akr_addr[] = {nn_public::METADATA0_STORAGE_ADDR + offsetof(nn_public::VpuMetadataMapSingle, akr_storage),
                           nn_public::METADATA1_STORAGE_ADDR + offsetof(nn_public::VpuMetadataMapSingle, akr_storage),
                           nn_public::METADATA0_STORAGE_ADDR + offsetof(nn_public::VpuMetadataMapDual0, akr_storage)};

    uint32_t dma0_addr[] = {nn_public::METADATA0_STORAGE_ADDR + offsetof(nn_public::VpuMetadataMapSingle, dma_storage),
                            nn_public::METADATA1_STORAGE_ADDR + offsetof(nn_public::VpuMetadataMapSingle, dma_storage),
                            nn_public::METADATA0_STORAGE_ADDR + offsetof(nn_public::VpuMetadataMapDual0, dma0_storage)};

    uint32_t dma1_addr[] = {nn_public::METADATA0_STORAGE_ADDR + offsetof(nn_public::VpuMetadataMapSingle, dma_storage),
                            nn_public::METADATA1_STORAGE_ADDR + offsetof(nn_public::VpuMetadataMapSingle, dma_storage),
                            nn_public::METADATA1_STORAGE_ADDR + offsetof(nn_public::VpuMetadataMapDual1, dma1_storage)};

    // different fifos for relocation to tile 1 should be used
    uint32_t fifo_base[] = {0x0, 0x1, 0x0};

    uint32_t workspace_addr[] = {nn_public::VPU_WORKSPACE_ADDR_0, nn_public::VPU_WORKSPACE_ADDR_1,
                                 nn_public::VPU_WORKSPACE_ADDR_0};

    for (int j = 0; j < N_TABS; ++j) {
        for (size_t i = 0; i < SPECIAL_SYMTAB_SIZE; ++i) {
            symTab_[j][i].st_info = static_cast<unsigned char>(elf64STInfo(elf::STB_GLOBAL, elf::STT_OBJECT));
            symTab_[j][i].st_other = STV_DEFAULT;
            symTab_[j][i].st_shndx = 0;
            symTab_[j][i].st_name = 0;
        }

        symTab_[j][VPU_NNRD_SYM_NNCXM_SLICE_BASE_ADDR].st_value = workspace_addr[j];
        symTab_[j][VPU_NNRD_SYM_NNCXM_SLICE_BASE_ADDR].st_size = nn_public::VPU_WORKSPACE_SIZE;

        symTab_[j][VPU_NNRD_SYM_RTM_IVAR].st_value = inv_addr[j];
        symTab_[j][VPU_NNRD_SYM_RTM_IVAR].st_size = nn_public::VPU_INVARIANT_COUNT;

        symTab_[j][VPU_NNRD_SYM_RTM_ACT].st_value = akr_addr[j];
        symTab_[j][VPU_NNRD_SYM_RTM_ACT].st_size = nn_public::VPU_KERNEL_RANGE_COUNT;

        symTab_[j][VPU_NNRD_SYM_RTM_DMA0].st_value = dma0_addr[j];
        symTab_[j][VPU_NNRD_SYM_RTM_DMA0].st_size = nn_public::VPU_DMA_TASK_COUNT;

        symTab_[j][VPU_NNRD_SYM_RTM_DMA1].st_value = dma1_addr[j];
        symTab_[j][VPU_NNRD_SYM_RTM_DMA1].st_size = nn_public::VPU_DMA_TASK_COUNT;

        symTab_[j][VPU_NNRD_SYM_FIFO_BASE].st_value = fifo_base[j];
        symTab_[j][VPU_NNRD_SYM_FIFO_BASE].st_size = 0;

        symTab_[j][VPU_NNRD_SYM_BARRIERS_START].st_value = fifo_base[j] * 32;
        symTab_[j][VPU_NNRD_SYM_BARRIERS_START].st_size = 0;

        symTab_[j][VPU_NNRD_SYM_HW_REGISTER].st_value = 0;
        symTab_[j][VPU_NNRD_SYM_HW_REGISTER].st_size = 0;
    }

    VPUX_ELF_THROW_UNLESS((index <= N_TABS), ArgsError, "The sym tab configuration is not supported!");

    // Return configuration
    // 0 - tile0
    // 1 - tile1
    // 2 - multi tile
    return std::vector<SymbolEntry>(symTab_[index], symTab_[index] + SPECIAL_SYMTAB_SIZE);
}

BufferSpecs HostParsedInference_3720::getParsedInferenceBufferSpecs() {
    return BufferSpecs(DEFAULT_ALIGN, utils::alignUp(sizeof(nn_public::VpuHostParsedInference), DEFAULT_ALIGN),
                       SHF_EXECINSTR);
}

BufferSpecs HostParsedInference_3720::getEntryBufferSpecs(size_t numOfEntries) {
    return BufferSpecs(DEFAULT_ALIGN,
                       numOfEntries * utils::alignUp(sizeof(nn_public::VpuMappedInference), DEFAULT_ALIGN),
                       SHF_EXECINSTR);
}

uint32_t HostParsedInference_3720::getArchTilesCount() const {
    return nn_public::VPU_MAX_TILES;
}

void HostParsedInference_3720::setHostParsedInference(DeviceBuffer& devBuffer,
                                                      const std::vector<uint64_t>& mapped_entry,
                                                      ResourceRequirements resReq, const uint64_t* perf_metrics) {
    auto hpi = reinterpret_cast<nn_public::VpuHostParsedInference*>(devBuffer.cpu_addr());
    *hpi = {};

    hpi->resource_requirements_.nn_slice_count_ = resReq.nn_slice_count_;
    hpi->resource_requirements_.nn_barriers_ = resReq.nn_barriers_;
    if (perf_metrics) {
        memcpy(static_cast<void*>(&hpi->performance_metrics_), static_cast<const void*>(perf_metrics),
               sizeof(VpuPerformanceMetrics));
    } else {
        setDefaultPerformanceMetrics(hpi->performance_metrics_);
    }

    hpi->mapped_.address = mapped_entry[0];
    hpi->mapped_.count = mapped_entry.size();
}

elf::Version HostParsedInference_3720::getELFLibABIVersion() const {
    return {VERSION_MAJOR, VERSION_MINOR, VERSION_PATCH};
}

elf::Version HostParsedInference_3720::getStaticMIVersion() const {
    return {VPU_NNRT_37XX_API_VER_MAJOR, VPU_NNRT_37XX_API_VER_MINOR, VPU_NNRT_37XX_API_VER_PATCH};
}

}  // namespace elf
