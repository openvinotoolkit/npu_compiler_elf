//
// Copyright (C) 2023-2025 Intel Corporation
// SPDX-License-Identifier: Apache-2.0
//

#pragma once

#include <hpi_common_interface.hpp>
#include <vpux_headers/buffer_manager.hpp>
#include <vpux_headers/device_buffer.hpp>
#include <vpux_headers/platform.hpp>

namespace elf {
class HostParsedInference_4000_Base : public HostParsedInferenceCommon {
public:
    explicit HostParsedInference_4000_Base(elf::platform::ArchKind archKind);
    std::vector<SymbolEntry> getSymbolTable(uint8_t index) const override;
    std::vector<elf::Elf_Word> getSymbolSectionTypes() const override;
    bool getExplicitAllocationsEnabled() const override;
    BufferSpecs getParsedInferenceBufferSpecs() override;
    void setHostParsedInference(DeviceBuffer& devBuffer, const std::vector<uint64_t>& mapped_entry,
                                ResourceRequirements resReq, const uint64_t* perf_metrics) override;
    elf::Version getELFLibABIVersion() const override;
    elf::Version getStaticMIVersion() const override;
    uint32_t getArchTilesCount() const override;

protected:
    HostParsedInference_4000_Base() = default;

    std::vector<SymbolEntry> symTab_ = {};
    std::vector<elf::Elf_Word> secTypeContainers_ = {};
    elf::platform::ArchKind archKind_ = {};
};

class HostParsedInference_4000 : public HostParsedInference_4000_Base {
public:
    explicit HostParsedInference_4000(elf::platform::ArchKind archKind);
};

}  // namespace elf
