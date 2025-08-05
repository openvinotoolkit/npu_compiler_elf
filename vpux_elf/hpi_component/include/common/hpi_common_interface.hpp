//
// Copyright (C) 2023-2025 Intel Corporation
// SPDX-License-Identifier: Apache-2.0
//

#pragma once

#include <array>
#include <vector>
#include <vpux_elf/types/elf_structs.hpp>
#include <vpux_elf/types/symbol_entry.hpp>
#include <vpux_elf/utils/version.hpp>
#include <vpux_headers/buffer_manager.hpp>
#include <vpux_headers/device_buffer.hpp>
#include <vpux_headers/metadata.hpp>

namespace elf {

constexpr auto DEFAULT_ALIGN = 64;

class HostParsedInferenceCommon {
public:
    virtual ~HostParsedInferenceCommon() = default;
    virtual std::vector<SymbolEntry> getSymbolTable(uint8_t index) const = 0;
    virtual std::vector<elf::Elf_Word> getSymbolSectionTypes() const;

    /**
     * Get buffer specs of host parsed inference for specific architecture
     * @return BufferSpecs of the host parsed inference.
     *
     */
    virtual BufferSpecs getParsedInferenceBufferSpecs() = 0;
    /**
     * Get buffer specs of mapped inference (entry) for specific architecture
     * @return BufferSpecs of the mapped inference
     */
    virtual BufferSpecs getEntryBufferSpecs(size_t);
    /**
     * Set the entry (mapped inference) and the resource requirements
     * for the pre-allocated DeviceBuffer that contains the current architecture
     * structure in memory
     *
     * @param devBuffer reference to the device buffer in order to reinterpret
     * it to the current architecture specific HPI strucutre
     *
     * @param mapped_entry uint64_t that holds the address of the mapped entry, returned by the loader
     * getEntry method
     *
     * @param resReq resource requirements to be added to the host parsed inference
     */
    virtual void setHostParsedInference(DeviceBuffer& devBuffer, const std::vector<uint64_t>& mapped_entry,
                                        ResourceRequirements resReq, const uint64_t* perf_metrics) = 0;
    /**
     * Get ABI Version of current HPI/Loader
     */
    virtual elf::Version getELFLibABIVersion() const = 0;

    /**
     * Get Mapped inference version
     */
    virtual elf::Version getStaticMIVersion() const = 0;

    /**
     * Get number of tiles
     */
    virtual uint32_t getArchTilesCount() const = 0;
};
}  // namespace elf
