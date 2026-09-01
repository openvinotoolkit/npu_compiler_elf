//
// Copyright (C) 2023-2026 Intel Corporation
// SPDX-License-Identifier: Apache-2.0
//
#if defined(CONFIG_TARGET_SOC_3720) || defined(HOST_BUILD)
#include <hpi_3720.hpp>
#endif

#if defined(CONFIG_TARGET_SOC_4000) || defined(HOST_BUILD)
#include <hpi_4000.hpp>
#endif
#if defined(CONFIG_TARGET_SOC_5000) || defined(HOST_BUILD)
#include <hpi_5000.hpp>
#endif
// to be removed with E#88139: NPU5000+ share a common HPI implementation
#include <hpi_common_interface.hpp>

namespace elf {

// Default implementations will be overriden as needed by derived classes

std::unique_ptr<HostParsedInferenceCommon> HostParsedInferenceCommon::getArchSpecificHPI(
        elf::platform::ArchKind archKind) {
    VPUX_ELF_LOG(LogLevel::LOG_DEBUG, "Creating specialized HPI for arch %u", archKind);

    std::unique_ptr<HostParsedInferenceCommon> archSpecificHPI;
    switch (archKind) {
#if defined(CONFIG_TARGET_SOC_3720) || defined(HOST_BUILD)
    case elf::platform::ArchKind::NPU3720:
        archSpecificHPI = std::make_unique<HostParsedInference_3720>();
        break;
#endif

#if defined(CONFIG_TARGET_SOC_4000) || defined(HOST_BUILD)
    case elf::platform::ArchKind::NPU4000:
        archSpecificHPI = std::make_unique<HostParsedInference_4000>(archKind);
        break;
#endif
#if defined(CONFIG_TARGET_SOC_5000) || defined(HOST_BUILD)
    case elf::platform::ArchKind::NPU5010:
    case elf::platform::ArchKind::NPU5020:
        archSpecificHPI = std::make_unique<HostParsedInference_5000>(archKind);
        break;
#endif
// to be updated with E#88139: NPU5000+ share a common HPI implementation
    default:
        VPUX_ELF_THROW(RangeError, (elf::platform::stringifyArchKind(archKind) + " arch is not supported").c_str());
        break;
    }

    return archSpecificHPI;
}

std::vector<elf::Elf_Word> HostParsedInferenceCommon::getSymbolSectionTypes() const {
    return {};
}

bool HostParsedInferenceCommon::getExplicitAllocationsEnabled() const {
    return false;
}

BufferSpecs HostParsedInferenceCommon::getEntryBufferSpecs(size_t numOfEntries) {
    (void)numOfEntries;
    return {};
}

}  // namespace elf
