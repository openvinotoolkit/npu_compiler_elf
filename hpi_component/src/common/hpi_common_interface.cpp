//
// Copyright (C) 2023-2025 Intel Corporation
// SPDX-License-Identifier: Apache-2.0
//

#include <hpi_common_interface.hpp>

namespace elf {

// Default implementations will be overriden as needed by derived classes

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
