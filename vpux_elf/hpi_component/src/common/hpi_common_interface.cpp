//
// Copyright (C) 2023-2025 Intel Corporation
// SPDX-License-Identifier: Apache-2.0
//

#include <hpi_common_interface.hpp>

namespace elf {

std::vector<elf::Elf_Word> HostParsedInferenceCommon::getSymbolSectionTypes() const {
    return {};
}

BufferSpecs HostParsedInferenceCommon::getEntryBufferSpecs(size_t numOfEntries) {
    (void)numOfEntries;
    return {};
}

}  // namespace elf
