//
// Copyright (C) 2025-2026 Intel Corporation
// SPDX-License-Identifier: Apache-2.0
//

//

#pragma once

#include <vpux_elf/types/dma_symbol_entry.hpp>
#include <vpux_elf/writer/section.hpp>

namespace elf {
namespace writer {

class DmaSymbolSection;

class DmaSymbol {
public:
    size_t getIndex() const;

    void setDmaSymbol(const DmaSymbolEntry& dmaSym);

private:
    void setIndex(size_t index);

    DmaSymbolEntry getDmaSymbol() const;

    size_t m_symbol_index = 0;
    DmaSymbolEntry m_dmaSymbol;

    friend writer::DmaSymbolSection;
};

}  // namespace writer
}  // namespace elf
