//
// Copyright (C) 2025 Intel Corporation
// SPDX-License-Identifier: Apache-2.0
//

//

#include <vpux_elf/types/vpu_extensions.hpp>
#include <vpux_elf/writer/dma_symbol_section.hpp>

#include <algorithm>

using namespace elf;
using namespace elf::writer;

DmaSymbolSection::DmaSymbolSection(const std::string& name): Section(name), sh_info(0) {
    m_header.sh_type = VPU_SHT_DMA_SYMBOLS;
    m_header.sh_entsize = sizeof(DmaSymbolEntry);
    m_fileAlignRequirement = alignof(DmaSymbolEntry);
}

DmaSymbol* DmaSymbolSection::addDmaSymbolEntry() {
    m_symbols.push_back(std::unique_ptr<DmaSymbol>(new DmaSymbol()));
    m_symbols.back()->setIndex(m_symbols.size() - 1);
    return m_symbols.back().get();
}

const std::vector<std::unique_ptr<DmaSymbol>>& DmaSymbolSection::getDmaSymbols() const {
    return m_symbols;
}

void DmaSymbolSection::finalize() {
    m_header.sh_info = sh_info;

    for (const auto& dmaSymbol : m_symbols) {
        auto dmaSymbolEntry = dmaSymbol->m_dmaSymbol;

        m_data.insert(m_data.end(), reinterpret_cast<uint8_t*>(&dmaSymbolEntry),
                      reinterpret_cast<uint8_t*>(&dmaSymbolEntry) + sizeof(dmaSymbolEntry));
    }

    // set size of the section in header, so it gets accounted when writer calculates blob size before allocation
    // this way writer can look at single place (size in header) for all sections
    // including those that don't populate m_data, e.g. EmptySection
    setSize(m_data.size());
}
