//
// Copyright (C) 2025 Intel Corporation
// SPDX-License-Identifier: Apache-2.0
//

//

#include <vpux_elf/writer/dma_symbol.hpp>

using namespace elf;
using namespace elf::writer;

void DmaSymbol::setIndex(size_t index) {
    m_symbol_index = index;
}

size_t DmaSymbol::getIndex() {
    return m_symbol_index;
}

void DmaSymbol::setDmaSymbol(DmaSymbolEntry& dmaSym) {
    m_dmaSymbol = dmaSym;
}

DmaSymbolEntry DmaSymbol::getDmaSymbol() {
    return m_dmaSymbol;
}
