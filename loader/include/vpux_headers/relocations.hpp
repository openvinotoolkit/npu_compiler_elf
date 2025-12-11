//
// Copyright (C) 2025 Intel Corporation
// SPDX-License-Identifier: Apache-2.0
//

//

#pragma once

#include <vpux_elf/types/dma_symbol_entry.hpp>

namespace elf {
namespace relocations {

void reduceDmaDims(const uint32_t (&dmaShapes)[DMA_SYMBOL_MAX_TENSOR_DIMENSIONS],
                   const uint32_t (&dmaStrides)[DMA_SYMBOL_MAX_TENSOR_DIMENSIONS], const uint32_t dmaSize,
                   std::array<uint32_t, DMA_SYMBOL_MAX_TENSOR_DIMENSIONS>& reducedDmaShapes,
                   std::array<uint32_t, DMA_SYMBOL_MAX_TENSOR_DIMENSIONS>& reducedDmaStrides);

uint64_t calculateDmaAddress(uint64_t address, const uint32_t (&tileOffsets)[DMA_SYMBOL_MAX_TENSOR_DIMENSIONS],
                             const uint32_t (&strides)[DMA_SYMBOL_MAX_TENSOR_DIMENSIONS], const uint32_t dmaSize);

void dmaTaskInputRelocation(void* targetAddr, const DmaSymbolEntry& sym, const Elf_Sxword);
void dmaTaskOutputRelocation(void* targetAddr, const DmaSymbolEntry& sym, const Elf_Sxword);

}  // namespace relocations
}  // namespace elf
