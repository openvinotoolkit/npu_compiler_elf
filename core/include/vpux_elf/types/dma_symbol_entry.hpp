//
// Copyright (C) 2025 Intel Corporation
// SPDX-License-Identifier: Apache-2.0
//

//

#pragma once

#include <cstddef>
#include <vpux_elf/types/data_types.hpp>

namespace elf {
static constexpr auto DMA_SYMBOL_MAX_TENSOR_DIMENSIONS = std::size_t{6};

struct DmaSymbolEntry {
    uint32_t ioIndex;
    uint64_t address;
    uint32_t shapes[DMA_SYMBOL_MAX_TENSOR_DIMENSIONS];
    uint32_t strides[DMA_SYMBOL_MAX_TENSOR_DIMENSIONS];
    uint32_t tileOffsets[DMA_SYMBOL_MAX_TENSOR_DIMENSIONS];
    uint32_t dmaShapes[DMA_SYMBOL_MAX_TENSOR_DIMENSIONS];
    uint32_t dmaStrides[DMA_SYMBOL_MAX_TENSOR_DIMENSIONS];
    uint32_t dmaSize;
};
}  // namespace elf
