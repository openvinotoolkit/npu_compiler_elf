//
// Copyright (C) 2025-2026 Intel Corporation
// SPDX-License-Identifier: Apache-2.0
//

//

#pragma once

#include <cstddef>
#include <vpux_elf/types/data_types.hpp>
#include <vpux_elf/utils/struct_alignment.hpp>

namespace elf {

#pragma pack(push, 1)

static constexpr auto DMA_SYMBOL_MAX_TENSOR_DIMENSIONS = std::size_t{6};

struct VPUX_ALIGNED_STRUCT(8) DmaSymbolEntry {
    uint32_t ioIndex;
    uint8_t reserved[4];  // padding to align the next member to 8 bytes
    uint64_t address;
    uint32_t shapes[DMA_SYMBOL_MAX_TENSOR_DIMENSIONS];
    uint32_t strides[DMA_SYMBOL_MAX_TENSOR_DIMENSIONS];
    uint32_t tileOffsets[DMA_SYMBOL_MAX_TENSOR_DIMENSIONS];
    uint32_t dmaShapes[DMA_SYMBOL_MAX_TENSOR_DIMENSIONS];
    uint32_t dmaStrides[DMA_SYMBOL_MAX_TENSOR_DIMENSIONS];
    uint32_t dmaSize;      // Can be interpreted as bit or byte size depending on relocation type.
    uint8_t reserved2[4];  // padding to make the struct size a multiple of 8 bytes
};

static_assert(sizeof(DmaSymbolEntry) == 144, "DmaSymbolEntry size is not 144 bytes");
static_assert(alignof(DmaSymbolEntry) == 8, "DmaSymbolEntry alignment is not 8 bytes");
static_assert(offsetof(DmaSymbolEntry, ioIndex) % 4 == 0, "Alignment error");
static_assert(offsetof(DmaSymbolEntry, address) % 8 == 0, "Alignment error");
static_assert(offsetof(DmaSymbolEntry, shapes) % 4 == 0, "Alignment error");
static_assert(offsetof(DmaSymbolEntry, strides) % 4 == 0, "Alignment error");
static_assert(offsetof(DmaSymbolEntry, tileOffsets) % 4 == 0, "Alignment error");
static_assert(offsetof(DmaSymbolEntry, dmaShapes) % 4 == 0, "Alignment error");
static_assert(offsetof(DmaSymbolEntry, dmaStrides) % 4 == 0, "Alignment error");
static_assert(offsetof(DmaSymbolEntry, dmaSize) % 4 == 0, "Alignment error");

#pragma pack(pop)
}  // namespace elf
