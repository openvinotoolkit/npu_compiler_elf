//
// Copyright (C) 2025-2026 Intel Corporation
// SPDX-License-Identifier: Apache-2.0
//

//

#include <array>
#include <nnrt_headers_40xx.hpp>
#include <vpux_headers/relocations.hpp>

#include "vpux_elf/utils/error.hpp"

namespace elf::relocations {

using namespace elf;

void reduceDmaDims(const uint32_t (&dmaShapes)[DMA_SYMBOL_MAX_TENSOR_DIMENSIONS],
                   const uint32_t (&dmaStrides)[DMA_SYMBOL_MAX_TENSOR_DIMENSIONS], const uint32_t dmaSize,
                   std::array<uint32_t, DMA_SYMBOL_MAX_TENSOR_DIMENSIONS>& reducedDmaShapes,
                   std::array<uint32_t, DMA_SYMBOL_MAX_TENSOR_DIMENSIONS>& reducedDmaStrides) {
    auto continousSize = dmaSize;
    bool nonContinousDimFound = false;
    size_t reducedDim = 0;
    // Aggregate total compact size until first non-compact dimension is found.
    // After non-compact dimension is found simply copy remaining dimensions and strides
    // into arrays that hold reduced dims. We don't need to reduce remaining dimensions
    // since from DMA engine perspective it only matters that innermost dimension
    // is as large as possible.
    for (size_t dim = 0; dim < DMA_SYMBOL_MAX_TENSOR_DIMENSIONS && reducedDim < DMA_SYMBOL_MAX_TENSOR_DIMENSIONS;
         dim++) {
        auto currentSize = dmaShapes[dim];
        auto currentStride = dmaStrides[dim];
        if (nonContinousDimFound) {
            reducedDmaStrides[reducedDim] = currentStride * dmaSize;
            reducedDmaShapes[reducedDim] = currentSize;
            reducedDim++;
            continue;
        }
        if (currentStride * dmaSize != continousSize) {
            reducedDmaStrides[reducedDim] = dmaSize;
            reducedDmaShapes[reducedDim] = continousSize;
            reducedDim++;
            reducedDmaStrides[reducedDim] = currentStride * dmaSize;
            reducedDmaShapes[reducedDim] = currentSize;
            reducedDim++;
            nonContinousDimFound = true;
            continue;
        }
        continousSize *= currentSize;
    }

    if (reducedDim == 0) {
        reducedDmaShapes[0] = continousSize;
        reducedDmaStrides[0] = dmaSize;
    }
}

uint64_t calculateDmaAddress(uint64_t address, const uint32_t (&tileOffsets)[DMA_SYMBOL_MAX_TENSOR_DIMENSIONS],
                             const uint32_t (&strides)[DMA_SYMBOL_MAX_TENSOR_DIMENSIONS], const uint32_t dmaSize) {
    for (size_t idx = 0; idx < DMA_SYMBOL_MAX_TENSOR_DIMENSIONS; idx++) {
        address += static_cast<uint64_t>(tileOffsets[idx]) * strides[idx] * dmaSize;
    }

    return address;
}

void dmaTaskInputRelocation(void* targetAddr, const DmaSymbolEntry& sym, const Elf_Sxword) {
    auto dmaTask = reinterpret_cast<elf::DmaDescriptor*>(targetAddr);

    std::array<uint32_t, DMA_SYMBOL_MAX_TENSOR_DIMENSIONS> reducedDmaShapes{1, 1, 1, 1, 1, 1};
    std::array<uint32_t, DMA_SYMBOL_MAX_TENSOR_DIMENSIONS> reducedDmaStrides{0, 0, 0, 0, 0, 0};

    reduceDmaDims(sym.dmaShapes, sym.dmaStrides, sym.dmaSize, reducedDmaShapes, reducedDmaStrides);
    auto startAddress = calculateDmaAddress(sym.address, sym.tileOffsets, sym.strides, sym.dmaSize);

    dmaTask->width.src = reducedDmaShapes[0];
    dmaTask->dim_size_1.src = reducedDmaShapes[1] != 0 ? reducedDmaShapes[1] - 1 : 0;
    dmaTask->dim_size_2.src = reducedDmaShapes[2] != 0 ? reducedDmaShapes[2] - 1 : 0;
    dmaTask->dim_size_src_3 = reducedDmaShapes[3] != 0 ? reducedDmaShapes[3] - 1 : 0;
    dmaTask->dim_size_src_4 = reducedDmaShapes[4] != 0 ? reducedDmaShapes[4] - 1 : 0;
    dmaTask->dim_size_src_5 = reducedDmaShapes[5] != 0 ? reducedDmaShapes[5] - 1 : 0;
    dmaTask->stride_src_1 = reducedDmaStrides[1];
    dmaTask->stride_src_2 = reducedDmaStrides[2];
    dmaTask->stride_src_3 = reducedDmaStrides[3];
    dmaTask->stride_src_4 = reducedDmaStrides[4];
    dmaTask->stride_src_5 = reducedDmaStrides[5];
    dmaTask->src_offsetof = startAddress;
}

void dmaTaskOutputRelocation(void* targetAddr, const DmaSymbolEntry& sym, const Elf_Sxword) {
    auto dmaTask = reinterpret_cast<elf::DmaDescriptor*>(targetAddr);

    std::array<uint32_t, DMA_SYMBOL_MAX_TENSOR_DIMENSIONS> reducedDmaShapes{1, 1, 1, 1, 1, 1};
    std::array<uint32_t, DMA_SYMBOL_MAX_TENSOR_DIMENSIONS> reducedDmaStrides{0, 0, 0, 0, 0, 0};

    reduceDmaDims(sym.dmaShapes, sym.dmaStrides, sym.dmaSize, reducedDmaShapes, reducedDmaStrides);
    auto startAddress = calculateDmaAddress(sym.address, sym.tileOffsets, sym.strides, sym.dmaSize);

    dmaTask->width.dst = reducedDmaShapes[0];
    dmaTask->dim_size_1.dst = reducedDmaShapes[1] != 0 ? reducedDmaShapes[1] - 1 : 0;
    dmaTask->dim_size_2.dst = reducedDmaShapes[2] != 0 ? reducedDmaShapes[2] - 1 : 0;
    dmaTask->dim_size_dst_3 = reducedDmaShapes[3] != 0 ? reducedDmaShapes[3] - 1 : 0;
    dmaTask->dim_size_dst_4 = reducedDmaShapes[4] != 0 ? reducedDmaShapes[4] - 1 : 0;
    dmaTask->dim_size_dst_5 = reducedDmaShapes[5] != 0 ? reducedDmaShapes[5] - 1 : 0;
    dmaTask->stride_dst_1 = reducedDmaStrides[1];
    dmaTask->stride_dst_2 = reducedDmaStrides[2];
    dmaTask->stride_dst_3 = reducedDmaStrides[3];
    dmaTask->stride_dst_4 = reducedDmaStrides[4];
    dmaTask->stride_dst_5 = reducedDmaStrides[5];
    dmaTask->dst_offsetof = startAddress;
}

uint64_t calculateDmaBitAddress(uint64_t address, const uint32_t (&tileOffsets)[DMA_SYMBOL_MAX_TENSOR_DIMENSIONS],
                                const uint32_t (&strides)[DMA_SYMBOL_MAX_TENSOR_DIMENSIONS], const uint32_t dmaSize) {
    uint64_t bitOffset = 0;
    for (size_t idx = 0; idx < DMA_SYMBOL_MAX_TENSOR_DIMENSIONS; idx++) {
        bitOffset += static_cast<uint64_t>(tileOffsets[idx]) * strides[idx] * dmaSize;
    }

    VPUX_ELF_THROW_WHEN(bitOffset % 8, RelocError, "DMA relocation offset is not byte aligned");

    return address + (bitOffset / 8);
}

void dmaTaskInputBitRelocation(void* targetAddr, const DmaSymbolEntry& sym, const Elf_Sxword) {
    auto dmaTask = reinterpret_cast<elf::DmaDescriptor*>(targetAddr);

    std::array<uint32_t, DMA_SYMBOL_MAX_TENSOR_DIMENSIONS> reducedDmaShapes{1, 1, 1, 1, 1, 1};
    std::array<uint32_t, DMA_SYMBOL_MAX_TENSOR_DIMENSIONS> reducedDmaStrides{0, 0, 0, 0, 0, 0};

    reduceDmaDims(sym.dmaShapes, sym.dmaStrides, sym.dmaSize, reducedDmaShapes, reducedDmaStrides);
    auto startAddress = calculateDmaBitAddress(sym.address, sym.tileOffsets, sym.strides, sym.dmaSize);

    VPUX_ELF_THROW_WHEN(reducedDmaShapes[0] % 8, RelocError, "DMA relocation width is not byte aligned");
    for (size_t strideIdx = 1; strideIdx < reducedDmaStrides.size(); strideIdx++) {
        VPUX_ELF_THROW_WHEN(reducedDmaStrides[strideIdx] % 8, RelocError, "DMA relocation stride is not byte aligned");
    }

    dmaTask->width.src = reducedDmaShapes[0] / 8;
    dmaTask->dim_size_1.src = reducedDmaShapes[1] != 0 ? reducedDmaShapes[1] - 1 : 0;
    dmaTask->dim_size_2.src = reducedDmaShapes[2] != 0 ? reducedDmaShapes[2] - 1 : 0;
    dmaTask->dim_size_src_3 = reducedDmaShapes[3] != 0 ? reducedDmaShapes[3] - 1 : 0;
    dmaTask->dim_size_src_4 = reducedDmaShapes[4] != 0 ? reducedDmaShapes[4] - 1 : 0;
    dmaTask->dim_size_src_5 = reducedDmaShapes[5] != 0 ? reducedDmaShapes[5] - 1 : 0;
    dmaTask->stride_src_1 = reducedDmaStrides[1] / 8;
    dmaTask->stride_src_2 = reducedDmaStrides[2] / 8;
    dmaTask->stride_src_3 = reducedDmaStrides[3] / 8;
    dmaTask->stride_src_4 = reducedDmaStrides[4] / 8;
    dmaTask->stride_src_5 = reducedDmaStrides[5] / 8;
    dmaTask->src_offsetof = startAddress;
}

void dmaTaskOutputBitRelocation(void* targetAddr, const DmaSymbolEntry& sym, const Elf_Sxword) {
    auto dmaTask = reinterpret_cast<elf::DmaDescriptor*>(targetAddr);

    std::array<uint32_t, DMA_SYMBOL_MAX_TENSOR_DIMENSIONS> reducedDmaShapes{1, 1, 1, 1, 1, 1};
    std::array<uint32_t, DMA_SYMBOL_MAX_TENSOR_DIMENSIONS> reducedDmaStrides{0, 0, 0, 0, 0, 0};

    reduceDmaDims(sym.dmaShapes, sym.dmaStrides, sym.dmaSize, reducedDmaShapes, reducedDmaStrides);
    auto startAddress = calculateDmaBitAddress(sym.address, sym.tileOffsets, sym.strides, sym.dmaSize);

    VPUX_ELF_THROW_WHEN(reducedDmaShapes[0] % 8, RelocError, "DMA relocation width is not byte aligned");
    for (size_t strideIdx = 1; strideIdx < reducedDmaStrides.size(); strideIdx++) {
        VPUX_ELF_THROW_WHEN(reducedDmaStrides[strideIdx] % 8, RelocError, "DMA relocation stride is not byte aligned");
    }

    dmaTask->width.dst = reducedDmaShapes[0] / 8;
    dmaTask->dim_size_1.dst = reducedDmaShapes[1] != 0 ? reducedDmaShapes[1] - 1 : 0;
    dmaTask->dim_size_2.dst = reducedDmaShapes[2] != 0 ? reducedDmaShapes[2] - 1 : 0;
    dmaTask->dim_size_dst_3 = reducedDmaShapes[3] != 0 ? reducedDmaShapes[3] - 1 : 0;
    dmaTask->dim_size_dst_4 = reducedDmaShapes[4] != 0 ? reducedDmaShapes[4] - 1 : 0;
    dmaTask->dim_size_dst_5 = reducedDmaShapes[5] != 0 ? reducedDmaShapes[5] - 1 : 0;
    dmaTask->stride_dst_1 = reducedDmaStrides[1] / 8;
    dmaTask->stride_dst_2 = reducedDmaStrides[2] / 8;
    dmaTask->stride_dst_3 = reducedDmaStrides[3] / 8;
    dmaTask->stride_dst_4 = reducedDmaStrides[4] / 8;
    dmaTask->stride_dst_5 = reducedDmaStrides[5] / 8;
    dmaTask->dst_offsetof = startAddress;
}

}  // namespace elf::relocations
