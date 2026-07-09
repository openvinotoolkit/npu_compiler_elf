//
// Copyright (C) 2025-2026 Intel Corporation
// SPDX-License-Identifier: Apache-2.0
//

#pragma once

// Wrap the NPU4 DMA hardware header in a dedicated namespace to prevent
// C++ ODR violations. The ELF library is a single unified build for all
// NPU generations, so DMA headers can be transitively
// included in the same link unit. Wrapping each in its own namespace makes
// their types (e.g. DmaDescriptor) distinct from the linker's perspective,
// satisfying the One Definition Rule.
namespace dma_npu4 {
// clang-format off
#include <api/vpu_dma_hw_40xx.h>
// clang-format on
}  // namespace dma_npu4
