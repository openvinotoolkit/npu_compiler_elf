//
// Copyright (C) 2023-2025 Intel Corporation
// SPDX-License-Identifier: Apache-2.0
//

#pragma once

#include <climits>
#include <vpux_elf/types/data_types.hpp>

namespace elf {

constexpr Elf_Xword SHARABLE_BUFFER_ENABLED = uint64_t{1} << sizeof(uint32_t) * CHAR_BIT;

struct BufferSpecs {
public:
    uint64_t alignment;
    uint64_t size;
    Elf_Xword procFlags;
    BufferSpecs(): alignment(0), size(0), procFlags(0) {
    }
    BufferSpecs(uint64_t alignment, uint64_t size, uint64_t procFlags)
            : alignment(alignment), size(size), procFlags(procFlags) {
    }
    bool isSharable() const {
        return procFlags & SHARABLE_BUFFER_ENABLED;
    }
};

}  // namespace elf
