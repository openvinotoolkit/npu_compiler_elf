//
// Copyright (C) 2024-2025 Intel Corporation
// SPDX-License-Identifier: Apache-2.0
//

//

#include <vpux_elf/accessor.hpp>

elf::AccessManager::AccessManager(size_t binarySize): mSize(binarySize) {
}

size_t elf::AccessManager::getSize() const {
    return mSize;
};
