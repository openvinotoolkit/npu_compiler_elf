//
// Copyright (C) 2023-2025 Intel Corporation
// SPDX-License-Identifier: Apache-2.0
//

//

#pragma once
#include <stddef.h>

#include <vpux_elf/types/data_types.hpp>

namespace elf {
namespace utils {

bool checkELFMagic(const unsigned char* elfIdent);
size_t alignUp(size_t size, size_t alignment);
bool isPowerOfTwo(size_t value);
bool hasNPUAccess(Elf_Xword sectionFlags);
bool isNetworkIO(Elf_Xword sectionFlags);
bool hasMemoryFootprint(elf::Elf_Word sectionType);

}  // namespace utils
}  // namespace elf
