//
// Copyright (C) 2023-2025 Intel Corporation
// SPDX-License-Identifier: Apache-2.0
//

//

#pragma once

#include <vpux_elf/types/data_types.hpp>

namespace elf {

///
/// Refer to https://docs.oracle.com/cd/E23824_01/html/819-0690/chapter6-54839.html
/// for the detailed description of the values and structures below
///

struct Elf64_Rel {
    Elf64_Addr r_offset;
    Elf_Xword  r_info;
};

struct Elf64_Rela {
    Elf64_Addr r_offset;
    Elf_Xword  r_info;
    Elf_Sxword r_addend;
};

struct Elf32_Rel {
    Elf32_Addr r_offset;
    Elf_Word   r_info;
};

struct Elf32_Rela {
    Elf32_Addr r_offset;
    Elf_Word   r_info;
    Elf_Sword  r_addend;
};

//! Extract symbol index from info
Elf_Word elf64RSym(Elf_Xword info);

//! Extract relocation type from info
Elf_Word elf64RType(Elf_Xword info);

//! Pack relocation type and symbol index into info
Elf_Xword elf64RInfo(Elf_Word sym, Elf_Word type);

using RelocationEntry = Elf64_Rel;
using RelocationAEntry = Elf64_Rela;

} // namespace elf
