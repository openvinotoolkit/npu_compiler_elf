//
// Copyright (C) 2023-2025 Intel Corporation
// SPDX-License-Identifier: Apache-2.0
//

//

#pragma once

#include <vpux_elf/types/data_types.hpp>
#include <vpux_elf/types/elf_header.hpp>
#include <vpux_elf/types/relocation_entry.hpp>
#include <vpux_elf/types/section_header.hpp>
#include <vpux_elf/types/symbol_entry.hpp>


namespace elf {

enum ELF_Bitness {
    Elf32 = 32,
    Elf64 = 64
};

template <ELF_Bitness B>
struct ElfTypes {
};

template <>
struct ElfTypes<ELF_Bitness::Elf32> {
    using ELFHeader = Elf32_Ehdr;
    using RelocationEntry = Elf32_Rel;
    using RelocationAEntry = Elf32_Rela;
    using SectionHeader = Elf32_Shdr;
    using SymbolEntry = Elf32_Sym;
};

template <>
struct ElfTypes<ELF_Bitness::Elf64> {
    using ELFHeader = Elf64_Ehdr;
    using RelocationEntry = Elf64_Rel;
    using RelocationAEntry = Elf64_Rela;
    using SectionHeader = Elf64_Shdr;
    using SymbolEntry = Elf64_Sym;
};

} // namespace elf
