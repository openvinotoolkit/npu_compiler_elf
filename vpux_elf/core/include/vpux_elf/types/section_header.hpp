//
// Copyright (C) 2023-2025 Intel Corporation
// SPDX-License-Identifier: Apache-2.0
//

//

#pragma once

#include <vpux_elf/types/data_types.hpp>

namespace elf {

///
/// Refer to https://docs.oracle.com/cd/E19455-01/806-3773/elf-2/index.html
/// for the detailed description of the values and structures below
///

//! Section types
constexpr Elf_Word SHT_NULL          = 0;
constexpr Elf_Word SHT_PROGBITS      = 1;
constexpr Elf_Word SHT_SYMTAB        = 2;
constexpr Elf_Word SHT_STRTAB        = 3;
constexpr Elf_Word SHT_RELA          = 4;
constexpr Elf_Word SHT_HASH          = 5;
constexpr Elf_Word SHT_DYNAMIC       = 6;
constexpr Elf_Word SHT_NOTE          = 7;
constexpr Elf_Word SHT_NOBITS        = 8;
constexpr Elf_Word SHT_REL           = 9;
constexpr Elf_Word SHT_SHLIB         = 10;
constexpr Elf_Word SHT_DYNSYM        = 11;
constexpr Elf_Word SHT_LOPROC        = 0x70000000;
constexpr Elf_Word SHT_HIPROC        = 0x7fffffff;
constexpr Elf_Word SHT_LOUSER        = 0x80000000;
constexpr Elf_Word SHT_HIUSER        = 0xffffffff;

//! Section flags
constexpr Elf_Xword SHF_NONE            = 0x0;
// As defined by the ELF format, the SHF_WRITE flag is set for a section that contains data that should be
// writable during process execution. For NPU, this means the flag is set by the compiler for a section that
// is known to be modified by any of the NPU cores during inference execution. This also means it is not set
// for a section that is modified by the host at any point before inference execution (e.g. when applying
// relocations during loading process).
constexpr Elf_Xword SHF_WRITE           = 0x1;
constexpr Elf_Xword SHF_ALLOC           = 0x2;
constexpr Elf_Xword SHF_EXECINSTR       = 0x4;
constexpr Elf_Xword SHF_INFO_LINK       = 0x40;
constexpr Elf_Xword SHF_MASKOS          = 0xff00000;
constexpr Elf_Xword SHF_MASKPROC        = 0xf0000000;

//! Special section indexes
constexpr Elf_Word SHN_UNDEF     = 0;
constexpr Elf_Word SHN_LORESERVE = 0xff00;
constexpr Elf_Word SHN_LOPROC    = 0xff00;
constexpr Elf_Word SHN_HIPROC    = 0xff1f;
constexpr Elf_Word SHN_LOOS      = 0xff20;
constexpr Elf_Word SHN_HIOS      = 0xff3f;
constexpr Elf_Word SHN_ABS       = 0xfff1;
constexpr Elf_Word SHN_COMMON    = 0xfff2;
constexpr Elf_Word SHN_XINDEX    = 0xffff;
constexpr Elf_Word SHN_HIRESERVE = 0xffff;

struct Elf64_Shdr {
    Elf_Word   sh_name;
    Elf_Word   sh_type;
    Elf_Xword  sh_flags;
    Elf64_Addr sh_addr;
    Elf64_Off  sh_offset;
    Elf_Xword  sh_size;
    Elf_Word   sh_link;
    Elf_Word   sh_info;
    Elf_Xword  sh_addralign;
    Elf_Xword  sh_entsize;
};

struct Elf32_Shdr {
    Elf_Word   sh_name;
    Elf_Word   sh_type;
    Elf_Word   sh_flags;
    Elf32_Addr sh_addr;
    Elf32_Off  sh_offset;
    Elf_Word   sh_size;
    Elf_Word   sh_link;
    Elf_Word   sh_info;
    Elf_Word   sh_addralign;
    Elf_Word   sh_entsize;
};

using SectionHeader = Elf64_Shdr;


namespace elf_note {
// Standard GNU Format for SHT_NOTE - ABI Version sections
struct VersionNote {
    uint32_t n_namesz;      // size of n_name field
    uint32_t n_descz;       // size of n_desc field
    uint32_t n_type;
    uint8_t n_name[4];
    uint32_t n_desc[4];
};

// Standard values for n_type field of NOTE section
constexpr uint32_t NT_GNU_ABI_TAG = 1;
constexpr uint32_t NT_GNU_HWCAP = 2;
constexpr uint32_t NT_GNU_BUILD_ID = 3;
constexpr uint32_t NT_GNU_GOLD_VERSION = 4;
constexpr uint32_t NT_GNU_PROPERTY_TYPE_0 = 5;

// Standard values for n_desc[0] field of ABI Version NOTE section
constexpr uint8_t ELF_NOTE_OS_LINUX = 0;
constexpr uint8_t ELF_NOTE_OS_GNU = 1;
constexpr uint8_t ELF_NOTE_OS_SOLARIS2 = 2;
constexpr uint8_t ELF_NOTE_OS_FREEBSD = 3;

} // namespace elf_note
} // namespace elf
