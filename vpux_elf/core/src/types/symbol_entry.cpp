//
// Copyright (C) 2023-2025 Intel Corporation
// SPDX-License-Identifier: Apache-2.0
//

//

#include <vpux_elf/types/symbol_entry.hpp>

using namespace elf;

//! Extract symbol binding attributes from info
Elf_Xword elf::elf64STBind(Elf_Xword info) {
    return info >> 4;
}

//! Extract symbol type from info
Elf_Xword elf::elf64STType(Elf_Xword info) {
    return info & 0xf;
}

//! Pack symbol binding attributes and symbol type into info
Elf_Xword elf::elf64STInfo(Elf_Xword bind, Elf_Xword type) {
    return (bind << 4) + (type & 0xf);
}

//! Performs a transformation over visibility to zero out all bits that have no defined meaning
uint8_t elf::elf64STVisibility(uint8_t visibility) {
    return visibility & 0x3;
}
