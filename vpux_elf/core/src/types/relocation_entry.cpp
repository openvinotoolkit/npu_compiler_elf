//
// Copyright (C) 2023-2025 Intel Corporation
// SPDX-License-Identifier: Apache-2.0
//

//

#include <vpux_elf/types/relocation_entry.hpp>

using namespace elf;

//! Extract symbol index from info
Elf_Word elf::elf64RSym(Elf_Xword info) {
    return info >> 32;
}

//! Extract relocation type from info
Elf_Word elf::elf64RType(Elf_Xword info) {
    return static_cast<Elf_Word>(info);
}

//! Pack relocation type and symbol index into info
Elf_Xword elf::elf64RInfo(Elf_Word sym, Elf_Word type) {
    return (static_cast<Elf_Xword>(sym) << 32) + (static_cast<Elf_Xword>(type));
}
