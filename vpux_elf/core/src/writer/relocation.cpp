//
// Copyright (C) 2023-2025 Intel Corporation
// SPDX-License-Identifier: Apache-2.0
//

//

#include <vpux_elf/writer/relocation.hpp>

using namespace elf;
using namespace elf::writer;

//
// RelocationEntry
//

Elf64_Addr Relocation::getOffset() const {
    return m_relocation.r_offset;
}

void Relocation::setOffset(Elf64_Addr offset) {
    m_relocation.r_offset = offset;
}

void Relocation::setType(Elf_Word type) {
    m_relocation.r_info = elf64RInfo(elf64RSym(m_relocation.r_info), type);
}

Elf_Word Relocation::getType() const {
    return elf64RType(m_relocation.r_info);
}

void Relocation::setAddend(Elf_Sxword addend) {
    m_relocation.r_addend = addend;
}

Elf_Sxword Relocation::getAddend() const {
    return m_relocation.r_addend;
}

void Relocation::setSymbol(const Symbol* symbol) {
    m_symbol = symbol;
}

const Symbol* Relocation::getSymbol() const {
    return m_symbol;
}

void Relocation::setSpecialSymbol(Elf_Word specialSymbol) {
    m_relocation.r_info = elf64RInfo(specialSymbol, elf64RType(m_relocation.r_info));
}

Elf_Word Relocation::getSpecialSymbol() const {
    return elf64RSym(m_relocation.r_info);
}
