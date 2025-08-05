//
// Copyright (C) 2023-2025 Intel Corporation
// SPDX-License-Identifier: Apache-2.0
//

//

#include <vpux_elf/writer/relocation_section.hpp>

using namespace elf;
using namespace elf::writer;

RelocationSection::RelocationSection(const std::string& name) : Section(name) {
    m_header.sh_type = SHT_RELA;
    m_header.sh_entsize = sizeof(RelocationAEntry);
    m_fileAlignRequirement = alignof(RelocationAEntry);
}

const SymbolSection* RelocationSection::getSymbolTable() const {
    return m_symTab;
}

void RelocationSection::setSymbolTable(const SymbolSection* symTab) {
    m_symTab = symTab;
}

Elf_Word RelocationSection::getSpecialSymbolTable() const {
    return m_header.sh_link;
}

void RelocationSection::setSpecialSymbolTable(Elf_Word specialSymbolTable) {
    m_header.sh_link = specialSymbolTable;
}

const Section* RelocationSection::getSectionToPatch() const {
    return m_sectionToPatch;
}

void RelocationSection::setSectionToPatch(const Section* sectionToPatch) {
    m_sectionToPatch = sectionToPatch;
}

Relocation* RelocationSection::addRelocationEntry() {
    m_relocations.push_back(std::unique_ptr<Relocation>(new Relocation));
    return m_relocations.back().get();
}

const std::vector<std::unique_ptr<Relocation>>& RelocationSection::getRelocations() const {
    return m_relocations;
}

void RelocationSection::finalize() {
    m_header.sh_info = static_cast<Elf_Word>(m_sectionToPatch->getIndex());
    maskFlags(SHF_INFO_LINK);
    if (m_symTab) {
        m_header.sh_link = static_cast<Elf_Word>(m_symTab->getIndex());
    }

    for (const auto& relocation : m_relocations) {
        auto relocationEntry = relocation->m_relocation;
        if (relocation->getSymbol()) {
            relocationEntry.r_info = elf64RInfo(static_cast<Elf_Word>(relocation->getSymbol()->getIndex()), relocation->getType());
        }

        m_data.insert(m_data.end(), reinterpret_cast<uint8_t*>(&relocationEntry),
                      reinterpret_cast<uint8_t*>(&relocationEntry) + sizeof(relocationEntry));
    }

    // set size of the section in header, so it gets accounted when writer calculates blob size before allocation
    // this way writer can look at single place (size in header) for all sections
    // including those that don't populate m_data, e.g. EmptySection
    setSize(m_data.size());
}
