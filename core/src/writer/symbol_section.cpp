//
// Copyright (C) 2023-2025 Intel Corporation
// SPDX-License-Identifier: Apache-2.0
//

//

#include <vpux_elf/writer/symbol_section.hpp>

#include <algorithm>

using namespace elf;
using namespace elf::writer;

SymbolSection::SymbolSection(const std::string& name, StringSection* namesSection) : Section(name), m_namesSection(namesSection), sh_info(0) {
    m_header.sh_type = SHT_SYMTAB;
    m_header.sh_entsize = sizeof(SymbolEntry);
    m_fileAlignRequirement = alignof(SymbolEntry);

    m_symbols.push_back(std::unique_ptr<Symbol>(new Symbol));
    m_symbols.back()->setIndex(m_symbols.size() - 1);
}

Symbol* SymbolSection::addSymbolEntry(const std::string& name) {
    m_symbols.push_back(std::unique_ptr<Symbol>(new Symbol(name)));
    m_symbols.back()->setIndex(m_symbols.size() - 1);
    return m_symbols.back().get();
}

const std::vector<std::unique_ptr<Symbol>>& SymbolSection::getSymbols() const {
    return m_symbols;
}

void SymbolSection::finalize() {
    std::stable_sort(m_symbols.begin(), m_symbols.end(), [](const std::unique_ptr<Symbol>& lhs, const std::unique_ptr<Symbol>& rhs) {
        return lhs->getBinding() < rhs->getBinding();
    });

    m_header.sh_info = sh_info;
    m_header.sh_link = static_cast<Elf_Word>(m_namesSection->getIndex());

    for (const auto& symbol : m_symbols) {
        auto symbolEntry = symbol->m_symbol;
        symbolEntry.st_name = static_cast<Elf_Word>(m_namesSection->addString(symbol->getName()));
        symbolEntry.st_shndx = symbol->getRelatedSection() ? static_cast<Elf_Half>(symbol->getRelatedSection()->getIndex()) : 0;

        m_data.insert(m_data.end(), reinterpret_cast<uint8_t*>(&symbolEntry),
                      reinterpret_cast<uint8_t*>(&symbolEntry) + sizeof(symbolEntry));
    }

    // set size of the section in header, so it gets accounted when writer calculates blob size before allocation
    // this way writer can look at single place (size in header) for all sections
    // including those that don't populate m_data, e.g. EmptySection
    setSize(m_data.size());
}
