//
// Copyright (C) 2023-2025 Intel Corporation
// SPDX-License-Identifier: Apache-2.0
//

//

#include <vpux_elf/writer/symbol.hpp>

#include <algorithm>

using namespace elf;
using namespace elf::writer;

Symbol::Symbol(const std::string& name) : m_name(name) {
    m_symbol.st_name = 0;
    m_symbol.st_info = static_cast<uint8_t>(elf64STInfo(STB_LOCAL, STT_NOTYPE));
    m_symbol.st_other = elf64STVisibility(STV_DEFAULT);
    m_symbol.st_shndx = 0;
    m_symbol.st_value = 0;
    m_symbol.st_size = 0;
}

std::string Symbol::getName() const {
    return m_name;
}

void Symbol::setName(const std::string& name) {
    m_name = name;
}

size_t Symbol::getSize() const {
    return m_symbol.st_size;
}

void Symbol::setSize(size_t size) {
    m_symbol.st_size = size;
}

Elf64_Addr Symbol::getValue() const {
    return m_symbol.st_value;
}

void Symbol::setValue(Elf64_Addr value) {
    m_symbol.st_value = value;
}

Elf_Word Symbol::getType() const {
    return static_cast<Elf_Word>(elf64STType(m_symbol.st_info));
}

void Symbol::setType(Elf_Word type) {
    m_symbol.st_info = static_cast<uint8_t>(elf64STInfo(elf64STBind(m_symbol.st_info), type));
}

Elf_Word Symbol::getBinding() const {
    return static_cast<Elf_Word>(elf64STBind(m_symbol.st_info));
}

void Symbol::setBinding(Elf_Word bind) {
    m_symbol.st_info = static_cast<uint8_t>(elf64STInfo(bind, elf64STType(m_symbol.st_info)));
}

uint8_t Symbol::getVisibility() const {
    return m_symbol.st_other;
}

void Symbol::setVisibility(uint8_t visibility) {
    m_symbol.st_other = elf64STVisibility(visibility);
}

const Section* Symbol::getRelatedSection() const {
    return m_relatedSection;
}

void Symbol::setRelatedSection(const Section* section) {
    m_relatedSection = section;
}

size_t Symbol::getIndex() const {
    return m_index;
}

void Symbol::setIndex(size_t index) {
    m_index = index;
}
