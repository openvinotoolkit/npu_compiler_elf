//
// Copyright (C) 2023-2025 Intel Corporation
// SPDX-License-Identifier: Apache-2.0
//

//

#pragma once

#include <vpux_elf/types/symbol_entry.hpp>
#include <vpux_elf/writer/section.hpp>

namespace elf {
namespace writer {

class SymbolSection;

class Symbol {
public:
    std::string getName() const;
    void setName(const std::string& name);

    Elf_Word getType() const;
    void setType(Elf_Word type);

    Elf_Word getBinding() const;
    void setBinding(Elf_Word bind);

    uint8_t getVisibility() const;
    void setVisibility(uint8_t visibility);

    const Section* getRelatedSection() const;
    void setRelatedSection(const Section* section);

    Elf64_Addr getValue() const;
    void setValue(Elf64_Addr value);

    size_t getSize() const;
    void setSize(size_t size);

    size_t getIndex() const;

private:
    Symbol(const std::string& name = {});

    void setIndex(size_t index);

private:
    std::string m_name;
    size_t m_index = 0;

    SymbolEntry m_symbol{};
    const Section* m_relatedSection = nullptr;

    friend SymbolSection;
};

} // namespace writer
} // namespace elf
