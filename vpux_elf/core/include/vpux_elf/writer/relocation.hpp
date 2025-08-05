//
// Copyright (C) 2023-2025 Intel Corporation
// SPDX-License-Identifier: Apache-2.0
//

//

#pragma once

#include <vpux_elf/types/relocation_entry.hpp>
#include <vpux_elf/writer/symbol_section.hpp>

namespace elf {
namespace writer {

class RelocationSection;

class Relocation {
public:
    Elf64_Addr getOffset() const;
    void setOffset(Elf64_Addr offset);

    Elf_Word getType() const;
    void setType(Elf_Word type);

    Elf_Sxword getAddend() const;
    void setAddend(Elf_Sxword addend);

    const Symbol* getSymbol() const;
    void setSymbol(const Symbol* symbol);

    Elf_Word getSpecialSymbol() const;
    void setSpecialSymbol(Elf_Word specialSymbol);

private:
    Relocation() = default;

    RelocationAEntry m_relocation{};
    const Symbol* m_symbol = nullptr;

    friend RelocationSection;
};

} // namespace writer
} // namespace elf
