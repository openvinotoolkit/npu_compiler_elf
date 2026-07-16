//
// Copyright (C) 2023-2025 Intel Corporation
// SPDX-License-Identifier: Apache-2.0
//

//

#pragma once

#include <vpux_elf/writer/section.hpp>

#include <vpux_elf/writer/relocation.hpp>

namespace elf {

class Writer;

namespace writer {

class RelocationSection final : public Section {
public:
    const SymbolSection* getSymbolTable() const;
    void setSymbolTable(const SymbolSection* symTab);

    Elf_Word getSpecialSymbolTable() const;
    void setSpecialSymbolTable(Elf_Word specialSymbolTable);

    const Section* getSectionToPatch() const;
    void setSectionToPatch(const Section* sectionToPatch);

    Relocation* addRelocationEntry();
    const std::vector<std::unique_ptr<Relocation>>& getRelocations() const;

private:
    explicit RelocationSection(const std::string& name);

    void finalize() override;

private:
    const SymbolSection* m_symTab = nullptr;
    const Section* m_sectionToPatch = nullptr;

    std::vector<std::unique_ptr<Relocation>> m_relocations;

    friend Writer;
};

} // namespace writer
} // namespace elf
