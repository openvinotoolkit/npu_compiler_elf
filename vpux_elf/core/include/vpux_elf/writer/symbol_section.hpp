//
// Copyright (C) 2023-2025 Intel Corporation
// SPDX-License-Identifier: Apache-2.0
//

//

#pragma once

#include <vpux_elf/writer/symbol.hpp>
#include <vpux_elf/writer/string_section.hpp>

namespace elf {

class Writer;

namespace writer {

class SymbolSection final : public Section {
public:
    Symbol* addSymbolEntry(const std::string& name = {});
    const std::vector<std::unique_ptr<Symbol>>& getSymbols() const;

    void setInfo(uint32_t info) {
        sh_info = info;
    }

    uint32_t getInfo() {
        return sh_info;
    }

private:
    SymbolSection(const std::string& name, StringSection* namesSection);

    void finalize() override;

private:
    StringSection* m_namesSection = nullptr;
    std::vector<std::unique_ptr<Symbol>> m_symbols;
    uint32_t sh_info;

    friend Writer;
};

} // namespace writer
} // namespace elf
