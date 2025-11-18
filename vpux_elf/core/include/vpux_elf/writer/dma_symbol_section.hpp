//
// Copyright (C) 2025 Intel Corporation
// SPDX-License-Identifier: Apache-2.0
//

//

#pragma once

#include <vpux_elf/writer/dma_symbol.hpp>
#include <vpux_elf/writer/string_section.hpp>

namespace elf {

class Writer;

namespace writer {

class DmaSymbolSection final : public Section {
public:
    writer::DmaSymbol* addDmaSymbolEntry();
    const std::vector<std::unique_ptr<writer::DmaSymbol>>& getDmaSymbols() const;

    void setInfo(uint32_t info) {
        sh_info = info;
    }

    uint32_t getInfo() {
        return sh_info;
    }

private:
    DmaSymbolSection(const std::string& name);

    void finalize() override;

private:
    std::vector<std::unique_ptr<DmaSymbol>> m_symbols;
    uint32_t sh_info;

    friend Writer;
};

}  // namespace writer
}  // namespace elf
