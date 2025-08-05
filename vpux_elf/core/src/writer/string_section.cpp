//
// Copyright (C) 2023-2025 Intel Corporation
// SPDX-License-Identifier: Apache-2.0
//

//

#include <vpux_elf/writer/string_section.hpp>

using namespace elf;
using namespace elf::writer;

StringSection::StringSection(const std::string& name): Section(name) {
    m_header.sh_type = SHT_STRTAB;
    m_data.push_back('\0');
}

size_t StringSection::addString(const std::string& name) {
    if (name.empty()) {
        return 0;
    }

    const auto pos = m_data.size();
    const auto str = name.c_str();
    m_data.insert(m_data.end(), str, str + name.size() + 1);
    setSize(m_data.size());

    return pos;
}
