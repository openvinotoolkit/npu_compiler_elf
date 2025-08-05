//
// Copyright (C) 2023-2025 Intel Corporation
// SPDX-License-Identifier: Apache-2.0
//

//

#include <vpux_elf/writer/empty_section.hpp>

using namespace elf;
using namespace elf::writer;

EmptySection::EmptySection(const std::string& name) : Section(name) {
    m_header.sh_type = elf::SHT_NOBITS;
}

Elf_Xword EmptySection::getSize() const {
    return m_header.sh_size;
}

void EmptySection::setSize(Elf_Xword size) {
    m_header.sh_size = size;
}
