//
// Copyright (C) 2023-2025 Intel Corporation
// SPDX-License-Identifier: Apache-2.0
//

//

#pragma once

#include <vpux_elf/writer/section.hpp>

namespace elf {

class Writer;

namespace writer {

class EmptySection final : public Section {
public:
    Elf_Xword getSize() const;
    void setSize(Elf_Xword size);

private:
    explicit EmptySection(const std::string& name);

    friend Writer;
};

} // namespace writer
} // namespace elf
