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

class StringSection final : public Section {
public:
    size_t addString(const std::string& name);

private:
    explicit StringSection(const std::string& name);

    friend Writer;
};

} // namespace writer
} // namespace elf
