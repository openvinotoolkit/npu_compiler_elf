//
// Copyright (C) 2023 Intel Corporation
// SPDX-License-Identifier: Apache 2.0
//

//

#pragma once

#include <vpux_elf/writer/section.hpp>

namespace elf {

class Writer;

namespace writer {

template <typename T>
class BinaryDataSection final : public Section {
public:
    size_t appendData(const T& obj) {
        return appendData(&obj, 1);
    }

    size_t appendData(const T* obj, size_t sizeInElements) {
        writeRawBytesToElfStorageVector(reinterpret_cast<const uint8_t*>(obj), sizeInElements * sizeof(T));
        // return value is meaningless with memory consumption optimization
        // E#136375
        return 0;
    }

    T* expandData(size_t sizeInElements) {
        m_data.resize(m_data.size() + sizeInElements * sizeof(T));
        auto insertionPoint = m_data.end() - sizeInElements * sizeof(T);
        return &(*insertionPoint);
    }

    size_t getNumEntries() const {
        return static_cast<size_t>(m_data.size() / sizeof(T));
    }

private:
    explicit BinaryDataSection(const std::string& name, const Elf_Word section_type = SHT_PROGBITS): Section(name) {
        static_assert(std::is_standard_layout<T>::value, "Only POD types are supported");
        m_header.sh_type = section_type;
        m_header.sh_entsize = sizeof(T);
    }

    friend Writer;
};

}  // namespace writer
}  // namespace elf
