//
// Copyright (C) 2023 Intel Corporation
// SPDX-License-Identifier: Apache 2.0
//

//

#pragma once

#include <vpux_elf/types/data_types.hpp>
#include <vpux_elf/types/section_header.hpp>

#include <memory>
#include <string>
#include <vector>

namespace elf {

class Writer;

namespace writer {

class Section {
public:
    std::string getName() const;
    void setName(const std::string& name);

    Elf_Xword getAddrAlign() const;
    void setAddrAlign(Elf_Xword addrAlign);

    Elf64_Addr getAddr() const;
    void setAddr(Elf64_Addr addr);

    Elf64_Off getOffset() const;

    Elf_Xword getSize() const;
    void setSize(Elf_Xword size);

    Elf_Xword getFlags() const;
    void setFlags(Elf_Xword flags);
    void maskFlags(Elf_Xword flags);

    Elf_Word getType() const;
    void setType(Elf_Word type);

    size_t getFileAlignRequirement() const;

    size_t getIndex() const;

    virtual ~Section() = default;

    // if section has multiple entries inside allocated
    // separately, it may require multiple writes to its
    // part of the blob
    // E#136375 - revisit need to call shift every time manually
    // after serialization an object inside section
    uint8_t* getCurrentWriteAddr() const;
    void shiftCurrentWriteAddr(size_t shiftInBytes);

protected:
    explicit Section(const std::string& name = {});

    virtual void finalize();

    void setIndex(size_t index);
    void setNameOffset(size_t offset);
    void writeRawBytesToElfStorageVector(const uint8_t* sourceData, size_t sourceByteCount);

protected:
    std::string m_name;
    size_t m_index = 0;
    size_t m_fileAlignRequirement = 1;

    SectionHeader m_header{};
    std::vector<uint8_t> m_data;  // needed for string sections
    uint8_t* m_startAddr = nullptr;
    // keep track of offset separately from m_startAddr
    // to check out of bounds issues via section size on writes
    size_t m_currentWriteOffset = 0;

    friend Writer;
};

}  // namespace writer
}  // namespace elf
