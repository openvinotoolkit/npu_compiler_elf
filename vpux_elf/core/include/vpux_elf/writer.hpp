//
// Copyright (C) 2023 Intel Corporation
// SPDX-License-Identifier: Apache 2.0
//

//

#pragma once

#include <cstddef>
#include <vpux_elf/writer/section.hpp>

#include <vpux_elf/writer/binary_data_section.hpp>
#include <vpux_elf/writer/empty_section.hpp>
#include <vpux_elf/writer/relocation_section.hpp>
#include <vpux_elf/writer/string_section.hpp>
#include <vpux_elf/writer/symbol_section.hpp>

#include <vpux_elf/types/data_types.hpp>
#include <vpux_elf/types/elf_header.hpp>
#include <vpux_elf/types/section_header.hpp>

#include <vpux_elf/utils/error.hpp>

#include <string>
#include <vector>

namespace elf {

class Writer {
public:
    Writer();

    // Prepare elf header internals, register section headers and compute total size required.
    void prepareWriter();
    size_t getTotalSize() const;
    void generateELF(uint8_t* data);

    // E#136375: revisit name of the method and try to avoid need to call it
    // separately from generateELF
    void setSectionsStartAddr(uint8_t* elfBinary);

    writer::RelocationSection* addRelocationSection(const std::string& name = {});
    writer::SymbolSection* addSymbolSection(const std::string& name = {});
    writer::EmptySection* addEmptySection(const std::string& name = {});

    template <typename T>
    writer::BinaryDataSection<T>* addBinaryDataSection(const std::string& name = {},
                                                       const Elf_Word section_type = SHT_PROGBITS) {
        m_sections.push_back(
                std::unique_ptr<writer::BinaryDataSection<T>>(new writer::BinaryDataSection<T>(name, section_type)));
        m_sections.back()->setIndex(m_sections.size() - 1);
        return dynamic_cast<writer::BinaryDataSection<T>*>(m_sections.back().get());
    }

private:
    writer::Section* addSection(const std::string& name = {});
    writer::StringSection* addStringSection(const std::string& name = {});

    elf::ELFHeader generateELFHeader() const;

    static size_t writeRawBytesToStorageVector(uint8_t* storageVector, size_t storageSize, size_t storageOffset,
                                               const uint8_t* sourceData, size_t sourceByteCount);

    template <typename SourceType>
    static size_t writeContainerToStorageVector(uint8_t* storageVector, size_t storageSize, size_t storageOffset,
                                                const SourceType& sourceContainer, size_t sourceOffset,
                                                size_t sourceCount) {
        // Accept 0 size writes
        if (!sourceCount) {
            return storageOffset;
        }

        auto sourcePos = sourceContainer.begin() + sourceOffset;

        // Check source offset and size bounds
        VPUX_ELF_THROW_WHEN(sourcePos >= sourceContainer.end(), RuntimeError, "Read offset out of bounds");
        VPUX_ELF_THROW_WHEN(sourcePos + sourceCount > sourceContainer.end(), RuntimeError, "Read size exceeds bounds");

        // Convert sourceCount to byte count
        auto sourceByteCount = sourceCount * sizeof(typename SourceType::value_type);
        return writeRawBytesToStorageVector(storageVector, storageSize, storageOffset,
                                            reinterpret_cast<const uint8_t*>(&(*sourcePos)), sourceByteCount);
    }

    template <typename SourceType>
    static size_t writeObjectToStorageVector(uint8_t* storageVector, size_t storageSize, size_t storageOffset,
                                             const SourceType& sourceObject) {
        return writeRawBytesToStorageVector(storageVector, storageSize, storageOffset,
                                            reinterpret_cast<const uint8_t*>(&sourceObject), sizeof(SourceType));
    }

private:
    elf::ELFHeader m_elfHeader;
    size_t m_totalBinarySize = 0;
    size_t m_dataOffset = 0;
    writer::StringSection* m_sectionHeaderNames;
    writer::StringSection* m_symbolNames;
    std::vector<std::unique_ptr<writer::Section>> m_sections;
    std::vector<elf::SectionHeader> m_sectionHeaders;
};

}  // namespace elf
