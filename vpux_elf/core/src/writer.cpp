//
// Copyright (C) 2023-2025 Intel Corporation
// SPDX-License-Identifier: Apache-2.0
//

//

#include <cstddef>
#include <cstdint>
#include <utility>
#include <vpux_elf/utils/error.hpp>
#include <vpux_elf/utils/utils.hpp>
#include <vpux_elf/writer.hpp>
#include <vpux_elf/writer/empty_section.hpp>

#include <algorithm>
#include <unordered_set>

#include <iostream>

using namespace elf;
using namespace elf::writer;

//
// Writer
//

Writer::Writer() {
    // Creating NULL section
    m_sections.push_back(std::unique_ptr<Section>(new Section));

    m_sectionHeaderNames = addStringSection(".strtab");

    m_symbolNames = addStringSection(".symstrtab");
};

void Writer::prepareWriter() {
    m_elfHeader = generateELFHeader();

    m_elfHeader.e_shstrndx = static_cast<Elf_Half>(m_sectionHeaderNames->getIndex());

    for (auto& section : m_sections) {
        section->finalize();
        section->setNameOffset(m_sectionHeaderNames->addString(section->getName()));
    }

    auto curOffset = static_cast<size_t>(m_elfHeader.e_ehsize);
    if (m_elfHeader.e_shnum) {
        m_elfHeader.e_shoff = utils::alignUp(curOffset, m_elfHeader.e_shentsize);
        curOffset = static_cast<Elf_Half>(m_elfHeader.e_shoff);
    }

    curOffset += static_cast<size_t>(m_elfHeader.e_shnum) * m_elfHeader.e_shentsize;

    m_dataOffset = static_cast<size_t>(curOffset);
    m_totalBinarySize = m_dataOffset;

    m_sectionHeaders.reserve(m_elfHeader.e_shnum);

    for (auto& section : m_sections) {
        // account for alignment requirement of all sections, including those that don't occupy space in the blob
        // it's temporary solution to keep blobs of the same hash as before optimization and simplify validation
        // extra memory overhead is negligible, e.g. for Age&Gender blob of size 4.4MB we save around 3KB
        // E#136376
        m_totalBinarySize = utils::alignUp(m_totalBinarySize, section->getAddrAlign());

        const auto isNotEmptySection = dynamic_cast<elf::writer::EmptySection*>(section.get()) == nullptr;
        const auto hasData = section->getSize() != 0;

        if (isNotEmptySection && hasData) {
            // to keep "no-data" sections with zero offset (and don't allocate space for them in blob)
            // check for both not empty section & has data as there could be sections without data
            // that have type different from EmptySection e.g. shave.data being binary section
            // that maybe missing for a given blob
            section->m_header.sh_offset = m_totalBinarySize;
            m_totalBinarySize += section->getSize();
        }
        m_sectionHeaders.push_back(section->m_header);
    }
}

void Writer::generateELF(uint8_t* data) {
    VPUX_ELF_THROW_WHEN(data == nullptr, ArgsError, "Storage pointer is nullptr");
    VPUX_ELF_THROW_UNLESS(utils::checkELFMagic(reinterpret_cast<uint8_t*>(&m_elfHeader)), ImplausibleState,
                          "Can't generateELF without previous call to prepareWriter!");
    VPUX_ELF_THROW_UNLESS(m_totalBinarySize != 0, RangeError, "Unknown size for blob storage. Check if you called Writer::prepareWriter");
    const auto size = getTotalSize();

    const auto serializeSection = [data, size](Section* section) {
        if (!section->m_data.empty()) {
            // there are still sections that get serialized in 2 stages: first to internal storage of elf::Writer
            // then to final blob here, e.g. relocation sections and symbol tables
            // it's temporary solution for sections with internal states (e.g. relocation and symbol entries)
            // note: it needs to be done after blob size calculation as section offsets are being updated there
            // E#-136375
            Writer::writeContainerToStorageVector(data, size, section->getOffset(), section->m_data, 0,
                                                  section->m_data.size());
        }
    };

    for (auto& section : m_sections) {
        serializeSection(section.get());
    }

    m_dataOffset = writeObjectToStorageVector(data, size, 0, m_elfHeader);

    if (m_elfHeader.e_shoff) {
        m_dataOffset = writeContainerToStorageVector(data, size, m_dataOffset, m_sectionHeaders, 0, m_sectionHeaders.size());
    }
}

size_t Writer::getTotalSize() const {
    return m_totalBinarySize;
}

void Writer::setSectionsStartAddr(uint8_t* elfBinaryAddr) {
    VPUX_ELF_THROW_WHEN(elfBinaryAddr == nullptr, ArgsError, "Storage pointer is nullptr");
    for (auto& section : m_sections) {
        section->m_startAddr = elfBinaryAddr + section->m_header.sh_offset;
    }
}

Section* Writer::addSection(const std::string& name) {
    m_sections.push_back(std::unique_ptr<Section>(new Section(name)));
    m_sections.back()->setIndex(m_sections.size() - 1);
    return m_sections.back().get();
}

RelocationSection* Writer::addRelocationSection(const std::string& name) {
    m_sections.push_back(std::unique_ptr<RelocationSection>(new RelocationSection(name)));
    m_sections.back()->setIndex(m_sections.size() - 1);
    return dynamic_cast<RelocationSection*>(m_sections.back().get());
}

SymbolSection* Writer::addSymbolSection(const std::string& name) {
    m_sections.push_back(std::unique_ptr<SymbolSection>(new SymbolSection(name, m_symbolNames)));
    m_sections.back()->setIndex(m_sections.size() - 1);
    return dynamic_cast<SymbolSection*>(m_sections.back().get());
}

EmptySection* Writer::addEmptySection(const std::string& name) {
    m_sections.push_back(std::unique_ptr<EmptySection>(new EmptySection(name)));
    m_sections.back()->setIndex(m_sections.size() - 1);
    return dynamic_cast<EmptySection*>(m_sections.back().get());
}

StringSection* Writer::addStringSection(const std::string& name) {
    m_sections.push_back(std::unique_ptr<StringSection>(new StringSection(name)));
    m_sections.back()->setIndex(m_sections.size() - 1);
    return dynamic_cast<StringSection*>(m_sections.back().get());
}

elf::ELFHeader Writer::generateELFHeader() const {
    ELFHeader fileHeader{};

    fileHeader.e_ident[EI_MAG0] = ELFMAG0;
    fileHeader.e_ident[EI_MAG1] = ELFMAG1;
    fileHeader.e_ident[EI_MAG2] = ELFMAG2;
    fileHeader.e_ident[EI_MAG3] = ELFMAG3;
    fileHeader.e_ident[EI_CLASS] = ELFCLASS64;
    fileHeader.e_ident[EI_DATA] = ELFDATA2LSB;
    fileHeader.e_ident[EI_VERSION] = EV_NONE;
    fileHeader.e_ident[EI_OSABI] = 0;
    fileHeader.e_ident[EI_ABIVERSION] = 0;

    fileHeader.e_type = ET_REL;
    fileHeader.e_machine = EM_NONE;
    fileHeader.e_version = EV_NONE;

    fileHeader.e_entry = 0;
    fileHeader.e_flags = 0;
    fileHeader.e_shstrndx = 0;

    fileHeader.e_shnum = static_cast<Elf_Half>(m_sections.size());
    fileHeader.e_shoff = 0;

    fileHeader.e_ehsize = sizeof(ELFHeader);
    fileHeader.e_shentsize = sizeof(SectionHeader);

    return fileHeader;
}

size_t Writer::writeRawBytesToStorageVector(uint8_t* storageVector, size_t storageSize, size_t storageOffset,
                                            const uint8_t* sourceData, size_t sourceByteCount) {
    VPUX_ELF_THROW_WHEN(storageVector == nullptr, ArgsError, "Storage pointer is nullptr");

    auto storagePos = storageVector + storageOffset;
    auto storageVectorEnd = storageVector + storageSize;

    // Check storage offset and size bounds
    VPUX_ELF_THROW_WHEN(storagePos >= storageVectorEnd, RuntimeError, "Write offset out of bounds");
    VPUX_ELF_THROW_WHEN(storagePos + sourceByteCount > storageVectorEnd, RuntimeError, "Write size exceeds bounds");

    std::copy_n(sourceData, sourceByteCount, storagePos);

    return storageOffset + sourceByteCount;
}
