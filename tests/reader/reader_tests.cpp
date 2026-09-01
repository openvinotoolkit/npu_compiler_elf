//
// Copyright (C) 2025-2026 Intel Corporation.
// SPDX-License-Identifier: Apache-2.0
//

//

#include <cstring>

#include <vpux_elf/accessor.hpp>
#include <vpux_elf/reader.hpp>

#include <gtest/gtest.h>

using namespace elf;

// TODO: move to utils
#define OV_ASSERT_NO_THROW(statement) OV_ASSERT_NO_THROW_(statement, GTEST_FATAL_FAILURE_)
#define OV_ASSERT_NO_THROW_(statement, fail)                              \
    GTEST_AMBIGUOUS_ELSE_BLOCKER_                                         \
    if (::testing::internal::AlwaysTrue()) {                              \
        try {                                                             \
            GTEST_SUPPRESS_UNREACHABLE_CODE_WARNING_BELOW_(statement);    \
        } catch (const std::exception& e) {                               \
            fail("Expected: " #statement " doesn't throw an exception.\n" \
                 "  Actual: it throws.")                                  \
                    << e.what();                                          \
        } catch (...) {                                                   \
            fail("Expected: " #statement " doesn't throw an exception.\n" \
                 "  Actual: it throws.");                                 \
        }                                                                 \
    }

namespace {

ELFHeader createTemplateFileHeader() {
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
    fileHeader.e_shoff = sizeof(ELFHeader);
    fileHeader.e_shstrndx = 0;
    fileHeader.e_shnum = 0;

    fileHeader.e_ehsize = sizeof(ELFHeader);
    fileHeader.e_shentsize = sizeof(SectionHeader);

    return fileHeader;
}

constexpr size_t headerTableSize = 3;
constexpr size_t indexToCheck = 1;
constexpr size_t secHeaderStrIdxSecSize = 1;

struct ReaderTestScenario {
    ELFHeader fileHeader;
    std::vector<SectionHeader> sectionHeaders;
    size_t sectionTableBytes;
    size_t sectionNamesOffset;
};

// Helper to build a test ELF buffer from file header and section headers
std::vector<uint8_t> buildTestBuffer(const ELFHeader& fileHeader, const std::vector<SectionHeader>& sectionHeaders,
                                     size_t minSize = 0) {
    std::vector<uint8_t> buffer;
    buffer.insert(buffer.end(), reinterpret_cast<const uint8_t*>(&fileHeader),
                  reinterpret_cast<const uint8_t*>(&fileHeader) + sizeof(fileHeader));
    buffer.insert(
            buffer.end(), reinterpret_cast<const uint8_t*>(sectionHeaders.data()),
            reinterpret_cast<const uint8_t*>(sectionHeaders.data()) + sectionHeaders.size() * sizeof(SectionHeader));
    buffer.push_back('\0');

    if (buffer.size() < minSize) {
        buffer.resize(minSize, 0);
    }
    return buffer;
}

ReaderTestScenario createReaderTestScenario(size_t sectionsCount, size_t sectionNameTableIndex = 1,
                                            size_t sectionNameTableSize = secHeaderStrIdxSecSize) {
    ReaderTestScenario scenario;
    scenario.fileHeader = createTemplateFileHeader();
    scenario.fileHeader.e_shnum = sectionsCount;
    scenario.fileHeader.e_shstrndx = sectionNameTableIndex;
    scenario.sectionHeaders.resize(sectionsCount);
    scenario.sectionTableBytes = sizeof(SectionHeader) * sectionsCount;
    scenario.sectionNamesOffset = sizeof(scenario.fileHeader) + scenario.sectionTableBytes;

    scenario.sectionHeaders[sectionNameTableIndex].sh_type = SHT_STRTAB;
    scenario.sectionHeaders[sectionNameTableIndex].sh_offset = scenario.sectionNamesOffset;
    scenario.sectionHeaders[sectionNameTableIndex].sh_size = sectionNameTableSize;

    return scenario;
}

void setPayloadSection(std::vector<SectionHeader>& sectionHeaders, size_t index, size_t offset, Elf_Word size,
                       Elf_Word type = SHT_LOUSER) {
    sectionHeaders[index].sh_type = type;
    sectionHeaders[index].sh_offset = offset;
    sectionHeaders[index].sh_size = size;
}

void expectReaderThrowsRangeError(std::vector<uint8_t>& buffer, const char* expectedMessagePart) {
    auto accessor = DDRAccessManager<elf::DDRAlwaysEmplace>(buffer.data(), buffer.size());
    try {
        (void)Reader<ELF_Bitness::Elf64>(&accessor);
        FAIL() << "Expected RangeError to be thrown";
    } catch (const RangeError& err) {
        ASSERT_NE(std::strstr(err.what(), expectedMessagePart), nullptr);
    }
}

void expectReaderThrowsRangeError(std::vector<uint8_t>& buffer, ErrorCode expectedErrorCode) {
    auto accessor = DDRAccessManager<elf::DDRAlwaysEmplace>(buffer.data(), buffer.size());
    try {
        (void)Reader<ELF_Bitness::Elf64>(&accessor);
        FAIL() << "Expected RangeError to be thrown";
    } catch (const RangeError& err) {
        ASSERT_EQ(err.error_code, expectedErrorCode);
    }
}

void expectReaderNoThrow(std::vector<uint8_t>& buffer) {
    auto accessor = DDRAccessManager<elf::DDRAlwaysEmplace>(buffer.data(), buffer.size());
    OV_ASSERT_NO_THROW((Reader<ELF_Bitness::Elf64>(&accessor)));
}

}  // namespace

TEST(ELFReaderTests, ELFReaderThrowsOnIncorrectMagic) {
    auto fileHeader = createTemplateFileHeader();
    fileHeader.e_ident[EI_MAG3] = 'D';
    auto accessor =
            DDRAccessManager<elf::DDRAlwaysEmplace>(reinterpret_cast<uint8_t*>(&fileHeader), sizeof(fileHeader));

    ASSERT_ANY_THROW(auto reader = Reader<ELF_Bitness::Elf64>(&accessor));
}

TEST(ELFReaderTests, ReadingTheCorrectELFHeaderDoesntThrow) {
    std::vector<SectionHeader> sectionHeaders(headerTableSize);

    auto fileHeader = createTemplateFileHeader();
    fileHeader.e_shnum = headerTableSize;
    auto secHeaderStrIdx = headerTableSize - 1;
    fileHeader.e_shstrndx = secHeaderStrIdx;
    const auto sectionTableBytes = sizeof(SectionHeader) * headerTableSize;
    const auto sectionNamesOffset = sizeof(fileHeader) + sectionTableBytes;
    sectionHeaders[indexToCheck].sh_offset = sizeof(fileHeader);
    sectionHeaders[secHeaderStrIdx].sh_type = SHT_STRTAB;
    sectionHeaders[secHeaderStrIdx].sh_offset = sectionNamesOffset;
    sectionHeaders[secHeaderStrIdx].sh_size = secHeaderStrIdxSecSize;

    std::vector<uint8_t> buffer;
    buffer.insert(buffer.end(), reinterpret_cast<uint8_t*>(&fileHeader),
                  reinterpret_cast<uint8_t*>(&fileHeader) + sizeof(fileHeader));
    buffer.insert(buffer.end(), reinterpret_cast<uint8_t*>(sectionHeaders.data()),
                  reinterpret_cast<uint8_t*>(sectionHeaders.data()) + sizeof(SectionHeader) * headerTableSize);
    buffer.push_back('\0');
    auto accessor = DDRAccessManager<elf::DDRAlwaysEmplace>(buffer.data(), buffer.size());

    OV_ASSERT_NO_THROW(auto reader = Reader<ELF_Bitness::Elf64>(&accessor));
}

TEST(ELFReaderTests, ELFHeaderIsReadCorrectly) {
    std::vector<SectionHeader> sectionHeaders(headerTableSize);

    auto fileHeader = createTemplateFileHeader();
    fileHeader.e_shnum = headerTableSize;
    auto secHeaderStrIdx = headerTableSize - 1;
    fileHeader.e_shstrndx = secHeaderStrIdx;
    const auto sectionTableBytes = sizeof(SectionHeader) * headerTableSize;
    const auto sectionNamesOffset = sizeof(fileHeader) + sectionTableBytes;
    sectionHeaders[indexToCheck].sh_offset = sizeof(fileHeader);
    sectionHeaders[secHeaderStrIdx].sh_type = SHT_STRTAB;
    sectionHeaders[secHeaderStrIdx].sh_offset = sectionNamesOffset;
    sectionHeaders[secHeaderStrIdx].sh_size = secHeaderStrIdxSecSize;

    std::vector<uint8_t> buffer;
    buffer.insert(buffer.end(), reinterpret_cast<uint8_t*>(&fileHeader),
                  reinterpret_cast<uint8_t*>(&fileHeader) + sizeof(fileHeader));
    buffer.insert(buffer.end(), reinterpret_cast<uint8_t*>(sectionHeaders.data()),
                  reinterpret_cast<uint8_t*>(sectionHeaders.data()) + sizeof(SectionHeader) * headerTableSize);
    buffer.push_back('\0');
    auto accessor = DDRAccessManager<elf::DDRAlwaysEmplace>(buffer.data(), buffer.size());

    const auto reader = Reader<ELF_Bitness::Elf64>(&accessor);
    auto parsedFileHeader = *reader.getHeader();

    ASSERT_TRUE(sizeof(fileHeader) == sizeof(parsedFileHeader));
    ASSERT_TRUE(!memcmp(&fileHeader, &parsedFileHeader, sizeof(parsedFileHeader)));
}

TEST(ELFReaderTests, ELFReaderThrowsOnInvalidSectionHeaderCount) {
    auto fileHeader = createTemplateFileHeader();
    fileHeader.e_shnum = 1;
    auto accessor =
            DDRAccessManager<elf::DDRAlwaysEmplace>(reinterpret_cast<uint8_t*>(&fileHeader), sizeof(fileHeader));

    ASSERT_ANY_THROW(auto reader = Reader<ELF_Bitness::Elf64>(&accessor));
}

TEST(ELFReaderTests, SectionHeadersAreReadCorrectly) {
    std::vector<SectionHeader> sectionHeaders(headerTableSize);

    for (size_t idx = 0; idx < sectionHeaders.size(); idx++) {
        sectionHeaders[idx].sh_name = idx;
        sectionHeaders[idx].sh_size = headerTableSize;
    }

    auto fileHeader = createTemplateFileHeader();
    fileHeader.e_shnum = headerTableSize;
    fileHeader.e_shstrndx = headerTableSize - 1;
    const auto sectionTableBytes = sizeof(SectionHeader) * headerTableSize;
    const auto sectionNamesOffset = sizeof(fileHeader) + sectionTableBytes;
    sectionHeaders[fileHeader.e_shstrndx].sh_type = SHT_STRTAB;
    sectionHeaders[fileHeader.e_shstrndx].sh_offset = sectionNamesOffset;
    sectionHeaders[fileHeader.e_shstrndx].sh_size = headerTableSize;

    std::vector<uint8_t> buffer;
    buffer.insert(buffer.end(), reinterpret_cast<uint8_t*>(&fileHeader),
                  reinterpret_cast<uint8_t*>(&fileHeader) + sizeof(fileHeader));
    buffer.insert(buffer.end(), reinterpret_cast<uint8_t*>(sectionHeaders.data()),
                  reinterpret_cast<uint8_t*>(sectionHeaders.data()) + sizeof(SectionHeader) * headerTableSize);
    buffer.insert(buffer.end(), headerTableSize, '\0');

    auto accessor = DDRAccessManager<elf::DDRAlwaysEmplace>(buffer.data(), buffer.size());
    auto reader = Reader<ELF_Bitness::Elf64>(&accessor);

    ASSERT_TRUE(sizeof(sectionHeaders[0]) == sizeof(*reader.getSection(0).getHeader()));

    for (uint64_t idx = 0; idx < sectionHeaders.size(); ++idx) {
        ASSERT_TRUE(!memcmp(&sectionHeaders[idx], reader.getSection(idx).getHeader(), sizeof(sectionHeaders[0])));
    }
}

TEST(ELFReaderTests, PointerToSectionDataIsResolvedCorrectly) {
    std::vector<SectionHeader> sectionHeaders(headerTableSize);

    for (size_t idx = 0; idx < sectionHeaders.size(); idx++) {
        sectionHeaders[idx].sh_name = idx;
        sectionHeaders[idx].sh_size = headerTableSize;
    }

    auto fileHeader = createTemplateFileHeader();
    fileHeader.e_shnum = headerTableSize;
    fileHeader.e_shstrndx = headerTableSize - 1;
    const auto sectionTableBytes = sizeof(SectionHeader) * headerTableSize;
    const auto sectionNamesOffset = sizeof(fileHeader) + sectionTableBytes;
    sectionHeaders[indexToCheck].sh_offset = sizeof(fileHeader);
    sectionHeaders[fileHeader.e_shstrndx].sh_type = SHT_STRTAB;
    sectionHeaders[fileHeader.e_shstrndx].sh_offset = sectionNamesOffset;
    sectionHeaders[fileHeader.e_shstrndx].sh_size = headerTableSize;

    std::vector<uint8_t> buffer;
    buffer.insert(buffer.end(), reinterpret_cast<uint8_t*>(&fileHeader),
                  reinterpret_cast<uint8_t*>(&fileHeader) + sizeof(fileHeader));
    buffer.insert(buffer.end(), reinterpret_cast<uint8_t*>(sectionHeaders.data()),
                  reinterpret_cast<uint8_t*>(sectionHeaders.data()) + sizeof(SectionHeader) * headerTableSize);
    buffer.insert(buffer.end(), headerTableSize, '\0');

    auto accessor = DDRAccessManager<elf::DDRAlwaysEmplace>(buffer.data(), buffer.size());
    auto reader = Reader<ELF_Bitness::Elf64>(&accessor);
    ASSERT_EQ(reader.getSection(indexToCheck).getData<uint8_t>(), buffer.data() + sizeof(fileHeader));
}

TEST(ELFReaderTests, PtrToSectionDataIsResolvedCorrectlyWithGetSectionNoData) {
    std::vector<SectionHeader> sectionHeaders(headerTableSize);

    for (size_t idx = 0; idx < sectionHeaders.size(); idx++) {
        sectionHeaders[idx].sh_name = idx;
        sectionHeaders[idx].sh_size = headerTableSize;
    }

    auto fileHeader = createTemplateFileHeader();
    fileHeader.e_shnum = headerTableSize;
    fileHeader.e_shstrndx = headerTableSize - 1;
    const auto sectionTableBytes = sizeof(SectionHeader) * headerTableSize;
    const auto sectionNamesOffset = sizeof(fileHeader) + sectionTableBytes;
    sectionHeaders[indexToCheck].sh_offset = sizeof(fileHeader);
    sectionHeaders[fileHeader.e_shstrndx].sh_type = SHT_STRTAB;
    sectionHeaders[fileHeader.e_shstrndx].sh_offset = sectionNamesOffset;
    sectionHeaders[fileHeader.e_shstrndx].sh_size = headerTableSize;

    std::vector<uint8_t> buffer;
    buffer.insert(buffer.end(), reinterpret_cast<uint8_t*>(&fileHeader),
                  reinterpret_cast<uint8_t*>(&fileHeader) + sizeof(fileHeader));
    buffer.insert(buffer.end(), reinterpret_cast<uint8_t*>(sectionHeaders.data()),
                  reinterpret_cast<uint8_t*>(sectionHeaders.data()) + sizeof(SectionHeader) * headerTableSize);
    buffer.insert(buffer.end(), headerTableSize, '\0');

    auto accessor = DDRAccessManager<elf::DDRAlwaysEmplace>(buffer.data(), buffer.size());
    auto reader = Reader<ELF_Bitness::Elf64>(&accessor);
    ASSERT_EQ(reader.getSection(indexToCheck).getData<uint8_t>(), buffer.data() + sizeof(fileHeader));
}

TEST(ELFReaderTests, EntriesNumCanBeInflatedByMalformedSectionEntSize) {
    std::vector<SectionHeader> sectionHeaders(headerTableSize);

    constexpr size_t manipulatedSectionIdx = 1;
    constexpr size_t manipulatedSectionSize = sizeof(SymbolEntry);

    auto fileHeader = createTemplateFileHeader();
    fileHeader.e_shnum = headerTableSize;
    fileHeader.e_shstrndx = headerTableSize - 1;

    const auto sectionTableBytes = sizeof(SectionHeader) * headerTableSize;
    const auto manipulatedSectionOffset = sizeof(fileHeader) + sectionTableBytes;
    const auto sectionNamesOffset = manipulatedSectionOffset + manipulatedSectionSize;

    sectionHeaders[manipulatedSectionIdx].sh_name = 0;
    sectionHeaders[manipulatedSectionIdx].sh_type = SHT_SYMTAB;
    sectionHeaders[manipulatedSectionIdx].sh_offset = manipulatedSectionOffset;
    sectionHeaders[manipulatedSectionIdx].sh_size = manipulatedSectionSize;
    // Malformed value: table is interpreted as bytes instead of SymbolEntry-sized entries.
    sectionHeaders[manipulatedSectionIdx].sh_entsize = 1;

    sectionHeaders[fileHeader.e_shstrndx].sh_name = 0;
    sectionHeaders[fileHeader.e_shstrndx].sh_type = SHT_STRTAB;
    sectionHeaders[fileHeader.e_shstrndx].sh_offset = sectionNamesOffset;
    sectionHeaders[fileHeader.e_shstrndx].sh_size = 1;

    std::vector<uint8_t> buffer;
    buffer.insert(buffer.end(), reinterpret_cast<uint8_t*>(&fileHeader),
                  reinterpret_cast<uint8_t*>(&fileHeader) + sizeof(fileHeader));
    buffer.insert(buffer.end(), reinterpret_cast<uint8_t*>(sectionHeaders.data()),
                  reinterpret_cast<uint8_t*>(sectionHeaders.data()) + sectionTableBytes);
    buffer.insert(buffer.end(), manipulatedSectionSize, 0);
    buffer.push_back('\0');

    auto accessor = DDRAccessManager<elf::DDRAlwaysEmplace>(buffer.data(), buffer.size());
    auto reader = Reader<ELF_Bitness::Elf64>(&accessor);

    const auto& section = reader.getSection(manipulatedSectionIdx);
    ASSERT_THROW(section.getEntriesNum<SymbolEntry>(), SectionError);
}

TEST(ELFReaderTests, ReaderThrowsWhenSectionNameOffsetExceedsStringTable) {
    std::vector<SectionHeader> sectionHeaders(headerTableSize);

    constexpr size_t manipulatedSectionIdx = 1;
    constexpr Elf_Word outOfBoundsNameOffset = 2;

    auto fileHeader = createTemplateFileHeader();
    fileHeader.e_shnum = headerTableSize;
    fileHeader.e_shstrndx = headerTableSize - 1;

    const auto sectionTableBytes = sizeof(SectionHeader) * headerTableSize;
    const auto sectionNamesOffset = sizeof(fileHeader) + sectionTableBytes;

    // Corrupt one section header so its name points past the section-name string table.
    sectionHeaders[manipulatedSectionIdx].sh_name = outOfBoundsNameOffset;

    // Minimal .shstrtab: one-byte table containing only '\0'.
    // Any non-zero name offset must therefore be treated as out of bounds.
    sectionHeaders[fileHeader.e_shstrndx].sh_name = 0;
    sectionHeaders[fileHeader.e_shstrndx].sh_type = SHT_STRTAB;
    sectionHeaders[fileHeader.e_shstrndx].sh_offset = sectionNamesOffset;
    sectionHeaders[fileHeader.e_shstrndx].sh_size = secHeaderStrIdxSecSize;

    std::vector<uint8_t> buffer;
    buffer.insert(buffer.end(), reinterpret_cast<uint8_t*>(&fileHeader),
                  reinterpret_cast<uint8_t*>(&fileHeader) + sizeof(fileHeader));
    buffer.insert(buffer.end(), reinterpret_cast<uint8_t*>(sectionHeaders.data()),
                  reinterpret_cast<uint8_t*>(sectionHeaders.data()) + sectionTableBytes);
    // Backing storage for the one-byte section-name string table.
    buffer.push_back('\0');

    auto accessor = DDRAccessManager<elf::DDRAlwaysEmplace>(buffer.data(), buffer.size());

    // Reader validates section-name offsets during construction and must reject this ELF.
    ASSERT_ANY_THROW((Reader<ELF_Bitness::Elf64>(&accessor)));
}

TEST(ELFReaderTests, ReaderThrowsWhenSectionNameIsNotNullTerminatedInStringTable) {
    std::vector<SectionHeader> sectionHeaders(headerTableSize);

    constexpr size_t manipulatedSectionIdx = 1;

    auto fileHeader = createTemplateFileHeader();
    fileHeader.e_shnum = headerTableSize;
    fileHeader.e_shstrndx = headerTableSize - 1;

    const auto sectionTableBytes = sizeof(SectionHeader) * headerTableSize;
    const auto sectionNamesOffset = sizeof(fileHeader) + sectionTableBytes;

    // Offset is in-range, but points to a string that is not null-terminated in .shstrtab.
    sectionHeaders[manipulatedSectionIdx].sh_name = 1;

    sectionHeaders[fileHeader.e_shstrndx].sh_name = 0;
    sectionHeaders[fileHeader.e_shstrndx].sh_type = SHT_STRTAB;
    sectionHeaders[fileHeader.e_shstrndx].sh_offset = sectionNamesOffset;
    sectionHeaders[fileHeader.e_shstrndx].sh_size = 2;

    std::vector<uint8_t> buffer;
    buffer.insert(buffer.end(), reinterpret_cast<uint8_t*>(&fileHeader),
                  reinterpret_cast<uint8_t*>(&fileHeader) + sizeof(fileHeader));
    buffer.insert(buffer.end(), reinterpret_cast<uint8_t*>(sectionHeaders.data()),
                  reinterpret_cast<uint8_t*>(sectionHeaders.data()) + sectionTableBytes);
    // .shstrtab is valid at offset 0 ('\0'), but missing a terminator for the name at offset 1.
    buffer.push_back('\0');
    buffer.push_back('A');

    auto accessor = DDRAccessManager<elf::DDRAlwaysEmplace>(buffer.data(), buffer.size());

    ASSERT_ANY_THROW((Reader<ELF_Bitness::Elf64>(&accessor)));
}

TEST(ELFReaderTests, ReaderThrowsWhenSectionTableOffsetExceedsFileSize) {
    auto fileHeader = createTemplateFileHeader();
    fileHeader.e_shnum = 1;
    // Keep earlier validations valid and fail exactly on e_shoff <= fileSize.
    fileHeader.e_shoff = static_cast<uint64_t>(sizeof(ELFHeader) + 1);

    auto accessor =
            DDRAccessManager<elf::DDRAlwaysEmplace>(reinterpret_cast<uint8_t*>(&fileHeader), sizeof(fileHeader));

    ASSERT_THROW(auto reader = Reader<ELF_Bitness::Elf64>(&accessor), HeaderError);
}

TEST(ELFReaderTests, ReaderThrowsWhenSectionTableBytesExceedFileTail) {
    auto fileHeader = createTemplateFileHeader();
    fileHeader.e_shnum = 2;
    fileHeader.e_shoff = sizeof(ELFHeader);

    // Buffer has room for only one section header after e_shoff.
    // This makes shTableBytes > (fileSize - e_shoff).
    std::vector<uint8_t> buffer(sizeof(fileHeader) + sizeof(SectionHeader), 0);
    std::memcpy(buffer.data(), &fileHeader, sizeof(fileHeader));

    auto accessor = DDRAccessManager<elf::DDRAlwaysEmplace>(buffer.data(), buffer.size());

    ASSERT_THROW(auto reader = Reader<ELF_Bitness::Elf64>(&accessor), HeaderError);
}

TEST(ELFReaderTests, ReaderThrowsWhenPayloadSectionsOverlap) {
    // 1. ReaderThrowsWhenPayloadSectionsOverlap
    // - Section 2: [P, P+10)
    // - Section 3: [P+9, P+19)
    // - Shared byte range: [P+9, P+10) => overlap (1 byte)
    //
    // offset:   P         P+9       P+10       P+19
    // S2:      [==========)
    // S3:               [==========)
    //                    ^ overlap
    auto scenario = createReaderTestScenario(4);

    const auto payloadSectionOffset = scenario.sectionNamesOffset + secHeaderStrIdxSecSize;
    constexpr Elf_Word payloadSectionSize = 10;
    setPayloadSection(scenario.sectionHeaders, 2, payloadSectionOffset, payloadSectionSize);

    // Deliberate overlap with section 2.
    setPayloadSection(scenario.sectionHeaders, 3, payloadSectionOffset + payloadSectionSize - 1, payloadSectionSize);

    const auto neededSize = payloadSectionOffset + 2 * payloadSectionSize;
    auto buffer = buildTestBuffer(scenario.fileHeader, scenario.sectionHeaders, neededSize);
    expectReaderThrowsRangeError(buffer, ErrorCode::ELF_ERROR_RANGE_SECTION_OVERLAPS_NEXT_SECTION);
}

TEST(ELFReaderTests, ReaderThrowsWhenPayloadSectionRunsWayPastNextSection) {
    // Section 2 extends well past section 3, not just by a boundary-adjacent byte.
    //
    // offset:   P         P+5       P+15              P+35
    // S2:      [===============================)
    // S3:            [==========)
    //                ^^^^^^^^^^ section 3 is fully covered by section 2
    auto scenario = createReaderTestScenario(4);

    const auto payloadSectionOffset = scenario.sectionNamesOffset + secHeaderStrIdxSecSize;
    constexpr Elf_Word longPayloadSectionSize = 35;
    constexpr Elf_Word shortPayloadSectionSize = 10;
    setPayloadSection(scenario.sectionHeaders, 2, payloadSectionOffset, longPayloadSectionSize);
    setPayloadSection(scenario.sectionHeaders, 3, payloadSectionOffset + 5, shortPayloadSectionSize);

    const auto neededSize = payloadSectionOffset + longPayloadSectionSize;
    auto buffer = buildTestBuffer(scenario.fileHeader, scenario.sectionHeaders, neededSize);
    expectReaderThrowsRangeError(buffer, ErrorCode::ELF_ERROR_RANGE_SECTION_OVERLAPS_NEXT_SECTION);
}

TEST(ELFReaderTests, ReaderDoesntThrowWhenPayloadSectionsAreUnorderedButNonOverlapping) {
    // 2. ReaderDoesntThrowWhenPayloadSectionsAreUnorderedButNonOverlapping
    // - Section 3: [P+10, P+20)
    // - Section 2: [P+40, P+50)
    // - Section 4: [P+70, P+80)
    // - Unordered by index, but disjoint by ranges => no overlap
    //
    // offset:  P+10   P+20       P+40   P+50       P+70   P+80
    // S3:      [======)
    // S2:                      [======)
    // S4:                                   [======)
    auto scenario = createReaderTestScenario(5);

    constexpr Elf_Word payloadSectionSize = 10;
    const auto payloadBaseOffset = scenario.sectionNamesOffset + secHeaderStrIdxSecSize;

    // Intentionally unordered by index but non-overlapping by file range.
    setPayloadSection(scenario.sectionHeaders, 2, payloadBaseOffset + 40, payloadSectionSize);
    setPayloadSection(scenario.sectionHeaders, 3, payloadBaseOffset + 10, payloadSectionSize);
    setPayloadSection(scenario.sectionHeaders, 4, payloadBaseOffset + 70, payloadSectionSize);

    const auto neededSize = payloadBaseOffset + 70 + payloadSectionSize;
    auto buffer = buildTestBuffer(scenario.fileHeader, scenario.sectionHeaders, neededSize);
    expectReaderNoThrow(buffer);
}

TEST(ELFReaderTests, ReaderThrowsWhenPayloadSectionsAreUnorderedButOverlapping) {
    // Unordered by section index, but overlapping by file range.
    // This validates that overlap detection does not depend on section table order.
    //
    // offset:  P+10   P+20   P+25   P+35
    // S3:      [======)
    // S2:                [==========)
    // S4:                     [==========)
    //                         ^ overlap in [P+25, P+35)
    auto scenario = createReaderTestScenario(5);

    constexpr Elf_Word payloadSectionSize = 10;
    const auto payloadBaseOffset = scenario.sectionNamesOffset + secHeaderStrIdxSecSize;

    setPayloadSection(scenario.sectionHeaders, 2, payloadBaseOffset + 25, payloadSectionSize);
    setPayloadSection(scenario.sectionHeaders, 3, payloadBaseOffset + 10, payloadSectionSize);
    setPayloadSection(scenario.sectionHeaders, 4, payloadBaseOffset + 20, payloadSectionSize + 5);

    const auto neededSize = payloadBaseOffset + 35;
    auto buffer = buildTestBuffer(scenario.fileHeader, scenario.sectionHeaders, neededSize);
    expectReaderThrowsRangeError(buffer, ErrorCode::ELF_ERROR_RANGE_SECTION_OVERLAPS_NEXT_SECTION);
}

TEST(ELFReaderTests, ReaderDoesntThrowForSpecialCaseSectionTypes) {
    // 3. ReaderDoesntThrowForSpecialCaseSectionTypes
    // - SHT_NOBITS, VPU_SHT_CMX_METADATA, VPU_SHT_CMX_WORKSPACE are intentionally
    //   excluded from overlap validation
    // - They are intentionally excluded from overlap validation
    // - Only normal payload section is considered => no overlap failure expected
    //
    // Special sections:
    // NOBITS      offset=0 (ignored)
    // CMX_META    offset=0 (ignored)
    // CMX_WORK    offset=0 (ignored)
    //
    // Payload:
    // S5: [Q, Q+10) checked normally
    auto scenario = createReaderTestScenario(6);

    constexpr Elf_Word sectionSize = 10;
    const auto payloadOffset = scenario.sectionNamesOffset + secHeaderStrIdxSecSize;

    setPayloadSection(scenario.sectionHeaders, 2, 0, sectionSize, SHT_NOBITS);
    setPayloadSection(scenario.sectionHeaders, 3, 0, sectionSize, VPU_SHT_CMX_METADATA);
    setPayloadSection(scenario.sectionHeaders, 4, 0, sectionSize, VPU_SHT_CMX_WORKSPACE);

    // This payload section follows overlapping special-case sections.
    setPayloadSection(scenario.sectionHeaders, 5, payloadOffset + sectionSize + 4, sectionSize);

    const auto neededSize = scenario.sectionHeaders[5].sh_offset + sectionSize;
    auto buffer = buildTestBuffer(scenario.fileHeader, scenario.sectionHeaders, neededSize);
    expectReaderNoThrow(buffer);
}

TEST(ELFReaderTests, ReaderDoesntThrowWhenNextSectionOffsetIsZero) {
    // 4. ReaderDoesntThrowWhenNextSectionOffsetIsZero
    // - Section 2: [R, R+10)
    // - Section 3: offset 0 => skipped by overlap validator
    // - Effective checked set has only Section 2 => no overlap failure
    //
    // S2: [==========)
    // S3: offset=0  (skipped)
    auto scenario = createReaderTestScenario(4);

    constexpr Elf_Word sectionSize = 10;
    setPayloadSection(scenario.sectionHeaders, 2, scenario.sectionNamesOffset + secHeaderStrIdxSecSize, sectionSize);

    // Reader overlap check is properly handled: this zero-offset section would be skipped
    // as a constraint, allowing section 2's validation to proceed against file end
    setPayloadSection(scenario.sectionHeaders, 3, 0, sectionSize);

    const auto neededSize = scenario.sectionHeaders[2].sh_offset + sectionSize;
    auto buffer = buildTestBuffer(scenario.fileHeader, scenario.sectionHeaders, neededSize);
    expectReaderNoThrow(buffer);
}

TEST(ELFReaderTests, ReaderThrowsWhenPayloadSectionCOverlapsWithASeparatedByZeroOffsetB) {
    // 5. ReaderThrowsWhenPayloadSectionCOverlapsWithASeparatedByZeroOffsetB
    // - A (section 2): [A, A+10)
    // - B (section 3): offset 0, SHT_NOBITS => skipped
    // - C (section 4): [A+9, A+19)
    // - A and C overlap even though B is between them in table order => should throw
    //
    // offset:   A         A+9       A+10       A+19
    // A:       [==========)
    // B: offset=0 (ignored)
    // C:                 [==========)
    //                    ^ overlap
    // Scenario: A (non-zero offset), B (zero offset), C (non-zero offset, overlaps with A)
    // Verifies that overlap between A and C is detected even when B (zero-offset) is between them
    auto scenario = createReaderTestScenario(5);

    // Section A: payload, non-zero offset
    const auto offsetA = scenario.sectionNamesOffset + secHeaderStrIdxSecSize;
    constexpr Elf_Word sizeA = 10;
    setPayloadSection(scenario.sectionHeaders, 2, offsetA, sizeA);

    // Section B: zero offset, special type (skipped in overlap check)
    setPayloadSection(scenario.sectionHeaders, 3, 0, 10, SHT_NOBITS);

    // Section C: payload, overlaps with A despite B being in between
    const auto offsetC = offsetA + sizeA - 1;
    constexpr Elf_Word sizeC = 10;
    setPayloadSection(scenario.sectionHeaders, 4, offsetC, sizeC);

    const auto neededSize = offsetC + sizeC;
    auto buffer = buildTestBuffer(scenario.fileHeader, scenario.sectionHeaders, neededSize);
    expectReaderThrowsRangeError(buffer, ErrorCode::ELF_ERROR_RANGE_SECTION_OVERLAPS_NEXT_SECTION);
}

TEST(ELFReaderTests, ReaderThrowsWhenPayloadSectionExtendsBeyondFileBounds) {
    // 6. ReaderThrowsWhenPayloadSectionExtendsBeyondFileBounds (not section-section overlap)
    // - Section A: declared [A, A+100)
    // - File only has bytes up to about A+50
    // - This is a bounds violation (range exceeds file), not pairwise overlap
    //
    // declared section: [A-------------------------------A+100)
    // file available:   [0----------------A+50)
    //                                  ^ out-of-bounds tail
    // Scenario: Payload section extends beyond the file size
    // Verifies that final payload section can't extend past wholeFileSize
    auto scenario = createReaderTestScenario(3);

    // Payload section: offset is valid, but size extends beyond buffer
    const auto offsetA = scenario.sectionNamesOffset + secHeaderStrIdxSecSize;
    constexpr Elf_Word sizeA = 100;  // Large size
    setPayloadSection(scenario.sectionHeaders, 2, offsetA, sizeA);

    // Create buffer that's smaller than needed for the section
    const auto neededSize = offsetA + 50;  // Only 50 bytes, but section requests 100
    auto buffer = buildTestBuffer(scenario.fileHeader, scenario.sectionHeaders, neededSize);
    expectReaderThrowsRangeError(buffer, ErrorCode::ELF_ERROR_RANGE_SECTION_READ_GOES_OVER_END_OF_FILE);
}

TEST(ELFReaderTests, ReaderThrowsWhenNoBitsSectionExtendsBeyondFileBounds) {
    // 7. ReaderThrowsWhenNoBitsSectionExtendsBeyondFileBounds (not section-section overlap)
    // - Section A: declared [A, A+100)
    // - Section B: offset 0 => skipped as non-file-backed for range validation
    // - File only has bytes up to about A+50
    // - This is a bounds violation (range exceeds file), not pairwise overlap
    //
    // declared section: [A-------------------------------A+100)
    // section B:        offset=0 (ignored)
    // file available:   [0----------------A+50)
    //                                  ^ out-of-bounds tail
    // Scenario: SHT_NOBITS section extends beyond the file size with another zero-offset section present
    // Verifies that constructor range validation still rejects section A
    auto scenario = createReaderTestScenario(4);

    const auto offsetA = scenario.sectionNamesOffset + secHeaderStrIdxSecSize;
    constexpr Elf_Word sizeA = 100;
    setPayloadSection(scenario.sectionHeaders, 2, offsetA, sizeA, SHT_NOBITS);

    constexpr Elf_Word sizeB = 10;
    setPayloadSection(scenario.sectionHeaders, 3, 0, sizeB);

    const auto neededSize = offsetA + 50;
    auto buffer = buildTestBuffer(scenario.fileHeader, scenario.sectionHeaders, neededSize);
    expectReaderThrowsRangeError(buffer, ErrorCode::ELF_ERROR_RANGE_SECTION_READ_GOES_OVER_END_OF_FILE);
}

namespace {
// Parameterized test for section alignment validation
struct AlignmentCase {
    Elf_Word alignment;
    bool shouldThrow;
};

class ELFReaderAlignmentTests : public ::testing::TestWithParam<AlignmentCase> {};

TEST_P(ELFReaderAlignmentTests, ReaderHandlesSectionAlignmentZeroOneAndInvalidThree) {
    const auto testCase = GetParam();
    SCOPED_TRACE(::testing::Message() << "alignment=" << testCase.alignment);

    auto scenario = createReaderTestScenario(3, 2);

    constexpr Elf_Word payloadSectionSize = 16;
    setPayloadSection(scenario.sectionHeaders, indexToCheck, scenario.sectionNamesOffset + secHeaderStrIdxSecSize,
                      payloadSectionSize);
    scenario.sectionHeaders[indexToCheck].sh_addralign = testCase.alignment;

    const auto neededSize = scenario.sectionHeaders[indexToCheck].sh_offset + payloadSectionSize;
    auto buffer = buildTestBuffer(scenario.fileHeader, scenario.sectionHeaders, neededSize);

    auto accessor = DDRAccessManager<elf::DDRStandardEmplace, elf::DynamicBufferFactory>(buffer.data(), buffer.size());
    const auto constructReader = [&]() {
        return Reader<ELF_Bitness::Elf64>(&accessor);
    };

    if (testCase.shouldThrow) {
        ASSERT_THROW((void)constructReader(), SectionError);
    } else {
        OV_ASSERT_NO_THROW((void)constructReader());
    }
}

INSTANTIATE_TEST_SUITE_P(SectionAlignmentValidation, ELFReaderAlignmentTests,
                         ::testing::Values(AlignmentCase{0, false}, AlignmentCase{1, false}, AlignmentCase{3, true}));
}  // namespace
