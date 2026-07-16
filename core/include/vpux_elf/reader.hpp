//
// Copyright (C) 2023-2026 Intel Corporation
// SPDX-License-Identifier: Apache-2.0
//

//

#pragma once

#include <algorithm>
#include <cstddef>
#include <cstring>
#include <limits>
#include <vector>

#include <vpux_elf/types/data_types.hpp>
#include <vpux_elf/types/elf_header.hpp>
#include <vpux_elf/types/elf_structs.hpp>
#include <vpux_elf/types/section_header.hpp>
#include <vpux_elf/types/vpu_extensions.hpp>
#include <vpux_elf/utils/error.hpp>
#include <vpux_elf/utils/utils.hpp>

#include <vpux_elf/accessor.hpp>

namespace elf {

template <ELF_Bitness B>
class Reader {
public:
    class Section {
    public:
        Section() = default;
        Section(AccessManager* accessor, const typename ElfTypes<B>::SectionHeader* sectionHeader, const char* name)
                : mAccessManager(accessor), mHeader(sectionHeader), mName(name), mDataBuffer(nullptr) {
            VPUX_ELF_THROW_WHEN(!mAccessManager, ArgsError, "nullptr AccessManager");
            VPUX_ELF_THROW_WHEN(!mHeader, ArgsError, "nullptr section header");
        }

        const typename ElfTypes<B>::SectionHeader* getHeader() const {
            return mHeader;
        }

        template <typename T>
        size_t getEntriesNum() const {
            VPUX_ELF_THROW_UNLESS(mHeader->sh_entsize == sizeof(T), SectionError,
                                  "sh_entsize does not match expected entry type size");
            VPUX_ELF_THROW_UNLESS((mHeader->sh_size % sizeof(T)) == 0, SectionError,
                                  "section size is not divisible by expected entry type size");
            return static_cast<size_t>(mHeader->sh_size / sizeof(T));
        }

        const char* getName() const {
            return mName;
        }

        // API to retrieve a pointer to the start of the data buffer owned by the Section object
        // This API is particularly useful for user code which does not want the overhead to keep ownership of the data
        // buffer
        template <typename T>
        const T* getData() const {
            if (!mDataBuffer) {
                mDataBuffer = getDataBuffer();
            }
            return reinterpret_cast<const T*>(mDataBuffer->getBuffer().cpu_addr());
        }

        // API to retrieve a buffer with the data corresponding to the Section object
        // This API is useful for higher level semantics, particularly for sharing large sections between
        // different parts of user code
        std::shared_ptr<ManagedBuffer> getDataBuffer(bool cpuOnlyAccess = false) const {
            std::shared_ptr<ManagedBuffer> buffer = nullptr;

        // SHT_NOBITS - sections can have a size greater than the file
        // which will cause offset out of bounds.
        // VPU_SHT_CMX_METADATA - does not contain data in the binary file, so avoid reading
        // VPU_SHT_CMX_WORKSPACE - does not contain data in the binary file, so avoid reading
            if (!((mHeader->sh_type == SHT_NOBITS) || (mHeader->sh_type == VPU_SHT_CMX_METADATA) ||
                  mHeader->sh_type == VPU_SHT_CMX_WORKSPACE)) {
                buffer = mAccessManager->readInternal(
                        mHeader->sh_offset,
                        BufferSpecs(mHeader->sh_addralign, mHeader->sh_size, cpuOnlyAccess ? 0 : mHeader->sh_flags));
            }

            return buffer;
        }

    private:
        AccessManager* mAccessManager = nullptr;
        const typename ElfTypes<B>::SectionHeader* mHeader = nullptr;
        const char* mName = nullptr;
        mutable std::shared_ptr<ManagedBuffer> mDataBuffer;
    };

public:
    explicit Reader(AccessManager* accessor): Reader(nullptr, accessor) {
    }
    Reader(BufferManager* bufferManager, AccessManager* accessor)
            : mBufferManager(bufferManager), mAccessManager(accessor) {
        VPUX_ELF_THROW_UNLESS(mAccessManager, ArgsError, "Accessor pointer is null");

        auto readBuffer(buildBufferFromMember(&mElfHeader));
        mAccessManager->readExternal(0, readBuffer);

        VPUX_ELF_THROW_UNLESS(utils::checkELFMagic(reinterpret_cast<const uint8_t*>(&mElfHeader)), HeaderError,
                              "Incorrect ELF magic");
        VPUX_ELF_THROW_UNLESS(sizeof(typename ElfTypes<B>::SectionHeader) == mElfHeader.e_shentsize, HeaderError,
                              "Mismatch between expected and received section header size");
        VPUX_ELF_THROW_UNLESS(mElfHeader.e_shoff >= sizeof(mElfHeader), HeaderError,
                              "Section table overlaps ELF header");
        VPUX_ELF_THROW_UNLESS(mElfHeader.e_shnum, HeaderError,
                              "No sections detected, ELF blob without sections is unsupported!");
        const auto fileSize = mAccessManager->getSize();
        const auto shEntryBytes = sizeof(typename ElfTypes<B>::SectionHeader);
        const auto shTableBytes = shEntryBytes * mElfHeader.e_shnum;
        VPUX_ELF_THROW_UNLESS(mElfHeader.e_shoff <= fileSize && shTableBytes <= fileSize - mElfHeader.e_shoff,
                              HeaderError, "Section table exceeds whole ELF file size");
        VPUX_ELF_THROW_UNLESS(mElfHeader.e_shstrndx != SHN_UNDEF, HeaderError,
                              "Section name string table index is undefined");
        VPUX_ELF_THROW_UNLESS(mElfHeader.e_shstrndx < mElfHeader.e_shnum, HeaderError,
                              "Section name index exceeds section table");

        mSectionHeaders.resize(mElfHeader.e_shnum);
        readBuffer = buildBufferFromMember(&mSectionHeaders[0], mSectionHeaders.size() * sizeof(mSectionHeaders[0]));
        mAccessManager->readExternal(mElfHeader.e_shoff, readBuffer);

        if (mElfHeader.e_shstrndx) {
            const auto secNamesSection = mSectionHeaders[mElfHeader.e_shstrndx];
            const auto secNameSize = secNamesSection.sh_size;
            const auto secNamesOffset = secNamesSection.sh_offset;

            VPUX_ELF_THROW_UNLESS(secNamesSection.sh_type == SHT_STRTAB, HeaderError,
                                  "Section name table has invalid type");
            VPUX_ELF_THROW_UNLESS(secNameSize >= 1, HeaderError,
                                  "Section name table must contain at least a null terminator");

            VPUX_ELF_THROW_UNLESS(secNamesOffset <= mAccessManager->getSize() &&
                                      secNameSize <= mAccessManager->getSize() - secNamesOffset,
                                  HeaderError, "Section name size exceeds buffer size");

            mSectionNames.resize(secNameSize);
            readBuffer = buildBufferFromMember(&mSectionNames[0], mSectionNames.size() * sizeof(mSectionNames[0]));
            mAccessManager->readExternal(secNamesOffset, readBuffer);
            VPUX_ELF_THROW_UNLESS(mSectionNames.front() == '\0', HeaderError,
                                  "Section name table must start with a null terminator");

            const auto numberOfSections = static_cast<size_t>(mElfHeader.e_shnum);
            mSectionsCache.reserve(numberOfSections);

            validateNoSectionsOverlap(numberOfSections, fileSize);

            for (size_t secIdx = 0; secIdx < numberOfSections; secIdx++) {
                const auto& secHeader = mSectionHeaders[secIdx];

                const auto nameOffset = static_cast<size_t>(secHeader.sh_name);
                VPUX_ELF_THROW_UNLESS(nameOffset < mSectionNames.size(), HeaderError,
                                      "Section name offset exceeds section name table");

                const auto name = mSectionNames.data() + nameOffset;
                const auto maxNameLength = mSectionNames.size() - nameOffset;
                VPUX_ELF_THROW_UNLESS(std::memchr(name, '\0', maxNameLength) != nullptr, HeaderError,
                                      "Section name is not null-terminated within section name table");
                mSectionsCache.emplace_back(mAccessManager, &secHeader, name);
            }
        }
    }

    const typename ElfTypes<B>::ELFHeader* getHeader() const {
        return &mElfHeader;
    }

    size_t getSectionsNum() const {
        // Coverity requires to guard against malicious blob that may trigger read out of bounds
        // as a short-term solution define static limit on sections count
        // to avoid unnecessary rejection of blobs with large amount of sections allow all section count values
        // except maximum supported by the data type of variable
        // to be replaced with the check blob file size not less than amount of bytes needed deduced from ELF header
        constexpr auto MAX_SECTIONS_COUNT = std::numeric_limits<decltype(mElfHeader.e_shnum)>::max() - 1;
        VPUX_ELF_THROW_WHEN(mElfHeader.e_shnum > MAX_SECTIONS_COUNT, ArgsError, "Invalid e_shnum");
        return mElfHeader.e_shnum;
    }

    const Section& getSection(size_t index) const {
        VPUX_ELF_THROW_WHEN(index >= mSectionsCache.size(), RangeError, "Section index out of section number");

        return mSectionsCache[index];
    }

private:
    BufferManager* mBufferManager;
    AccessManager* mAccessManager;

    typename ElfTypes<B>::ELFHeader mElfHeader;
    std::vector<typename ElfTypes<B>::SectionHeader> mSectionHeaders;
    std::vector<char> mSectionNames;

    mutable std::vector<Section> mSectionsCache;

    template <typename T>
    StaticBuffer buildBufferFromMember(T* member, size_t byteSize = sizeof(T)) {
        return StaticBuffer(reinterpret_cast<uint8_t*>(member), BufferSpecs(0, byteSize, 0));
    }

    void validateNoSectionsOverlap(size_t numberOfSections, size_t fileSize) {
        // Collect valid sections for overlap checking
        std::vector<std::pair<size_t, size_t>> sortedRanges;  // {endOffset, secIdx}
        sortedRanges.reserve(numberOfSections);

        for (size_t i = 0; i < numberOfSections; i++) {
            const auto& secHeader = mSectionHeaders[i];

            // TODO: E#220889
            if (secHeader.sh_offset == 0 || secHeader.sh_size == 0) {
                continue;
            }

            const auto sectionOffset = static_cast<size_t>(secHeader.sh_offset);
            const auto sectionSize = static_cast<size_t>(secHeader.sh_size);
            VPUX_ELF_THROW_UNLESS(sectionOffset <= fileSize && sectionSize <= (fileSize - sectionOffset), RangeError,
                                  "Section range does not fit in file");

            // Store end offset and index
            sortedRanges.emplace_back(sectionOffset + sectionSize, i);
        }

        // Sort by end offset for efficient overlap detection
        std::sort(sortedRanges.begin(), sortedRanges.end());

        // Check consecutive pairs for overlaps (sorted by offset ensures all overlaps are detected)
        for (size_t i = 0; i + 1 < sortedRanges.size(); i++) {
            const auto endCurrent = sortedRanges[i].first;
            const auto nextIdx = sortedRanges[i + 1].second;
            const auto nextOffset = static_cast<size_t>(mSectionHeaders[nextIdx].sh_offset);

            // If current section's end is beyond next section's start, they overlap
            VPUX_ELF_THROW_UNLESS(endCurrent <= nextOffset, RangeError,
                                  "Section overlaps next section");
        }
    }
};

}  // namespace elf
