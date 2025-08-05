//
// Copyright (C) 2023-2025 Intel Corporation
// SPDX-License-Identifier: Apache-2.0
//

//

#pragma once

#include <cstddef>
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

        size_t getEntriesNum() const {
            VPUX_ELF_THROW_UNLESS(mHeader->sh_entsize, SectionError,
                                  "sh_entsize=0 represents a section that does not hold a table of fixed-size entries. "
                                  "This feature is not suported.")
            return static_cast<size_t>(mHeader->sh_size / mHeader->sh_entsize);
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
        VPUX_ELF_THROW_UNLESS(mElfHeader.e_shstrndx < mElfHeader.e_shnum, HeaderError,
                              "Section name index exceeds section table");

        mSectionHeaders.resize(mElfHeader.e_shnum);
        readBuffer = buildBufferFromMember(&mSectionHeaders[0], mSectionHeaders.size() * sizeof(mSectionHeaders[0]));
        mAccessManager->readExternal(mElfHeader.e_shoff, readBuffer);

        if (mElfHeader.e_shstrndx) {
            const auto secNamesSection = mSectionHeaders[mElfHeader.e_shstrndx];

            VPUX_ELF_THROW_UNLESS(secNamesSection.sh_offset + secNamesSection.sh_size <= mAccessManager->getSize(),
                                  HeaderError, "Section name size exceeds buffer size");

            mSectionNames.resize(secNamesSection.sh_size);
            readBuffer = buildBufferFromMember(&mSectionNames[0], mSectionNames.size() * sizeof(mSectionNames[0]));
            mAccessManager->readExternal(secNamesSection.sh_offset, readBuffer);

            auto numberOfSections = mElfHeader.e_shnum;
            mSectionsCache.reserve(numberOfSections);
            for (size_t secIdx = 0; secIdx < numberOfSections; secIdx++) {
                const auto& secHeader = mSectionHeaders[secIdx];
                const auto name = &mSectionNames[secHeader.sh_name];
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
        VPUX_ELF_THROW_WHEN(index >= mElfHeader.e_shnum, RangeError, "Section index out of bounds");

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
};

}  // namespace elf
