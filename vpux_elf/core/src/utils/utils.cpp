//
// Copyright (C) 2023-2025 Intel Corporation
// SPDX-License-Identifier: Apache-2.0
//

//

#include <vpux_elf/types/vpu_extensions.hpp>

#include <vpux_elf/types/elf_header.hpp>
#include <vpux_elf/utils/error.hpp>
#include <vpux_elf/utils/utils.hpp>

namespace elf {

namespace utils {

//
// @brief returning true if the magic is correct
// @params pointer to the elf blob memory
//
bool checkELFMagic(const unsigned char* elfIdent) {
    VPUX_ELF_THROW_UNLESS(elfIdent, ArgsError, "nullptr passed for elf buffer");

    if (elfIdent[elf::EI_MAG0] != elf::ELFMAG0 || elfIdent[elf::EI_MAG1] != elf::ELFMAG1 ||
        elfIdent[elf::EI_MAG2] != elf::ELFMAG2 || elfIdent[elf::EI_MAG3] != elf::ELFMAG3) {
        // if the elf magic is not correct return false
        return false;
    }
    return true;
}

size_t alignUp(size_t size, size_t alignment) {
    if (size && alignment) {
        size = ((size + alignment - 1) / alignment) * alignment;
    }
    return size;
}

bool isPowerOfTwo(size_t value) {
    return value && ((value & (value - 1)) == 0);
}

bool hasNPUAccess(Elf_Xword sectionFlags) {
    return sectionFlags & (SHF_EXECINSTR | VPU_SHF_PROC_DPU | VPU_SHF_PROC_DMA | VPU_SHF_PROC_SHAVE);
}

bool isNetworkIO(Elf_Xword sectionFlags) {
    return sectionFlags & (VPU_SHF_USERINPUT | VPU_SHF_USEROUTPUT | VPU_SHF_PROFOUTPUT);
}

bool hasMemoryFootprint(elf::Elf_Word sectionType) {
    switch (sectionType) {
    case elf::SHT_NOBITS:
    case elf::VPU_SHT_CMX_METADATA:
    case elf::VPU_SHT_CMX_WORKSPACE:
        return false;
    default:
        return true;
    }
}

}  // namespace utils

}  // namespace elf
