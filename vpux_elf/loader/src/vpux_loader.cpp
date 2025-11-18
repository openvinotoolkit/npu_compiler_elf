//
// Copyright (C) 2023-2025 Intel Corporation
// SPDX-License-Identifier: Apache-2.0
//

#include <algorithm>
#include <cstring>

#include <memory>
#include <unordered_map>
#include <vpux_loader/vpux_loader.hpp>
#include "vpux_elf/types/section_header.hpp"
#include "vpux_elf/utils/error.hpp"
#include "vpux_headers/buffer_specs.hpp"
#include "vpux_headers/device_buffer.hpp"
#include "vpux_headers/device_buffer_container.hpp"
#include "vpux_headers/managed_buffer.hpp"
#include "vpux_headers/relocations.hpp"

#ifndef VPUX_ELF_LOG_UNIT_NAME
#define VPUX_ELF_LOG_UNIT_NAME "VpuxLoader"
#endif
#include <vpux_elf/reader.hpp>

namespace elf {

namespace {

const uint32_t LO_21_BIT_MASK = 0x001F'FFFF;
const uint32_t B21_B26_MASK = 0x07E0'0000;

template <typename T>
void safeGet(T* dst, const T* src) {
    VPUX_ELF_LOG(LogLevel::LOG_DEBUG, "copying to %p from %p amount %u", dst, src, sizeof(T));
    memcpy(reinterpret_cast<void*>(dst), reinterpret_cast<const void*>(src), sizeof(T));
    VPUX_ELF_LOG(LogLevel::LOG_DEBUG, "copy done");
    return;
}

const uint32_t ADDRESS_MASK = ~0x00C0'0000u;
const uint64_t SLICE_LENGTH = 2 * 1024 * 1024;

uint32_t to_dpu_multicast(uint32_t addr, unsigned int& offset1, unsigned int& offset2, unsigned int& offset3) {
    const uint32_t bare_ptr = addr & ADDRESS_MASK;
    const uint32_t broadcast_mask = (addr & ~ADDRESS_MASK) >> 20;

    static const unsigned short multicast_masks[16] = {
            0x0000, 0x0001, 0x0002, 0x0003, 0x0012, 0x0011, 0x0010, 0x0030,
            0x0211, 0x0210, 0x0310, 0x0320, 0x3210, 0x3210, 0x3210, 0x3210,
    };

    VPUX_ELF_THROW_UNLESS(broadcast_mask < 16, RangeError, "Broadcast mask out of range");
    const unsigned short multicast_mask = multicast_masks[broadcast_mask];

    VPUX_ELF_THROW_UNLESS(multicast_mask != 0xffff, RangeError, "Got an invalid multicast mask");

    unsigned int base_mask = (static_cast<unsigned int>(multicast_mask) & 0xf) << 20;
    offset1 *= (multicast_mask >> 4) & 0xf;
    offset2 *= (multicast_mask >> 8) & 0xf;
    offset3 *= (multicast_mask >> 12) & 0xf;

    return bare_ptr | base_mask;
}

uint32_t to_dpu_multicast_base(uint32_t addr) {
    unsigned int offset1 = 0;
    unsigned int offset2 = 0;
    unsigned int offset3 = 0;
    return to_dpu_multicast(addr, offset1, offset2, offset3);
}

const auto VPU_16_BIT_SUM_Relocation = [](void* targetAddr, const elf::SymbolEntry& targetSym,
                                          const Elf_Sxword addend) -> void {
    auto addr = reinterpret_cast<uint16_t*>(targetAddr);
    auto symVal = targetSym.st_value;
    VPUX_ELF_LOG(LogLevel::LOG_DEBUG, "\t\t16Bit SUM reloc, addr %p addrVal 0x%x symVal 0x%llx addend %llu", addr,
                 *addr, symVal, addend);

    *addr += static_cast<uint16_t>(symVal + addend);
};

const auto VPU_64_BIT_MULT_Relocation = [](void* targetAddr, const elf::SymbolEntry& targetSym,
                                           const Elf_Sxword addend) -> void {
    auto addr = reinterpret_cast<uint64_t*>(targetAddr);
    auto symVal = targetSym.st_value;
    VPUX_ELF_LOG(LogLevel::LOG_DEBUG, "\t\t64Bit MULT reloc, addr %p addrVal 0x%x symVal 0x%llx addend %llu", addr,
                 *addr, symVal, addend);

    *addr *= static_cast<uint64_t>(symVal);
};

const auto VPU_64_BIT_MULT_SUB_Relocation = [](void* targetAddr, const elf::SymbolEntry& targetSym,
                                               const Elf_Sxword addend) -> void {
    auto addr = reinterpret_cast<uint64_t*>(targetAddr);
    auto symVal = targetSym.st_value;
    VPUX_ELF_LOG(LogLevel::LOG_DEBUG, "\t\t64Bit MULT after SUB reloc, addr %p addrVal 0x%x symVal 0x%llx addend %llu",
                 addr, *addr, symVal, addend);

    *addr *= static_cast<int64_t>(addend) - static_cast<int64_t>(symVal);
};

const auto VPU_64_BIT_Relocation = [](void* targetAddr, const elf::SymbolEntry& targetSym,
                                      const Elf_Sxword addend) -> void {
    auto addr = reinterpret_cast<uint64_t*>(targetAddr);
    auto symVal = targetSym.st_value;
    VPUX_ELF_LOG(LogLevel::LOG_DEBUG, "\t\t64Bit Reloc addr %p symval 0x%llx addnd %llu", addr, symVal, addend);

    *addr = symVal + addend;
};

const auto VPU_64_BIT_OR_Relocation = [](void* targetAddr, const elf::SymbolEntry& targetSym,
                                         const Elf_Sxword addend) -> void {
    auto addr = reinterpret_cast<uint64_t*>(targetAddr);
    auto symVal = targetSym.st_value;
    VPUX_ELF_LOG(LogLevel::LOG_DEBUG, "\t\t64Bit OR reloc, addr %p addrVal 0x%llx symVal 0x%llx addend %llu", addr,
                 *addr, symVal, addend);

    *addr |= symVal + addend;
};

const auto VPU_64_BIT_LSHIFT_Relocation = [](void* targetAddr, const elf::SymbolEntry& targetSym,
                                             const Elf_Sxword addend) -> void {
    (void)addend;  // hush compiler warning;
    auto addr = reinterpret_cast<uint64_t*>(targetAddr);
    auto symVal = targetSym.st_value;
    VPUX_ELF_LOG(LogLevel::LOG_DEBUG, "\t\t64Bit LSHIFT reloc, addr %p addrVal 0x%llx symVal 0x%llx", addr, *addr,
                 symVal);

    *addr <<= symVal;
};

const auto VPU_DISP40_RTM_RELOCATION = [](void* targetAddr, const elf::SymbolEntry& targetSym,
                                          const Elf_Sxword addend) -> void {
    auto addr = reinterpret_cast<uint64_t*>(targetAddr);
    auto symVal = targetSym.st_value;
    auto symSize = targetSym.st_size;
    uint64_t mask = 0xffffffffff;
    uint64_t maskedAddr = *addr & mask;
    VPUX_ELF_LOG(LogLevel::LOG_DEBUG, "\t\tDSIP40 reloc, addr %p symVal 0x%llx symSize %llu addend %llu", addr, symVal,
                 symSize, addend);

    *addr |= (symVal + (addend * (maskedAddr & (symSize - 1)))) & mask;
};

const auto VPU_32_BIT_Relocation = [](void* targetAddr, const elf::SymbolEntry& targetSym,
                                      const Elf_Sxword addend) -> void {
    auto addr = reinterpret_cast<uint32_t*>(targetAddr);
    auto symVal = targetSym.st_value;
    VPUX_ELF_LOG(LogLevel::LOG_DEBUG, "\t\t32Bit reloc, addr %p symVal 0x%llx addend %llu", addr, symVal, addend);

    *addr = static_cast<uint32_t>(symVal + addend);
};

const auto VPU_32_BIT_RTM_Relocation = [](void* targetAddr, const elf::SymbolEntry& targetSym,
                                          const Elf_Sxword addend) -> void {
    const auto addr = reinterpret_cast<uint32_t*>(targetAddr);
    auto symVal = targetSym.st_value;
    auto symSize = targetSym.st_size;
    VPUX_ELF_LOG(LogLevel::LOG_DEBUG, "\t\t32Bit RTM reloc, addr %p addrVal 0x%x symVal 0x%llx addend %llu", addr,
                 *addr, symVal, addend);

    *addr = static_cast<uint32_t>(symVal + (addend * (*addr & (symSize - 1))));
};

const auto VPU_32_BIT_SUM_Relocation = [](void* targetAddr, const elf::SymbolEntry& targetSym,
                                          const Elf_Sxword addend) -> void {
    const auto addr = reinterpret_cast<uint32_t*>(targetAddr);
    auto symVal = targetSym.st_value;
    VPUX_ELF_LOG(LogLevel::LOG_DEBUG, "\t\t32Bit SUM reloc, addr %p addrVal 0x%x symVal 0x%llx addend %llu", addr,
                 *addr, symVal, addend);

    *addr += static_cast<uint32_t>(symVal + addend);
};

const auto VPU_32_MULTICAST_BASE_Relocation = [](void* targetAddr, const elf::SymbolEntry& targetSym,
                                                 const Elf_Sxword addend) -> void {
    const auto addr = reinterpret_cast<uint32_t*>(targetAddr);
    auto symVal = targetSym.st_value;
    VPUX_ELF_LOG(LogLevel::LOG_DEBUG, "\t\t32Bit SUM reloc, addr %p addrVal 0x%x symVal 0x%llx addend %llu", addr,
                 *addr, symVal, addend);

    *addr = to_dpu_multicast_base(static_cast<uint32_t>(symVal + addend));
};

const auto VPU_32_MULTICAST_BASE_SUB_Relocation = [](void* targetAddr, const elf::SymbolEntry& targetSym,
                                                     const Elf_Sxword addend) -> void {
    const auto addr = reinterpret_cast<uint32_t*>(targetAddr);
    auto symVal = targetSym.st_value;
    VPUX_ELF_LOG(LogLevel::LOG_DEBUG, "\t\t32Bit SUM reloc, addr %p addrVal 0x%x symVal 0x%llx addend %llu", addr,
                 *addr, symVal, addend);

    *addr = to_dpu_multicast_base(static_cast<uint32_t>(symVal + addend)) - *addr;
};

const auto VPU_DISP28_MULTICAST_OFFSET_Relocation = [](void* targetAddr, const elf::SymbolEntry& targetSym,
                                                       const Elf_Sxword addend) -> void {
    const auto addr = reinterpret_cast<uint32_t*>(targetAddr);
    auto symVal = targetSym.st_value;
    VPUX_ELF_LOG(LogLevel::LOG_DEBUG, "\t\t32Bit SUM reloc, addr %p addrVal 0x%x symVal 0x%llx addend %llu", addr,
                 *addr, symVal, addend);

    unsigned int offs[3] = {SLICE_LENGTH >> 4, SLICE_LENGTH >> 4,
                            SLICE_LENGTH >> 4};  // 1024 * 1024 >> 4 as HW requirement
    to_dpu_multicast(static_cast<uint32_t>(symVal + addend), offs[0], offs[1], offs[2]);

    const auto index = *addr >> 4;
    *addr &= 0xf;
    *addr |= offs[index] << 4;
};

const auto VPU_DISP4_MULTICAST_OFFSET_Relocation = [](void* targetAddr, const elf::SymbolEntry& targetSym,
                                                      const Elf_Sxword addend) -> void {
    const auto addr = reinterpret_cast<uint32_t*>(targetAddr);
    auto symVal = targetSym.st_value;
    VPUX_ELF_LOG(LogLevel::LOG_DEBUG, "\t\t32Bit SUM reloc, addr %p addrVal 0x%x symVal 0x%llx addend %llu", addr,
                 *addr, symVal, addend);

    unsigned int offs[3] = {SLICE_LENGTH >> 4, SLICE_LENGTH >> 4,
                            SLICE_LENGTH >> 4};  // 1024 * 1024 >> 4 as HW requirement
    to_dpu_multicast(static_cast<uint32_t>(symVal + addend), offs[0], offs[1], offs[2]);

    const auto index = *addr & 0xf;
    *addr &= 0xfffffff0;
    *addr |= offs[index] != 0;
};

const auto VPU_LO_21_BIT_Relocation = [](void* targetAddr, const elf::SymbolEntry& targetSym,
                                         const Elf_Sxword addend) -> void {
    auto addr = reinterpret_cast<uint32_t*>(targetAddr);
    auto symVal = targetSym.st_value;
    VPUX_ELF_LOG(LogLevel::LOG_DEBUG, "\t\tLow 21 bits reloc, addr %p symVal 0x%llx addend %llu", addr, symVal, addend);

    auto patchAddr = static_cast<uint32_t>(symVal + addend) & LO_21_BIT_MASK;
    *addr &= ~LO_21_BIT_MASK;
    *addr |= patchAddr;
};

const auto VPU_LO_21_BIT_SUM_Relocation = [](void* targetAddr, const elf::SymbolEntry& targetSym,
                                             const Elf_Sxword addend) -> void {
    auto addr = reinterpret_cast<uint32_t*>(targetAddr);
    auto symVal = targetSym.st_value;
    VPUX_ELF_LOG(LogLevel::LOG_DEBUG, "\t\t32Bit Masked SUM reloc, addr %p symVal 0x%llx addend %llu", addr, symVal,
                 addend);

    auto patchAddr = static_cast<uint32_t>(symVal + addend) & LO_21_BIT_MASK;
    *addr += patchAddr;
};

const auto VPU_LO_21_BIT_MULTICAST_BASE_Relocation = [](void* targetAddr, const elf::SymbolEntry& targetSym,
                                                        const Elf_Sxword addend) -> void {
    const auto addr = reinterpret_cast<uint32_t*>(targetAddr);
    auto symVal = targetSym.st_value;
    VPUX_ELF_LOG(LogLevel::LOG_DEBUG, "\t\t32Bit SUM reloc, addr %p addrVal 0x%x symVal 0x%llx addend %llu", addr,
                 *addr, symVal, addend);

    auto patchAddr = static_cast<uint32_t>(symVal + addend) & LO_21_BIT_MASK;
    *addr = to_dpu_multicast_base(patchAddr);
};

const auto VPU_16_BIT_LSB_21_RSHIFT_5_Relocation = [](void* targetAddr, const elf::SymbolEntry& targetSym,
                                                      const Elf_Sxword addend) -> void {
    auto addr = reinterpret_cast<uint32_t*>(targetAddr);
    auto symVal = targetSym.st_value;
    VPUX_ELF_LOG(LogLevel::LOG_DEBUG,
                 "\t\t16Bit Reloc: Low 21 bits, rshift by 5 reloc, addr %p symVal 0x%llx addend %llu", addr, symVal,
                 addend);

    const uint32_t mask = 0x001F'FFFF;  // mask used to only keep last 21 bits
    const uint32_t lsb_16_mask = 0xFFFF;

    *addr &= ~lsb_16_mask;
    *addr |= (static_cast<uint32_t>(symVal + addend) & mask) >> 5;
};

const auto VPU_LO_21_BIT_RSHIFT_4_Relocation = [](void* targetAddr, const elf::SymbolEntry& targetSym,
                                                  const Elf_Sxword addend) -> void {
    auto addr = reinterpret_cast<uint32_t*>(targetAddr);
    auto symVal = targetSym.st_value;
    VPUX_ELF_LOG(LogLevel::LOG_DEBUG, "\t\tLow 21 bits, rshift 4 reloc, addr %p symVal 0x%llx addend %llu", addr,
                 symVal, addend);

    auto patchAddr = (static_cast<uint32_t>(symVal + addend) & LO_21_BIT_MASK) >> 4;
    *addr &= ~LO_21_BIT_MASK;
    *addr |= patchAddr;
};

const auto VPU_CMX_LOCAL_RSHIFT_5_Relocation = [](void* targetAddr, const elf::SymbolEntry& targetSym,
                                                  const Elf_Sxword addend) -> void {
    auto addr = reinterpret_cast<uint32_t*>(targetAddr);
    auto symVal = targetSym.st_value;
    VPUX_ELF_LOG(LogLevel::LOG_DEBUG, "\t\tCMX local rshift 5 reloc, addr %p addrVal 0x%x symVal 0x%llx addend %llu",
                 addr, *addr, symVal, addend);

    uint32_t CMX_TILE_SELECT_MASK = ~B21_B26_MASK;
    auto patchAddr = (static_cast<uint32_t>(symVal + addend) & CMX_TILE_SELECT_MASK) >> 5;
    *addr = patchAddr;
};

const auto VPU_32_BIT_OR_B21_B26_UNSET_Relocation = [](void* targetAddr, const elf::SymbolEntry& targetSym,
                                                       const Elf_Sxword addend) -> void {
    auto addr = reinterpret_cast<uint32_t*>(targetAddr);
    auto symVal = targetSym.st_value;
    VPUX_ELF_LOG(LogLevel::LOG_DEBUG,
                 "\t\t32 bits OR reloc with b21-26 unset, addr %p, before value: 0x%x symVal 0x%llx addend %llu", addr,
                 *addr, symVal, addend);

    uint32_t B21_B26_UNSET_MASK = ~B21_B26_MASK;
    auto patchAddr = static_cast<uint32_t>(symVal + addend) & B21_B26_UNSET_MASK;
    *addr |= patchAddr;
};

const auto VPU_64_BIT_OR_B21_B26_UNSET_Relocation = [](void* targetAddr, const elf::SymbolEntry& targetSym,
                                                       const Elf_Sxword addend) -> void {
    auto addr = reinterpret_cast<uint64_t*>(targetAddr);
    auto symVal = targetSym.st_value;
    VPUX_ELF_LOG(LogLevel::LOG_DEBUG,
                 "\t\t64 bits OR reloc with b21-26 unset, addr %p, before value: 0x%llx symVal 0x%llx addend %llu",
                 addr, *addr, symVal, addend);

    uint64_t B21_B26_UNSET_MASK = ~B21_B26_MASK;
    auto patchAddr = static_cast<uint64_t>(symVal + addend) & B21_B26_UNSET_MASK;
    *addr |= patchAddr;
};

const auto VPU_16_BIT_LSB_21_RSHIFT_5_LSHIFT_16_Relocation = [](void* targetAddr, const elf::SymbolEntry& targetSym,
                                                                const Elf_Sxword addend) -> void {
    auto addr = reinterpret_cast<uint32_t*>(targetAddr);
    auto symVal = targetSym.st_value;
    VPUX_ELF_LOG(LogLevel::LOG_DEBUG,
                 "\t\t16Bit Reloc: Low 21 bits, rshift by 5 reloc, addr %p symVal 0x%llx addend %llu", addr, symVal,
                 addend);

    const uint32_t mask = 0x001F'FFFF;  // mask used to only keep last 21 bits
    const uint32_t msb_16_mask = 0xFFFF0000;

    *addr &= ~msb_16_mask;
    *addr |= ((static_cast<uint32_t>(symVal + addend) & mask) >> 5) << 16;
};

const auto VPU_16_BIT_LSB_21_RSHIFT_5_LSHIFT_CUSTOM_Relocation = [](void* targetAddr, const elf::SymbolEntry& targetSym,
                                                                    const Elf_Sxword addend) -> void {
    // more details in ticket #E-97614
    auto addr = reinterpret_cast<uint32_t*>(targetAddr);
    auto symVal = targetSym.st_value;
    VPUX_ELF_LOG(
            LogLevel::LOG_DEBUG,
            "\t\t16Bit Reloc preemtion workaround: Low 21 bits, rshift by 5 reloc, addr %p symVal 0x%llx addend %llu",
            addr, symVal, addend);

    const uint32_t mask = 0x001F'FFFF;                          // mask used to only keep last 21 bits
    const uint32_t preemtion_work_around_16_mask = 0xFFFE4000;  // 1111 1111 1111 1110 0100 0000 0000 0000

    *addr &= ~preemtion_work_around_16_mask;

    auto src_value = (static_cast<uint32_t>(symVal + addend) & mask) >> 5;
    // need to convert value from this view: 0000 0000 0000 0000 1111 1111 1111 1111
    // to                                    1111 1111 1111 1110 0100 0000 0000 0000

    // set [17:31] bits
    auto converted_value = (src_value & ~1) << 16;
    // format                                1111 1111 1111 1110 0000 0000 0000 0000

    // set [14] bit
    converted_value |= (src_value & 1) << 14;
    // format                                1111 1111 1111 1110 0100 0000 0000 0000

    *addr |= converted_value;
};

const auto VPU_32_BIT_OR_B21_B26_UNSET_HIGH_16_Relocation = [](void* targetAddr, const elf::SymbolEntry& targetSym,
                                                               const Elf_Sxword addend) -> void {
    auto addr = reinterpret_cast<uint16_t*>(targetAddr);
    auto symVal = targetSym.st_value;
    VPUX_ELF_LOG(
            LogLevel::LOG_DEBUG,
            "\t\t32 bits OR reloc with b21-26 unset and high 16, addr %p, before value: 0x%llx symVal 0x%x addend %llu",
            addr, *addr, symVal, addend);

    uint64_t B21_B26_UNSET_MASK = ~B21_B26_MASK;
    auto patchAddr = static_cast<uint32_t>(symVal + addend) & B21_B26_UNSET_MASK;
    *addr |= patchAddr >> 16;
};

const auto VPU_32_BIT_OR_B21_B26_UNSET_LOW_16_Relocation = [](void* targetAddr, const elf::SymbolEntry& targetSym,
                                                              const Elf_Sxword addend) -> void {
    auto addr = reinterpret_cast<uint16_t*>(targetAddr);
    auto symVal = targetSym.st_value;
    VPUX_ELF_LOG(
            LogLevel::LOG_DEBUG,
            "\t\t32 bits OR reloc with b21-26 unset and low 16, addr %p, before value: 0x%llx symVal 0x%x addend %llu",
            addr, *addr, symVal, addend);

    uint64_t B21_B26_UNSET_MASK = ~B21_B26_MASK;
    auto patchAddr = static_cast<uint16_t>(symVal + addend) & B21_B26_UNSET_MASK;
    *addr |= patchAddr & 0xFFFF;
};

const auto VPU_HIGH_27_BIT_OR_Relocation = [](void* targetAddr, const elf::SymbolEntry& targetSym,
                                              const Elf_Sxword addend) -> void {
    auto addr = reinterpret_cast<uint64_t*>(targetAddr);
    auto symVal = targetSym.st_value;
    VPUX_ELF_LOG(LogLevel::LOG_DEBUG, "\t\tHigh 27 bits reloc, addr %p addrVal 0x%llx  symVal 0x%llx addend %llu", addr,
                 *addr, symVal, addend);

    auto patchAddrUnsetTile = static_cast<uint32_t>(symVal + addend) & ~0xE0'0000;
    auto patchAddr = (patchAddrUnsetTile >> 4) & (0x7FFF'FFFF >> 4);  // only [30:4]
    *addr |= (static_cast<uint64_t>(patchAddr) << 37);                // set [64:37]
};

const auto VPU_32_OR_LO_19_LSB_21_RSHIFT_2_Relocation = [](void* targetAddr, const elf::SymbolEntry& targetSym,
                                                           const Elf_Sxword addend) -> void {
    auto addr = reinterpret_cast<uint32_t*>(targetAddr);
    auto symVal = targetSym.st_value;
    VPUX_ELF_LOG(LogLevel::LOG_DEBUG, "\t\tLow 21 bits, rshift 2 reloc, addr %p symVal 0x%llx addend %llu", addr,
                 symVal, addend);

    auto patchAddr = (static_cast<uint32_t>(symVal + addend) & LO_21_BIT_MASK) >> 2;
    *addr &= ~(LO_21_BIT_MASK >> 2);
    *addr |= patchAddr;
};

}  // namespace

const std::unordered_map<Elf_Word, VPUXLoader::Action> VPUXLoader::actionMap = {
        {SHT_NULL, Action::None},
        {SHT_PROGBITS, Action::AllocateAndLoad},
        {SHT_SYMTAB, Action::RegisterUserIO},
        {SHT_STRTAB, Action::None},
        {SHT_RELA, Action::Relocate},
        {SHT_HASH, Action::Error},
        {SHT_DYNAMIC, Action::Error},
        {SHT_NOTE, Action::None},
        {SHT_NOBITS, Action::Allocate},
        {SHT_REL, Action::Error},
        {SHT_SHLIB, Action::Error},
        {SHT_DYNSYM, Action::Error},
        {VPU_SHT_NETDESC, Action::None},
        {VPU_SHT_PROF, Action::None},
        {VPU_SHT_CMX_METADATA, Action::None},
        {VPU_SHT_CMX_WORKSPACE, Action::None},
        {VPU_SHT_PLATFORM_INFO, Action::None},
        {VPU_SHT_PERF_METRICS, Action::None},
        {VPU_SHT_COMPILER_HASH, Action::None},
        {VPU_SHT_DMA_SYMBOLS, Action::None},
};

const std::unordered_map<VPUXLoader::RelocationType, VPUXLoader::RelocationFunc> VPUXLoader::relocationMap = {
        {R_VPU_64, VPU_64_BIT_Relocation},
        {R_VPU_16_SUM, VPU_16_BIT_SUM_Relocation},
        {R_VPU_64_MULT, VPU_64_BIT_MULT_Relocation},
        {R_VPU_64_MULT_SUB, VPU_64_BIT_MULT_SUB_Relocation},
        {R_VPU_64_OR, VPU_64_BIT_OR_Relocation},
        {R_VPU_DISP40_RTM, VPU_DISP40_RTM_RELOCATION},
        {R_VPU_64_LSHIFT, VPU_64_BIT_LSHIFT_Relocation},
        {R_VPU_32, VPU_32_BIT_Relocation},
        {R_VPU_32_RTM, VPU_32_BIT_RTM_Relocation},
        {R_VPU_32_SUM, VPU_32_BIT_SUM_Relocation},
        {R_VPU_32_MULTICAST_BASE, VPU_32_MULTICAST_BASE_Relocation},
        {R_VPU_32_MULTICAST_BASE_SUB, VPU_32_MULTICAST_BASE_SUB_Relocation},
        {R_VPU_DISP28_MULTICAST_OFFSET, VPU_DISP28_MULTICAST_OFFSET_Relocation},
        {R_VPU_DISP4_MULTICAST_OFFSET_CMP, VPU_DISP4_MULTICAST_OFFSET_Relocation},
        {R_VPU_LO_21, VPU_LO_21_BIT_Relocation},
        {R_VPU_LO_21_SUM, VPU_LO_21_BIT_SUM_Relocation},
        {R_VPU_LO_21_MULTICAST_BASE, VPU_LO_21_BIT_MULTICAST_BASE_Relocation},
        {R_VPU_16_LSB_21_RSHIFT_5, VPU_16_BIT_LSB_21_RSHIFT_5_Relocation},
        {R_VPU_LO_21_RSHIFT_4, VPU_LO_21_BIT_RSHIFT_4_Relocation},
        {R_VPU_CMX_LOCAL_RSHIFT_5, VPU_CMX_LOCAL_RSHIFT_5_Relocation},
        {R_VPU_32_BIT_OR_B21_B26_UNSET, VPU_32_BIT_OR_B21_B26_UNSET_Relocation},
        {R_VPU_64_BIT_OR_B21_B26_UNSET, VPU_64_BIT_OR_B21_B26_UNSET_Relocation},
        {R_VPU_16_LSB_21_RSHIFT_5_LSHIFT_16, VPU_16_BIT_LSB_21_RSHIFT_5_LSHIFT_16_Relocation},
        {R_VPU_16_LSB_21_RSHIFT_5_LSHIFT_CUSTOM, VPU_16_BIT_LSB_21_RSHIFT_5_LSHIFT_CUSTOM_Relocation},
        {R_VPU_32_BIT_OR_B21_B26_UNSET_HIGH_16, VPU_32_BIT_OR_B21_B26_UNSET_HIGH_16_Relocation},
        {R_VPU_32_BIT_OR_B21_B26_UNSET_LOW_16, VPU_32_BIT_OR_B21_B26_UNSET_LOW_16_Relocation},
        {R_VPU_HIGH_27_BIT_OR, VPU_HIGH_27_BIT_OR_Relocation},
        {R_VPU_32_OR_LO_19_LSB_21_RSHIFT_2, VPU_32_OR_LO_19_LSB_21_RSHIFT_2_Relocation}};

const std::unordered_map<VPUXLoader::RelocationType, VPUXLoader::DmaRelocationFunc> VPUXLoader::dmaRelocationMap = {
        {R_VPU_DMA_TASK_INPUT, relocations::dmaTaskInputRelocation},
        {R_VPU_DMA_TASK_OUTPUT, relocations::dmaTaskOutputRelocation}};

VPUXLoader::VPUXLoader(AccessManager* accessor, BufferManager* bufferManager)
        : m_inferBufferContainer(bufferManager),
          m_backupBufferContainer(bufferManager),
          m_relocationSectionIndexes(std::make_shared<std::vector<std::size_t>>()),
          m_jitRelocations(std::make_shared<std::vector<std::size_t>>()),
          m_userInputsDescriptors(std::make_shared<std::vector<DeviceBuffer>>()),
          m_userOutputsDescriptors(std::make_shared<std::vector<DeviceBuffer>>()),
          m_profOutputsDescriptors(std::make_shared<std::vector<DeviceBuffer>>()),
          m_loaded(false),
          m_inferencesMayBeRunInParallel(true) {
    VPUX_ELF_THROW_UNLESS(bufferManager, ArgsError, "Invalid BufferManager pointer");
    m_bufferManager = bufferManager;
    m_reader = std::make_shared<Reader<ELF_Bitness::Elf64>>(m_bufferManager, accessor);
    m_sectionMap = std::make_shared<std::map<elf::Elf_Word /*section type*/, std::vector<size_t>>>();

    VPUX_ELF_LOG(LogLevel::LOG_TRACE, "Initializing... Register sections");
    auto numSections = m_reader->getSectionsNum();
    for (size_t sectionCtr = 0; sectionCtr < numSections; ++sectionCtr) {
        auto section = m_reader->getSection(sectionCtr);
        auto sectionType = section.getHeader()->sh_type;

        (*m_sectionMap)[sectionType].emplace_back(sectionCtr);
        VPUX_ELF_LOG(LogLevel::LOG_DEBUG, "[%lu] Section name: %s", sectionCtr, section.getName());

        // Early fetch of IO buffer specs
        const auto action = actionMap.find(sectionType);
        if (action == actionMap.end()) {
            if (sectionType >= elf::SHT_LOUSER && sectionType <= elf::SHT_HIUSER) {
                VPUX_ELF_LOG(LogLevel::LOG_WARN, "Unrecognized Section Type in User range %x", sectionType);
            } else {
                VPUX_ELF_THROW(ImplausibleState, "Unrecognized Section Type outside of User range");
            }
        } else if (action->second == Action::RegisterUserIO) {
            earlyFetchIO(section);
        }
    }

    // accomodate missing section due to compatibility with older ELFs
    if (m_sectionMap->find(elf::VPU_SHT_PERF_METRICS) == m_sectionMap->end()) {
        (*m_sectionMap)[elf::VPU_SHT_PERF_METRICS] = {};
    }
};

VPUXLoader::VPUXLoader(const VPUXLoader& other)
        : m_bufferManager(other.m_bufferManager),
          m_reader(other.m_reader),
          m_inferBufferContainer(other.m_inferBufferContainer),
          m_backupBufferContainer(other.m_backupBufferContainer),
          m_runtimeSymTabs(other.m_runtimeSymTabs),
          m_relocationSectionIndexes(other.m_relocationSectionIndexes),
          m_jitRelocations(other.m_jitRelocations),
          m_userInputsDescriptors(other.m_userInputsDescriptors),
          m_userOutputsDescriptors(other.m_userOutputsDescriptors),
          m_profOutputsDescriptors(other.m_profOutputsDescriptors),
          m_sectionMap(other.m_sectionMap),
          m_explicitAllocations(other.m_explicitAllocations),
          m_loaded(other.m_loaded),
          m_symbolSectionTypes(other.m_symbolSectionTypes),
          m_inferencesMayBeRunInParallel(other.m_inferencesMayBeRunInParallel),
          m_sharedScratchBuffers(other.m_sharedScratchBuffers),
          m_scratchRelocations(other.m_scratchRelocations) {
    reloadNewBuffers();
    applyRelocations(*m_relocationSectionIndexes);
}

// override the symbol table for the newly created loader
VPUXLoader::VPUXLoader(const VPUXLoader& other, const std::vector<SymbolEntry>& runtimeSymTabs)
        : m_bufferManager(other.m_bufferManager),
          m_reader(other.m_reader),
          m_inferBufferContainer(other.m_inferBufferContainer),
          m_backupBufferContainer(other.m_backupBufferContainer),
          m_runtimeSymTabs(runtimeSymTabs),
          m_relocationSectionIndexes(other.m_relocationSectionIndexes),
          m_jitRelocations(other.m_jitRelocations),
          m_userInputsDescriptors(other.m_userInputsDescriptors),
          m_userOutputsDescriptors(other.m_userOutputsDescriptors),
          m_profOutputsDescriptors(other.m_profOutputsDescriptors),
          m_sectionMap(other.m_sectionMap),
          m_explicitAllocations(other.m_explicitAllocations),
          m_loaded(other.m_loaded),
          m_symbolSectionTypes(other.m_symbolSectionTypes),
          m_inferencesMayBeRunInParallel(other.m_inferencesMayBeRunInParallel),
          m_sharedScratchBuffers(other.m_sharedScratchBuffers),
          m_scratchRelocations(other.m_scratchRelocations) {
    reloadNewBuffers();
    applyRelocations(*m_relocationSectionIndexes);
}

VPUXLoader& VPUXLoader::operator=(const VPUXLoader& other) {
    if (this == &other) {
        return *this;
    }

    m_bufferManager = other.m_bufferManager;
    m_reader = other.m_reader;
    m_inferBufferContainer = other.m_inferBufferContainer;
    m_backupBufferContainer = other.m_backupBufferContainer;
    m_runtimeSymTabs = other.m_runtimeSymTabs;
    m_relocationSectionIndexes = other.m_relocationSectionIndexes;
    m_jitRelocations = other.m_jitRelocations;
    m_userInputsDescriptors = other.m_userInputsDescriptors;
    m_userOutputsDescriptors = other.m_userOutputsDescriptors;
    m_profOutputsDescriptors = other.m_profOutputsDescriptors;
    m_explicitAllocations = other.m_explicitAllocations;
    m_symbolSectionTypes = other.m_symbolSectionTypes;
    m_sectionMap = other.m_sectionMap;
    m_loaded = other.m_loaded;
    m_inferencesMayBeRunInParallel = other.m_inferencesMayBeRunInParallel;
    m_sharedScratchBuffers = other.m_sharedScratchBuffers;
    m_scratchRelocations = other.m_scratchRelocations;

    reloadNewBuffers();
    applyRelocations(*m_relocationSectionIndexes);

    return *this;
}

VPUXLoader::~VPUXLoader() {
}

elf::DeviceBufferContainer::BufferPtr VPUXLoader::getEntry() {
    auto numSections = m_reader->getSectionsNum();

    for (size_t sectionCtr = 0; sectionCtr < numSections; ++sectionCtr) {
        const auto& section = m_reader->getSection(sectionCtr);

        auto hdr = section.getHeader();
        if (hdr->sh_type == elf::SHT_SYMTAB) {
            auto symTabsSize = section.getEntriesNum();
            auto symTabs = section.getData<elf::SymbolEntry>();

            for (size_t symTabIdx = 0; symTabIdx < symTabsSize; ++symTabIdx) {
                auto& symTab = symTabs[symTabIdx];
                auto symType = elf64STType(symTab.st_info);
                if (symType == VPU_STT_ENTRY) {
                    auto secIndx = symTab.st_shndx;
                    return m_inferBufferContainer.getBufferInfoFromIndex(secIndx).mBuffer;
                }
            }
        }
    }

    VPUX_ELF_THROW(ImplausibleState, "Can not continue without entry!");
    return {};
}

void VPUXLoader::load(const std::vector<SymbolEntry>& runtimeSymTabs, bool,
                      const std::vector<elf::Elf_Word>& symbolSectionTypes, bool explicitAllocations) {
    VPUX_ELF_THROW_WHEN(m_loaded, SequenceError, "Sections were previously loaded.");

    m_runtimeSymTabs = runtimeSymTabs;
    m_symbolSectionTypes = symbolSectionTypes;
    m_explicitAllocations = explicitAllocations;

    VPUX_ELF_LOG(LogLevel::LOG_TRACE, "Starting LOAD process");
    auto numSections = m_reader->getSectionsNum();

    m_relocationSectionIndexes->reserve(numSections);
    m_jitRelocations->reserve(2);

    VPUX_ELF_LOG(LogLevel::LOG_DEBUG, "Got elf with %zu sections", numSections);
    for (size_t sectionCtr = 0; sectionCtr < numSections; ++sectionCtr) {
        VPUX_ELF_LOG(LogLevel::LOG_DEBUG, "Solving section %zu", sectionCtr);

        const auto& section = m_reader->getSection(sectionCtr);

        const auto sectionHeader = section.getHeader();
        auto sectionType = sectionHeader->sh_type;
        auto searchAction = actionMap.find(sectionType);
        auto action = Action::None;

        if (searchAction == actionMap.end()) {
            if (sectionType >= elf::SHT_LOUSER && sectionType <= elf::SHT_HIUSER) {
                VPUX_ELF_LOG(LogLevel::LOG_WARN, "Unrecognized Section Type in User range %x", sectionType);
            } else {
                VPUX_ELF_THROW(ImplausibleState, "Unrecognized Section Type outside of User range");
            }
        } else {
            action = searchAction->second;
        }

        auto sectionFlags = sectionHeader->sh_flags;

        VPUX_ELF_LOG(LogLevel::LOG_DEBUG, "    name  : %s", section.getName());
        VPUX_ELF_LOG(LogLevel::LOG_DEBUG, "    type  : %u", sectionType);
        VPUX_ELF_LOG(LogLevel::LOG_DEBUG, "    flags : 0x%llx", sectionFlags);
        VPUX_ELF_LOG(LogLevel::LOG_DEBUG, "    action: %u", (uint32_t)action);

        switch (action) {
        case Action::AllocateAndLoad: {
            bool isAllocateable = sectionFlags & SHF_ALLOC;
            if (m_explicitAllocations && !isAllocateable) {
                break;
            }

            VPUX_ELF_LOG(LogLevel::LOG_TRACE, "Allocate and loading %zu", sectionCtr);

            // Shared condition:
            //  1. has data
            //  2. is read only
            //  3. not target of a relocation section
            //
            // Condition 1 is fulfilled by entering this case
            // Condition 2 can be checked here
            // Condition 3 needs to be checked after all relocation sections have been registered in order to be
            // independent from the sections order inside the ELF binary

            auto& inferBufferInfo = m_inferBufferContainer.safeInitBufferInfoAtIndex(sectionCtr);
            inferBufferInfo.mBufferDetails.mHasData = true;

            // The information about write access from an NPU core to a section buffer is crucial to correctly share
            // section buffers between loader instances belonging to the same clone tree.
            //
            // Below are the possible states of a loader instance in a clone tree:
            //  - L0 created from blob X (root) - Is an original instance and can have cloned instances created from it,
            //  with which it will be able to share section buffers.
            //  - L1 cloned from L0 (node) - Is a cloned instance created from an original instance and can have cloned
            //  instances created from it. It may share section buffers with L0 and any future cloned instances created
            //  from L0 or itself.
            //  - L2 cloned from L1 (node) - Is a cloned instance created from another cloned instance and can have
            //  cloned instances created from it. It may share section buffers with L0 and L1 and any future cloned
            //  instances created from L0, L1 or itself.
            //  - L3 created from blob X (root) - Is the same as L0, but it is unrelated to the instances above in terms
            //  of buffers sharing, even though it was created from the same blob X.
            //
            // When we are executing this code, we are creating an original instance.
            //
            // The current implementation assumes all loader instances belonging to the same clone tree can run in
            // parallel, thus any writable section (see SHF_WRITE definition in section_header.hpp for details about the
            // meaning of writable) is considered not shareable with other loader instances.
            inferBufferInfo.mBufferDetails.mIsShared = sectionFlags & SHF_WRITE ? false : true;
            inferBufferInfo.mBufferDetails.mIsProcessed = false;

            VPUX_ELF_LOG(LogLevel::LOG_DEBUG, "\tLoaded section %s (address: %p, size: %llu)", section.getName(),
                         inferBufferInfo.mBuffer->getBuffer().cpu_addr(), inferBufferInfo.mBuffer->getBuffer().size());
            break;
        }

        case Action::Allocate: {
            bool isAllocateable = sectionFlags & SHF_ALLOC;
            if ((m_explicitAllocations && !isAllocateable) || utils::isNetworkIO(sectionFlags)) {
                break;
            }

            VPUX_ELF_LOG(LogLevel::LOG_TRACE, "Allocating %zu", sectionCtr);

            auto sectionSize = sectionHeader->sh_size;
            auto sectionAlignment = sectionHeader->sh_addralign;

            // Based on the SHF_WRITE definition (see details in section_header.hpp) in the ELF format and since the
            // format does not impose restrictions on using (i.e. setting) the flag together with different section
            // types, we must allow NOBITS sections with SHF_WRITE not set. Additionally, some "old" (e.g. PV) blobs may
            // contain NOBITS sections with no SHF_WRITE flag, so we are forced anyway to allow NOBITS sections with
            // SHF_WRITE not set in order to maintain compatibility.
            if ((sectionFlags & SHF_WRITE) == 0) {
                VPUX_ELF_LOG(LogLevel::LOG_TRACE, "Allocating \"%s\" with no SHF_WRITE", section.getName());
            }

            if (!m_inferencesMayBeRunInParallel) {
                sectionFlags |= elf::SHARABLE_BUFFER_ENABLED;
            }

            auto& inferBufferInfo = m_inferBufferContainer.safeInitBufferInfoAtIndex(sectionCtr);
            inferBufferInfo.mBuffer = m_inferBufferContainer.buildAllocatedDeviceBuffer(
                    BufferSpecs(sectionAlignment, sectionSize, sectionFlags));

            if (inferBufferInfo.mBuffer->getBuffer().vpu_addr() == 0) {
                // driver did share scratch and returned empty allocation
                // that is to be updated later
                m_sharedScratchBuffers.push_back(sectionCtr);
            }

            inferBufferInfo.mBufferDetails.mHasData = false;
            inferBufferInfo.mBufferDetails.mIsShared = false;
            inferBufferInfo.mBufferDetails.mIsProcessed = true;

            VPUX_ELF_LOG(LogLevel::LOG_DEBUG, "\tFor section %s Allocated %p of size %llu", section.getName(),
                         inferBufferInfo.mBuffer->getBuffer().cpu_addr(), sectionSize);
            break;
        }

        case Action::Relocate: {
            // Trigger read of section data so that after load completes the AccessManager object can
            // be safely deleted
            // note: do it for both JIT and non-JIT relocations as the latter maybe delayed to post-load
            // in case of scratch sharing enabled
            section.getData<void>();

            if (sectionFlags & VPU_SHF_JIT) {
                VPUX_ELF_LOG(LogLevel::LOG_DEBUG, "Registering JIT Relocation %zu", sectionCtr);
                m_jitRelocations->push_back(static_cast<int>(sectionCtr));
            } else {
                m_relocationSectionIndexes->push_back(static_cast<int>(sectionCtr));
                VPUX_ELF_LOG(LogLevel::LOG_DEBUG, "Registering Relocation %zu", sectionCtr);
            }
            break;
        }

        case Action::Error: {
            VPUX_ELF_THROW(SectionError, "Unexpected section type");
            return;
        }

        case Action::RegisterUserIO: {
            // Trigger read of section data so that after load completes the AccessManager object can
            // be safely deleted
            section.getData<void>();
            break;
        }
        case Action::None: {
            break;
        }

        default: {
            VPUX_ELF_THROW(ImplausibleState, "Unrecognized Section Type outside of User range");
            return;
        }
        }
    }

    // Now that all relocation sections are known, check shared condition 3
    updateSharedBuffers(*m_relocationSectionIndexes);
    updateSharedBuffers(*m_jitRelocations);

    // Load actual buffers for the first time
    loadBuffers();

    if (!m_sharedScratchBuffers.empty()) {
        cacheScratchRelocations();
    }

    applyRelocations(*m_relocationSectionIndexes);

    VPUX_ELF_LOG(LogLevel::LOG_INFO, "Allocated %zu sections", m_inferBufferContainer.getBufferInfoCount());

    // sections were loaded. other calls to this method will throw an error
    m_loaded = true;

    return;
}

void VPUXLoader::cacheScratchRelocations() {
    m_scratchRelocations = std::make_shared<std::unordered_map<size_t, std::vector<size_t>>>();
    for (const auto& relocationSectionIdx : *m_relocationSectionIndexes) {
        const auto& relocSection = m_reader->getSection(relocationSectionIdx);
        auto relocations = relocSection.getData<elf::RelocationAEntry>();
        auto numRelocs = relocSection.getEntriesNum();

        auto relocSecHdr = relocSection.getHeader();

        Elf_Word targetSectionIdx = 0;
        auto relocSecFlags = relocSecHdr->sh_flags;
        if (relocSecFlags & SHF_INFO_LINK) {
            targetSectionIdx = relocSecHdr->sh_info;
        } else {
            VPUX_ELF_THROW(RelocError, "Rela section with no target section");
        }

        VPUX_ELF_THROW_WHEN(targetSectionIdx == 0 || targetSectionIdx > m_reader->getSectionsNum(), RelocError,
                            "invalid target section from rela section");

        const auto isTargetSharedScratch = std::find(m_sharedScratchBuffers.begin(), m_sharedScratchBuffers.end(),
                                                     targetSectionIdx) != m_sharedScratchBuffers.end();

        auto symTabIdx = relocSecHdr->sh_link;

        auto getSymTab = [&](size_t& symTabEntries) -> const SymbolEntry* {
            if (symTabIdx == VPU_RT_SYMTAB) {
                return m_runtimeSymTabs.data();
            }

            const auto& symTabSection = m_reader->getSection(symTabIdx);
            auto symTabSectionHdr = symTabSection.getHeader();
            symTabEntries = symTabSection.getEntriesNum();

            VPUX_ELF_THROW_UNLESS(checkSectionType(symTabSectionHdr, elf::SHT_SYMTAB), RelocError,
                                  "Reloc section pointing to snon-symtab");

            return symTabSection.getData<elf::SymbolEntry>();
        };

        size_t symTabEntries = 0;
        auto symTabs = getSymTab(symTabEntries);

        for (size_t relocIdx = 0; relocIdx < numRelocs; ++relocIdx) {
            const elf::RelocationAEntry& relocation = relocations[relocIdx];
            auto relSymIdx = elf64RSym(relocation.r_info);
            elf::SymbolEntry targetSymbol = symTabs[relSymIdx];
            auto symbolTargetSectionIdx = targetSymbol.st_shndx;

            const auto isSymbolSharedScratch = std::find(m_sharedScratchBuffers.begin(), m_sharedScratchBuffers.end(),
                                                         symbolTargetSectionIdx) != m_sharedScratchBuffers.end();

            auto relType = elf64RType(relocation.r_info);
            if (isSymbolSharedScratch || isTargetSharedScratch) {
                // check if all scratch based relocations are R_VPU_64 or R_VPU_32
                // R_VPU_64/32 are "pure" relocations and don't require target buffer reloading
                // because they don't depend on content of target before execution
                // we rely on that in updateSharedScratchBuffers by not reloading buffers
                // before triggering relocations
                VPUX_ELF_THROW_WHEN(
                        static_cast<elf::VPUXLoader::RelocationType>(relType) != R_VPU_64 &&
                                static_cast<elf::VPUXLoader::RelocationType>(relType) != R_VPU_32,
                        RelocError,
                        "Encountered relocation type that is neither R_VPU_64, nor R_VPU_32 based on scratch");
                (*m_scratchRelocations)[relocationSectionIdx].push_back(relocIdx);
            }
        }
    }
}

void VPUXLoader::updateSharedBuffers(const std::vector<std::size_t>& relocationSectionIndexes) {
    VPUX_ELF_LOG(LogLevel::LOG_TRACE, "Update shared buffers");

    // First, exclude all relocation targets from shared pool
    for (const auto& relocationSectionIdx : relocationSectionIndexes) {
        const auto& relocSection = m_reader->getSection(relocationSectionIdx);
        const auto relocSecHdr = relocSection.getHeader();
        const auto relocSecFlags = relocSecHdr->sh_flags;
        Elf_Word targetSectionIdx;
        if (relocSecFlags & SHF_INFO_LINK) {
            targetSectionIdx = relocSecHdr->sh_info;
        } else {
            VPUX_ELF_THROW(RelocError, "Rela section with no target section");
            return;
        }
        VPUX_ELF_LOG(LogLevel::LOG_TRACE, "Processing buffer for section %zu", targetSectionIdx);
        VPUX_ELF_THROW_WHEN(targetSectionIdx == 0 || targetSectionIdx > m_reader->getSectionsNum(), RelocError,
                            "invalid target section from rela section");

        // Line below should throw if buffer container does not have by this point a valid buffer associated with the
        // target relocation section
        auto& inferBufferInfo = m_inferBufferContainer.getBufferInfoFromIndex(targetSectionIdx);

        if (!inferBufferInfo.mBufferDetails.mIsProcessed) {
            inferBufferInfo.mBufferDetails.mIsShared = false;
        } else {
            VPUX_ELF_LOG(LogLevel::LOG_TRACE, "Buffer for section %zu is already processed", targetSectionIdx);
        }
    }
}

void VPUXLoader::loadBuffers() {
    // Now actually create and load buffers
    for (auto& elem : m_inferBufferContainer) {
        auto bufferIndex = elem.first;
        auto& bufferInfo = elem.second;

        if (!bufferInfo.mBufferDetails.mIsProcessed) {
            auto& section = m_reader->getSection(bufferIndex);

            if (bufferInfo.mBufferDetails.mIsShared) {
                bufferInfo.mBuffer = m_reader->getSection(bufferIndex).getDataBuffer();
            } else {
                // Initialize backup buffer info
                auto& backupBufferInfo = m_backupBufferContainer.safeInitBufferInfoAtIndex(bufferIndex);

                // Get actual backup buffer with CPU-only access
                backupBufferInfo.mBuffer = m_reader->getSection(bufferIndex).getDataBuffer(true);
                auto backupBufferLock = ElfBufferLockGuard(backupBufferInfo.mBuffer.get());
                // Explicitly allocate a new NPU-access buffer
                auto bufferSpecs = backupBufferInfo.mBuffer->getBufferSpecs();
                bufferSpecs.procFlags = section.getHeader()->sh_flags;
                bufferInfo.mBuffer = m_inferBufferContainer.buildAllocatedDeviceBuffer(bufferSpecs);

                const auto backupSize = backupBufferInfo.mBuffer->getBuffer().size();
                const auto inferSize = bufferInfo.mBuffer->getBuffer().size();

                VPUX_ELF_THROW_UNLESS(backupSize <= inferSize, RuntimeError,
                                      "Mismatch between section backup size and allocated device buffer size");

                // Copy data from backup to infer buffer
                bufferInfo.mBuffer->loadWithLock(backupBufferInfo.mBuffer->getBuffer().cpu_addr(),
                                                 backupBufferInfo.mBuffer->getBuffer().size());

                backupBufferInfo.mBufferDetails.mHasData = true;
                backupBufferInfo.mBufferDetails.mIsShared = true;
                backupBufferInfo.mBufferDetails.mIsProcessed = true;
            }

            bufferInfo.mBufferDetails.mIsProcessed = true;
        }
    }
}

void VPUXLoader::reloadNewBuffers() {
    for (const auto& buffer : m_inferBufferContainer) {
        auto& sectionIndex = buffer.first;
        auto& inferBufferInfo = buffer.second;
        if (inferBufferInfo.mBufferDetails.mHasData && !inferBufferInfo.mBufferDetails.mIsShared) {
            auto& backupBufferInfo = m_backupBufferContainer.getBufferInfoFromIndex(sectionIndex);
            auto backupBufferLock = ElfBufferLockGuard(backupBufferInfo.mBuffer.get());

            const auto backupSize = backupBufferInfo.mBuffer->getBuffer().size();
            const auto inferSize = inferBufferInfo.mBuffer->getBuffer().size();

            VPUX_ELF_THROW_UNLESS(backupSize <= inferSize, RuntimeError,
                                  "Mismatch between section backup size and allocated device buffer size");
            inferBufferInfo.mBuffer->loadWithLock(backupBufferInfo.mBuffer->getBuffer().cpu_addr(),
                                                  inferBufferInfo.mBuffer->getBuffer().size());
            VPUX_ELF_LOG(LogLevel::LOG_TRACE, "Loading with lock %llu bytes from %p to %p",
                         inferBufferInfo.mBuffer->getBuffer().size(), backupBufferInfo.mBuffer->getBuffer().cpu_addr(),
                         inferBufferInfo.mBuffer->getBuffer().cpu_addr());
        }
    }
}

void VPUXLoader::applyScratchRelocations() {
    VPUX_ELF_THROW_WHEN(m_scratchRelocations == nullptr, RelocError,
                        "Encountered an attempt to apply scratch relocations without corresponding cache");

    for (const auto& relocationSectionEntry : *m_scratchRelocations) {
        const auto& relocationSectionIdx = relocationSectionEntry.first;
        const auto& relocationEntriesIndexes = relocationSectionEntry.second;

        VPUX_ELF_LOG(LogLevel::LOG_DEBUG, "applying relocation section %u", relocationSectionIdx);

        const auto& relocSection = m_reader->getSection(relocationSectionIdx);
        auto relocations = relocSection.getData<elf::RelocationAEntry>();
        auto relocSecHdr = relocSection.getHeader();
        auto numRelocs = relocSection.getEntriesNum();

        VPUX_ELF_LOG(LogLevel::LOG_DEBUG, "\tRelA section with %zu elements at addr %p", numRelocs, relocations);
        VPUX_ELF_LOG(LogLevel::LOG_DEBUG, "\tRelA section info, link flags 0x%x %u 0x%llx", relocSecHdr->sh_info,
                     relocSecHdr->sh_link, relocSecHdr->sh_flags);

        // At this point we assume that all the section indexes passed to this method
        // are containing a section of sh_type == SHT_RELA. So, the sh_link
        // must point only to a section header index of the associated symbol table or to the reserved
        // symbol range of sections.
        auto symTabIdx = relocSecHdr->sh_link;
        VPUX_ELF_THROW_UNLESS((symTabIdx < m_reader->getSectionsNum() || (symTabIdx == VPU_RT_SYMTAB)), RangeError,
                              "sh_link exceeds the number of entries.")

        // by convention, we will assume symTabIdx==VPU_RT_SYMTAB to be the "built-in" symtab
        auto getSymTab = [&](size_t& symTabEntries) -> const SymbolEntry* {
            if (symTabIdx == VPU_RT_SYMTAB) {
                return m_runtimeSymTabs.data();
            }

            const auto& symTabSection = m_reader->getSection(symTabIdx);
            auto symTabSectionHdr = symTabSection.getHeader();
            symTabEntries = symTabSection.getEntriesNum();

            VPUX_ELF_THROW_UNLESS(checkSectionType(symTabSectionHdr, elf::SHT_SYMTAB), RelocError,
                                  "Reloc section pointing to snon-symtab");

            return symTabSection.getData<elf::SymbolEntry>();
        };

        size_t symTabEntries = 0;
        auto symTabs = getSymTab(symTabEntries);

        auto relocSecFlags = relocSecHdr->sh_flags;
        Elf_Word targetSectionIdx = 0;
        if (relocSecFlags & SHF_INFO_LINK) {
            targetSectionIdx = relocSecHdr->sh_info;
        } else {
            VPUX_ELF_THROW(RelocError, "Rela section with no target section");
            return;
        }

        VPUX_ELF_THROW_WHEN(targetSectionIdx == 0 || targetSectionIdx > m_reader->getSectionsNum(), RelocError,
                            "invalid target section from rela section");

        auto targetSection = m_reader->getSection(targetSectionIdx);

        // at this point we assume that all sections have an address, to which we can apply a simple lookup
        auto& targetSectionBuf = m_inferBufferContainer.getBufferInfoFromIndex(targetSectionIdx).mBuffer;
        auto targetSectionLock = ElfBufferLockGuard(targetSectionBuf.get());

        auto targetSectionAddr = targetSectionBuf->getBuffer().cpu_addr();
        VPUX_ELF_LOG(LogLevel::LOG_DEBUG, "Relocations are targeting section at addr %p named %s", targetSectionAddr,
                     targetSection.getName());

        // apply the actual relocations

        for (auto relocIdx : relocationEntriesIndexes) {
            const elf::RelocationAEntry& relocation = relocations[relocIdx];

            auto relOffset = relocation.r_offset;

            VPUX_ELF_THROW_UNLESS(relOffset < targetSectionBuf->getBuffer().size(), RelocError,
                                  "RelocOffset outside of the section size");

            auto relSymIdx = elf64RSym(relocation.r_info);

            // there are two types of relocation that can be suported at this point
            //    - special relocation that would use the runtime symbols
            // received from the user
            //    - relocations on the symbols defined in the symbol table inside the ELF file.
            // In this case the section has a specific number of entries (need to use the getEntriesNum method of
            // this section)
            VPUX_ELF_THROW_WHEN((relSymIdx > symTabEntries && symTabIdx != VPU_RT_SYMTAB) ||
                                        (relSymIdx > m_runtimeSymTabs.size() && symTabIdx == VPU_RT_SYMTAB),
                                RelocError, "SymTab index out of bounds!");

            auto relType = elf64RType(relocation.r_info);
            auto addend = relocation.r_addend;

            auto reloc = relocationMap.find(static_cast<RelocationType>(relType));
            VPUX_ELF_THROW_WHEN(reloc == relocationMap.end() || reloc->second == nullptr, RelocError,
                                "Invalid relocation type detected");

            auto relocFunc = reloc->second;

            // the actual data that we need to modify
            auto relocationTargetAddr = targetSectionAddr + relOffset;

            // deliberate copy so we don't modify the contents of the original elf.
            elf::SymbolEntry targetSymbol = symTabs[relSymIdx];
            auto symbolTargetSectionIdx = targetSymbol.st_shndx;

            uint64_t symValue = 0;
            symValue = m_inferBufferContainer.getBufferInfoFromIndex(symbolTargetSectionIdx)
                               .mBuffer->getBuffer()
                               .vpu_addr();
            VPUX_ELF_THROW_WHEN(symValue == 0, RelocError, "Relocation target section has no valid address");
            targetSymbol.st_value += symValue;

            VPUX_ELF_LOG(LogLevel::LOG_DEBUG, "\t\tApplying Relocation at offset %llu symidx %u reltype %u addend %llu",
                         relOffset, relSymIdx, relType, addend);

            relocFunc((void*)relocationTargetAddr, targetSymbol, addend);
        }
    }
}

void VPUXLoader::applyRelocations(const std::vector<std::size_t>& relocationSectionIndexes, bool onScratchUpdate) {
    if (onScratchUpdate) {
        applyScratchRelocations();
        return;
    }

    VPUX_ELF_LOG(LogLevel::LOG_TRACE, "apply relocations");

    // Iterate over all relocations sections
    for (const auto& relocationSectionIdx : relocationSectionIndexes) {
        VPUX_ELF_LOG(LogLevel::LOG_DEBUG, "applying relocation section %u", relocationSectionIdx);

        // Get relocation section from reader
        const auto& relocSection = m_reader->getSection(relocationSectionIdx);

        // Get pointer to first relocation entry in the section
        auto relocations = relocSection.getData<elf::RelocationAEntry>();
        auto relocSecHdr = relocSection.getHeader();
        auto numRelocs = relocSection.getEntriesNum();

        VPUX_ELF_LOG(LogLevel::LOG_DEBUG, "\tRelA section with %zu elements at addr %p", numRelocs, relocations);
        VPUX_ELF_LOG(LogLevel::LOG_DEBUG, "\tRelA section info, link flags 0x%x %u 0x%llx", relocSecHdr->sh_info,
                     relocSecHdr->sh_link, relocSecHdr->sh_flags);

        // At this point we assume that all the section indexes passed to this method
        // are containing a section of sh_type == SHT_RELA. So, the sh_link
        // must point only to a section header index of the associated symbol table or to the reserved
        // symbol range of sections.
        auto symTabIdx = relocSecHdr->sh_link;
        VPUX_ELF_THROW_UNLESS((symTabIdx < m_reader->getSectionsNum() || (symTabIdx == VPU_RT_SYMTAB)), RangeError,
                              "sh_link exceeds the number of entries.")

        // By contract, we treat symTabIdx==VPU_RT_SYMTAB to be the "built-in" symtab
        auto getSymTab = [&](size_t& symTabEntries) -> const SymbolEntry* {
            if (symTabIdx == VPU_RT_SYMTAB) {
                return m_runtimeSymTabs.data();
            }

            const auto& symTabSection = m_reader->getSection(symTabIdx);
            auto symTabSectionHdr = symTabSection.getHeader();
            symTabEntries = symTabSection.getEntriesNum();

            VPUX_ELF_THROW_UNLESS(checkSectionType(symTabSectionHdr, elf::SHT_SYMTAB), RelocError,
                                  "Reloc section pointing to snon-symtab");

            return symTabSection.getData<elf::SymbolEntry>();
        };

        // Number of symbols in the symtab section (will be updated by getSymTab)
        size_t symTabEntries = 0;
        // Get pointer to first symbol and the number of symbols in the symtab
        auto symTabs = getSymTab(symTabEntries);
        VPUX_ELF_THROW_UNLESS(symTabs, RuntimeError, "nullptr received for SymbolEntry pointer");

        auto relocSecFlags = relocSecHdr->sh_flags;
        Elf_Word targetSectionIdx = 0;
        if (relocSecFlags & SHF_INFO_LINK) {
            targetSectionIdx = relocSecHdr->sh_info;
        } else {
            VPUX_ELF_THROW(RelocError, "Rela section with no target section");
            return;
        }

        VPUX_ELF_THROW_WHEN(targetSectionIdx == 0 || targetSectionIdx > m_reader->getSectionsNum(), RelocError,
                            "Invalid target section from rela section");

        const auto isTargetSharedScratch = std::find(m_sharedScratchBuffers.begin(), m_sharedScratchBuffers.end(),
                                                     targetSectionIdx) != m_sharedScratchBuffers.end();

        if (!m_sharedScratchBuffers.empty() && isTargetSharedScratch) {
            continue;
        }

        // Fetching relocation target section just for its name as the actual buffer where the relocation will be
        // applied is fetched from the inference buffer container
        auto targetSection = m_reader->getSection(targetSectionIdx);

        // At this point all sections than need to be NPU-accessible must have an associated inference buffer, so look
        // for it in the inference buffer container. Exception from this rule is currently the scratch section, which is
        // handled separately.
        auto& targetSectionBuf = m_inferBufferContainer.getBufferInfoFromIndex(targetSectionIdx).mBuffer;
        auto targetSectionLock = ElfBufferLockGuard(targetSectionBuf.get());

        auto targetSectionAddr = targetSectionBuf->getBuffer().cpu_addr();
        VPUX_ELF_LOG(LogLevel::LOG_DEBUG, "Relocations are targeting section at addr %p named %s", targetSectionAddr,
                     targetSection.getName());

        // Loop over all relocations in the current relocation section
        for (size_t relocIdx = 0; relocIdx < numRelocs; ++relocIdx) {
            const elf::RelocationAEntry& relocation = relocations[relocIdx];

            // Offset within the target section buffer (i.e. where to apply relocation)
            auto relOffset = relocation.r_offset;

            VPUX_ELF_THROW_UNLESS(relOffset < targetSectionBuf->getBuffer().size(), RelocError,
                                  "RelocOffset outside of the section size");

            // Index of symbol in the symtab
            auto relSymIdx = elf64RSym(relocation.r_info);

            // there are two types of relocation that can be suported at this point
            //    - special relocation that would use the runtime symbols
            // received from the user
            //    - relocations on the symbols defined in the symbol table inside the ELF file.
            // In this case the section has a specific number of entries (need to use the getEntriesNum method of
            // this section)
            VPUX_ELF_THROW_WHEN((relSymIdx > symTabEntries && symTabIdx != VPU_RT_SYMTAB) ||
                                        (relSymIdx > m_runtimeSymTabs.size() && symTabIdx == VPU_RT_SYMTAB),
                                RelocError, "SymTab index out of bounds!");

            auto relType = elf64RType(relocation.r_info);
            auto addend = relocation.r_addend;

            auto reloc = relocationMap.find(static_cast<RelocationType>(relType));
            VPUX_ELF_THROW_WHEN(reloc == relocationMap.end() || reloc->second == nullptr, RelocError,
                                "Invalid relocation type detected");

            auto relocFunc = reloc->second;

            // The actual address that we need to modify
            auto relocationTargetAddr = targetSectionAddr + relOffset;

            // Deliberate copy so we don't modify the contents of the original elf.
            elf::SymbolEntry targetSymbol = symTabs[relSymIdx];
            // Index of the section targeted by this symbol
            auto symbolTargetSectionIdx = targetSymbol.st_shndx;

            if (!m_sharedScratchBuffers.empty()) {
                const auto isSymbolSharedScratch =
                        std::find(m_sharedScratchBuffers.begin(), m_sharedScratchBuffers.end(),
                                  symbolTargetSectionIdx) != m_sharedScratchBuffers.end();

                if (isSymbolSharedScratch) {
                    // It is shared scratch enabled and we are not triggered from updateScratchSharedBuffers
                    // so scratch address is not known yet and corresponding relocations must be skipped
                    continue;
                }
            }

            uint64_t symValue = 0;
            // Check first if the symbol targets one of the inference section buffers
            if (m_inferBufferContainer.hasBufferInfoAtIndex(symbolTargetSectionIdx)) {
                // Yes, initialize symValue with the base address of the section buffer
                symValue = m_inferBufferContainer.getBufferInfoFromIndex(symbolTargetSectionIdx)
                                   .mBuffer->getBuffer()
                                   .vpu_addr();
                VPUX_ELF_THROW_WHEN(symValue == 0, RelocError, "Relocation target section has no valid address");
            }

            // Dispatch between different relocation scenarios:
            // 1. regular relocation
            // 2. relocation using special symtab
            //      In this scenario, the symbol is located in a special symtab that needs to be supplied to the loader
            //      by its user.
            // 3. relocation using symtab override mode
            //      In this scenario, the symbol is located in an ordinary symtab that is part of the blob, but the
            //      symbol references a section from the blob which was not and/or cannot be allocated by the loader
            //      (e.g. a CMX section). A list of section types together with a corresponding list of symtabs needs to
            //      be supplied to the loader by its user and the loader will use the first symbol from the symtab
            //      corresponding to the section type of the symbol target section to override the symbol from the blob.
            if (symValue || symTabIdx == VPU_RT_SYMTAB) {
                // This is the branch handling normal relocations or relocations using the special symtab.
                targetSymbol.st_value += symValue;
            } else {
                // This is the branch handling symtab override mode.
                VPUX_ELF_THROW_UNLESS(m_symbolSectionTypes.size() > 0 && m_runtimeSymTabs.size() > 0 &&
                                              m_symbolSectionTypes.size() == m_runtimeSymTabs.size(),
                                      RuntimeError, "Invalid runtime symbols configuration");

                auto sectionType = m_reader->getSection(symbolTargetSectionIdx).getHeader()->sh_type;

                size_t index = 0;
                for (; index < m_symbolSectionTypes.size(); ++index) {
                    if (m_symbolSectionTypes[index] == sectionType) {
                        break;
                    }
                }

                VPUX_ELF_THROW_UNLESS(index < m_symbolSectionTypes.size(), RuntimeError,
                                      "Could not find section buffer where the current symbol is located");

                targetSymbol = m_runtimeSymTabs[index];
            }

            VPUX_ELF_LOG(LogLevel::LOG_DEBUG, "\t\tApplying Relocation at offset %llu symidx %u reltype %u addend %llu",
                         relOffset, relSymIdx, relType, addend);

            relocFunc((void*)relocationTargetAddr, targetSymbol, addend);
        }
    }
}

template <typename SymbolType, typename SectionType, typename ResolveSymbolFunc, typename RelocateFunc>
void VPUXLoader::applyRelocations(SectionType& relocSection, SectionType& symbolSection,
                                            std::vector<DeviceBuffer>& ioBuffers, uint8_t* targetSectionPtr,
                                            size_t targetSectionSize, ResolveSymbolFunc resolveSymbol,
                                            RelocateFunc relocate) {
    auto relocations = relocSection.template getData<elf::RelocationAEntry>();
    auto numRelocs = relocSection.getEntriesNum();
    auto symbols = symbolSection.template getData<SymbolType>();
    auto numSymbols = symbolSection.getEntriesNum();

    // apply the actual relocations
    for (size_t relocIdx = 0; relocIdx < numRelocs; ++relocIdx) {
        VPUX_ELF_LOG(LogLevel::LOG_DEBUG, "\t Solving Reloc at %p %zu", relocations, relocIdx);

        const auto& relocation = relocations[relocIdx];

        auto relOffset = relocation.r_offset;

        VPUX_ELF_THROW_UNLESS(relOffset < targetSectionSize, RelocError, "RelocOffset outside of the section size");

        SymbolType resolvedSymbol;

        auto symIdx = elf64RSym(relocation.r_info);

        VPUX_ELF_THROW_UNLESS(symIdx < numSymbols, RelocError, "SymTab index out of bounds!");

        resolvedSymbol = symbols[symIdx];
        resolveSymbol(resolvedSymbol, symIdx, ioBuffers);

        auto relType = elf64RType(relocation.r_info);
        auto addend = relocation.r_addend;

        VPUX_ELF_LOG(LogLevel::LOG_DEBUG, "\t\t applying Reloc offset symidx reltype addend %llu %u %u %llu", relOffset,
                     symIdx, relType, addend);

        auto targetAddr = targetSectionPtr + relOffset;

        VPUX_ELF_LOG(LogLevel::LOG_DEBUG, "\t targetsectionAddr %p offs %llu result %p symIdx %u", targetSectionPtr,
                     relOffset, targetAddr, symIdx);

        relocate(static_cast<VPUXLoader::RelocationType>(relType), (void*)targetAddr, resolvedSymbol, addend);
    }
}

void VPUXLoader::applyJitRelocations(std::vector<DeviceBuffer>& inputs, std::vector<DeviceBuffer>& outputs,
                                     std::vector<DeviceBuffer>& profiling) {
    VPUX_ELF_LOG(LogLevel::LOG_TRACE, "apply JITrelocations");

    for (const auto& relocationSectionIdx : *m_jitRelocations) {
        VPUX_ELF_LOG(LogLevel::LOG_DEBUG, "\tapplying JITrelocation section %u", relocationSectionIdx);

        const auto& relocSection = m_reader->getSection(relocationSectionIdx);
        auto relocSecHdr = relocSection.getHeader();

        VPUX_ELF_LOG(LogLevel::LOG_DEBUG, "\tJitRelA section info, link flags 0x%x %u 0x%llx", relocSecHdr->sh_info,
                     relocSecHdr->sh_link, relocSecHdr->sh_flags);

        // At this point we assume that all the section indexes passed to this method
        // are containing a section of sh_type == SHT_RELA. So, the sh_link
        // must point only to a section header index of the associated symbol table.
        auto symTabIdx = relocSecHdr->sh_link;
        VPUX_ELF_THROW_UNLESS(symTabIdx < m_reader->getSectionsNum(), RangeError,
                              "sh_link exceeds the number of entries.");

        // in JitRelocations case, we will expect to point to either "VPUX_USER_INPUT" or "VPUX_USER_INPUT" symtabs
        VPUX_ELF_THROW_WHEN(symTabIdx == VPU_RT_SYMTAB, RelocError, "JitReloc pointing to runtime symtab idx");

        const auto& symTabSection = m_reader->getSection(symTabIdx);

        auto relocSecFlags = relocSecHdr->sh_flags;

        auto getUserAddrs = [&]() -> std::vector<DeviceBuffer> {
            if (relocSecFlags & VPU_SHF_USERINPUT) {
                return std::vector<DeviceBuffer>(inputs);
            } else if (relocSecFlags & VPU_SHF_USEROUTPUT) {
                return std::vector<DeviceBuffer>(outputs);
            } else if (relocSecFlags & VPU_SHF_PROFOUTPUT) {
                return std::vector<DeviceBuffer>(profiling);
            } else {
                VPUX_ELF_THROW(RelocError, "Jit reloc section pointing neither to userInput nor userOutput");
                return std::vector<DeviceBuffer>(outputs);
            }
        };

        auto userAddrs = getUserAddrs();

        Elf_Word targetSectionIdx = 0;
        if (relocSecFlags & SHF_INFO_LINK) {
            targetSectionIdx = relocSecHdr->sh_info;
        } else {
            VPUX_ELF_THROW(RelocError, "Rela section with no target section");
            return;
        }

        // at this point we assume that all sections have an address, to which we can apply a simple lookup
        auto targetSectionBuf = m_inferBufferContainer.getBufferInfoFromIndex(targetSectionIdx).mBuffer;
        auto targetSectionLock = ElfBufferLockGuard(targetSectionBuf.get());

        auto targetSectionAddr = targetSectionBuf->getBuffer().cpu_addr();
        auto targetSectionSize = targetSectionBuf->getBuffer().size();

        VPUX_ELF_LOG(LogLevel::LOG_DEBUG, "\t targetSectionAddr %p", targetSectionAddr);

        if (checkSectionType(symTabSection.getHeader(), elf::SHT_SYMTAB)) {
            auto resolveRuntimeSymbol = [](elf::SymbolEntry& symbol, uint32_t symIdx,
                                           std::vector<DeviceBuffer>& ioBuffers) {
                symbol.st_value = ioBuffers[symIdx - 1].vpu_addr();
            };

            auto applyRelocation = [](RelocationType type, void* targetAddr, elf::SymbolEntry& resolvedSymbol,
                                      Elf_Sxword addend) {
                auto reloc = relocationMap.find(static_cast<VPUXLoader::RelocationType>(type));
                VPUX_ELF_THROW_WHEN(reloc == relocationMap.end() || reloc->second == nullptr, RelocError,
                                    "Invalid relocation type detected");
                auto relocFunc = reloc->second;

                relocFunc((void*)targetAddr, resolvedSymbol, addend);
            };

            applyRelocations<elf::SymbolEntry>(relocSection, symTabSection, userAddrs, targetSectionAddr,
                                                         targetSectionSize, std::move(resolveRuntimeSymbol),
                                                         std::move(applyRelocation));
        } else if (checkSectionType(symTabSection.getHeader(), elf::VPU_SHT_DMA_SYMBOLS)) {
            auto resolveDmaSymbol = [](elf::DmaSymbolEntry& symbol, uint32_t, std::vector<DeviceBuffer>& ioBuffers) {
                auto bufferIdx = symbol.ioIndex;
                symbol.address = ioBuffers[bufferIdx].vpu_addr();
                auto ioBufferUserStrides = ioBuffers[bufferIdx].get_user_stride();
                if (ioBufferUserStrides.has_value()) {
                    VPUX_ELF_THROW_UNLESS(sizeof(ioBufferUserStrides.value()) <= sizeof(symbol.dmaStrides), RelocError,
                                        "Mismatch between symbol DMA strides and user strides");
                    VPUX_ELF_THROW_UNLESS(sizeof(ioBufferUserStrides.value()) <= sizeof(symbol.strides), RelocError,
                                        "Mismatch between symbol strides and user strides");
                    std::memcpy(symbol.dmaStrides, ioBufferUserStrides.value().data(), sizeof(symbol.dmaStrides));
                    std::memcpy(symbol.strides, ioBufferUserStrides.value().data(), sizeof(symbol.strides));
                }
            };

            auto applyDmaRelocation = [](RelocationType type, void* targetAddr, elf::DmaSymbolEntry& resolvedSymbol,
                                         Elf_Sxword addend) {
                auto reloc = dmaRelocationMap.find(static_cast<VPUXLoader::RelocationType>(type));
                VPUX_ELF_THROW_WHEN(reloc == dmaRelocationMap.end() || reloc->second == nullptr, RelocError,
                                    "Invalid relocation type detected");
                auto relocFunc = reloc->second;

                relocFunc((void*)targetAddr, resolvedSymbol, addend);
            };

            applyRelocations<elf::DmaSymbolEntry>(relocSection, symTabSection, userAddrs, targetSectionAddr,
                                                            targetSectionSize, std::move(resolveDmaSymbol),
                                                            std::move(applyDmaRelocation));
        } else {
            VPUX_ELF_THROW(RelocError, "Relocation section references unknown symtab section format");
        }
    }
}

std::vector<DeviceBuffer> VPUXLoader::getAllocatedBuffers() const {
    return m_inferBufferContainer.getBuffersAsVector();
}

void VPUXLoader::registerUserIO(std::vector<DeviceBuffer>& userIO, const elf::SymbolEntry* symbols,
                                size_t symbolCount) const {
    if (symbolCount <= 1) {
        VPUX_ELF_LOG(LogLevel::LOG_WARN, "Have a USER_IO symbols section with no symbols");
        return;
    }

    userIO.resize(symbolCount - 1);

    // symbol sections always start with an UNDEFINED symbol by standard
    for (size_t symbolCtr = 1; symbolCtr < symbolCount; ++symbolCtr) {
        const elf::SymbolEntry& sym = symbols[symbolCtr];
        userIO[symbolCtr - 1] = DeviceBuffer(nullptr, 0, sym.st_size);
        VPUX_ELF_LOG(LogLevel::LOG_DEBUG, "\t index %zu : size %zu\n", symbolCtr - 1, sym.st_size);
    }
}

void VPUXLoader::earlyFetchIO(const elf::Reader<Elf64>::Section& section) {
    const auto sectionFlags = section.getHeader()->sh_flags;

    VPUX_ELF_LOG(LogLevel::LOG_DEBUG, "Parsed symtab section with flags %llx", sectionFlags);

    if (sectionFlags & VPU_SHF_USERINPUT) {
        VPUX_ELF_THROW_WHEN(m_userInputsDescriptors->size(), SequenceError,
                            "User inputs already read.... potential more than one input section?");

        VPUX_ELF_LOG(LogLevel::LOG_DEBUG, "\tRegistering %zu inputs", section.getEntriesNum() - 1);
        registerUserIO(*m_userInputsDescriptors, section.getData<elf::SymbolEntry>(), section.getEntriesNum());
    } else if (sectionFlags & VPU_SHF_USEROUTPUT) {
        VPUX_ELF_THROW_WHEN(m_userOutputsDescriptors->size(), SequenceError,
                            "User outputs already read.... potential more than one output section?");

        VPUX_ELF_LOG(LogLevel::LOG_DEBUG, "\tRegistering %zu outputs", section.getEntriesNum() - 1);
        registerUserIO(*m_userOutputsDescriptors, section.getData<elf::SymbolEntry>(), section.getEntriesNum());
    } else if (sectionFlags & VPU_SHF_PROFOUTPUT) {
        VPUX_ELF_THROW_WHEN(m_profOutputsDescriptors->size(), SequenceError,
                            "Profiling outputs already read.... potential more than one output section?");

        VPUX_ELF_LOG(LogLevel::LOG_DEBUG, "\tRegistering %zu prof outputs", section.getEntriesNum() - 1);
        registerUserIO(*m_profOutputsDescriptors, section.getData<elf::SymbolEntry>(), section.getEntriesNum());
    }
}

std::vector<DeviceBuffer> VPUXLoader::getInputBuffers() const {
    return *m_userInputsDescriptors.get();
};

std::vector<DeviceBuffer> VPUXLoader::getOutputBuffers() const {
    return *m_userOutputsDescriptors.get();
};

std::vector<DeviceBuffer> VPUXLoader::getProfBuffers() const {
    return *m_profOutputsDescriptors.get();
};

bool VPUXLoader::checkSectionType(const elf::SectionHeader* section, Elf_Word secType) const {
    return section->sh_type == secType;
}

std::vector<std::shared_ptr<ManagedBuffer>> VPUXLoader::getSectionsOfType(elf::Elf_Word type) {
    VPUX_ELF_THROW_WHEN(!utils::hasMemoryFootprint(type), elf::RuntimeError,
                        "Can't access data of NOBITS-like section");

    std::vector<std::shared_ptr<ManagedBuffer>> retVector;

    if (m_sectionMap->find(type) != m_sectionMap->end()) {
        for (auto sectionIndex : (*m_sectionMap)[type]) {
            auto sectionBuffer = m_reader->getSection(sectionIndex).getDataBuffer();
            retVector.push_back(sectionBuffer);
        }
    }

    return retVector;
};

void VPUXLoader::setInferencesMayBeRunInParallel(bool inferencesMayBeRunInParallel) {
    m_inferencesMayBeRunInParallel = inferencesMayBeRunInParallel;
}

bool VPUXLoader::getInferencesMayBeRunInParallel() const {
    return m_inferencesMayBeRunInParallel;
}

void VPUXLoader::updateSharedScratchBuffers(const std::vector<DeviceBuffer>& newBuffers) {
    VPUX_ELF_THROW_WHEN(m_sharedScratchBuffers.size() != newBuffers.size(), RuntimeError,
                        "Incorrect amount of buffers for updateSharedScratchBuffers");
    if (m_sharedScratchBuffers.empty()) {
        return;
    }

    size_t i = 0;
    bool changed = false;
    for (const auto& newBuffer : newBuffers) {
        const auto idx = m_sharedScratchBuffers[i++];
        auto& oldManagedBuffer = m_inferBufferContainer.getBufferInfoFromIndex(idx).mBuffer;
        if (newBuffer.vpu_addr() != oldManagedBuffer->getBuffer().vpu_addr()) {
            changed = true;
            oldManagedBuffer->resetBuffer(newBuffer);
        }
    }

    if (changed) {
        // don't reload buffers and rely on scratch relocations to be "pure"
        applyRelocations(*m_relocationSectionIndexes, true);
    }
}

}  // namespace elf
