//
// Copyright (C) 2023-2025 Intel Corporation
// SPDX-License-Identifier: Apache-2.0
//

#pragma once


#include <cstddef>

namespace elf {
/*
Abstraction class to encapsulate device addressing logic. We have 2 addresses, that specify the same physical location.
Object does not own any of the pointed regions
in memory, but from 2 different view-points
@cpu_addr - Defines cpu visible address, aka, the physical address that is visible from the host perspective.
        Any access to the contents that the "host" does, will use this address
@vpu_addr - defines the vpu visible address, aka, the physical address that is visible from device perspective.
        Any access to the contents that the "vpu" does, will use this address
*/

class DeviceBuffer {
public:
    DeviceBuffer()
        : m_cpuAddr(nullptr)
        , m_vpuAddr(0)
        , m_size(0){};

    DeviceBuffer(uint8_t *cpu_addr, uint64_t vpu_addr, size_t size)
        : m_cpuAddr(cpu_addr)
        , m_vpuAddr(vpu_addr)
        , m_size(size){};

    DeviceBuffer(const DeviceBuffer &other)
        : m_cpuAddr(other.m_cpuAddr)
        , m_vpuAddr(other.m_vpuAddr)
        , m_size(other.m_size){};

    DeviceBuffer(DeviceBuffer &&other)
        : m_cpuAddr(other.m_cpuAddr)
        , m_vpuAddr(other.m_vpuAddr)
        , m_size(other.m_size){};

    DeviceBuffer &operator=(const DeviceBuffer &other) {
        m_cpuAddr = other.m_cpuAddr;
        m_vpuAddr = other.m_vpuAddr;
        m_size = other.m_size;

        return *this;
    }

    DeviceBuffer &operator=(const DeviceBuffer &&other) {
        m_cpuAddr = other.m_cpuAddr;
        m_vpuAddr = other.m_vpuAddr;
        m_size = other.m_size;

        return *this;
    }

    ~DeviceBuffer() = default;

    uint8_t *cpu_addr() { return m_cpuAddr; }
    const uint8_t *cpu_addr() const { return m_cpuAddr; }
    uint64_t vpu_addr() const { return m_vpuAddr; }
    size_t size() const { return m_size; }

private:
    uint8_t *m_cpuAddr;
    uint64_t m_vpuAddr;
    size_t m_size;
};
} // namespace elf
