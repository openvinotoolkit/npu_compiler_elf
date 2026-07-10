//
// Copyright (C) 2026 Intel Corporation.
// SPDX-License-Identifier: Apache-2.0
//

#pragma once

#include <cstdlib>
#include <cstring>
#include <iostream>
#include <new>
#include <string_view>
#include <unordered_map>
#include <vector>

#include "vpux_elf/utils/error.hpp"
#include "vpux_elf/utils/utils.hpp"
#include "vpux_headers/buffer_manager.hpp"
#include "vpux_headers/buffer_specs.hpp"
#include "vpux_headers/device_buffer.hpp"

class NullAllocBufferManager : public elf::BufferManager {
    elf::DeviceBuffer allocate(const elf::BufferSpecs& buffSpecs) override;
    void deallocate(elf::DeviceBuffer& devAddress) override;
    void lock(elf::DeviceBuffer& devAddress) override;
    void unlock(elf::DeviceBuffer& devAddress) override;
    size_t copy(elf::DeviceBuffer& to, const uint8_t* from, size_t count) override;
};

class DummyBufferManager : public elf::BufferManager {
public:
    elf::DeviceBuffer allocate(const elf::BufferSpecs& buffSpecs) override;
    void deallocate(elf::DeviceBuffer& devBuffer) override;
    void lock(elf::DeviceBuffer& devBuffer) override;
    void unlock(elf::DeviceBuffer& devBuffer) override;
    size_t copy(elf::DeviceBuffer& to, const uint8_t* from, size_t count) override;
};

class HeapBufferManager : public elf::BufferManager {
public:
    struct AllocStats {
        size_t _currentTotalCount = 0;
        size_t _currentTotalSize = 0;
        size_t _totalCPUCount = 0;
        size_t _totalCPUSize = 0;
        size_t _totalNPUCount = 0;
        size_t _totalNPUSize = 0;
    };

    explicit HeapBufferManager(std::string_view name = "AnonymousBufferManager");

    HeapBufferManager(const HeapBufferManager& other) = delete;
    HeapBufferManager(HeapBufferManager&& other) = delete;

    HeapBufferManager operator=(const HeapBufferManager& rhs) = delete;
    HeapBufferManager operator=(HeapBufferManager&& rhs) = delete;

    ~HeapBufferManager() = default;

    elf::DeviceBuffer allocate(const elf::BufferSpecs& buffSpecs) override;
    void deallocate(elf::DeviceBuffer& devBuffer) override;
    void lock(elf::DeviceBuffer&) override;
    void unlock(elf::DeviceBuffer&) override;
    size_t copy(elf::DeviceBuffer& to, const uint8_t* from, size_t count) override;

    const AllocStats& getStats();
    void printAllocationStats();

private:
    std::string _name = {};
    AllocStats _allocStats = {};
    std::unordered_map<uint8_t*, uint64_t> _allocations = {};
};

class CountingBufferManager final : public elf::BufferManager {
public:
    elf::DeviceBuffer allocate(const elf::BufferSpecs& buffSpecs) override;
    void deallocate(elf::DeviceBuffer& devAddress) override;
    void lock(elf::DeviceBuffer& devAddress) override;
    void unlock(elf::DeviceBuffer& devAddress) override;
    size_t copy(elf::DeviceBuffer& to, const uint8_t* from, size_t count) override;

    int allocateCalls = 0;
    int deallocateCalls = 0;
    int lockCalls = 0;
    int unlockCalls = 0;
    int copyCalls = 0;

    elf::BufferSpecs lastRequestedSpecs = {};
    uint8_t* deallocatedCpuAddr = nullptr;
    std::vector<uint8_t> lastAllocation = {};
};

class BadAllocSizeBufferManager final : public elf::BufferManager {
public:
    elf::DeviceBuffer allocate(const elf::BufferSpecs& buffSpecs) override;
    void deallocate(elf::DeviceBuffer& devAddress) override;
    void lock(elf::DeviceBuffer& devAddress) override;
    void unlock(elf::DeviceBuffer& devAddress) override;
    size_t copy(elf::DeviceBuffer& to, const uint8_t* from, size_t count) override;

    elf::BufferSpecs lastRequested = {};
    std::vector<uint8_t> backing = {};
};
