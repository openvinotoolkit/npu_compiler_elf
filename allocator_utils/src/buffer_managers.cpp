//
// Copyright (C) 2026 Intel Corporation.
// SPDX-License-Identifier: Apache-2.0
//

#include "allocator_utils/buffer_managers.hpp"

using namespace elf;

// ----- NullAllocBufferManager -----

DeviceBuffer NullAllocBufferManager::allocate(const BufferSpecs& buffSpecs) {
    (void)buffSpecs;
    return DeviceBuffer();
}

void NullAllocBufferManager::deallocate(DeviceBuffer& devAddress) {
    (void)devAddress;
}

void NullAllocBufferManager::lock(DeviceBuffer& devAddress) {
    (void)devAddress;
}

void NullAllocBufferManager::unlock(DeviceBuffer& devAddress) {
    (void)devAddress;
}

size_t NullAllocBufferManager::copy(DeviceBuffer& to, const uint8_t* from, size_t count) {
    (void)to;
    (void)from;
    (void)count;
    return 0;
}

// ----- DummyBufferManager -----

DeviceBuffer DummyBufferManager::allocate(const BufferSpecs& buffSpecs) {
    auto addr = malloc(buffSpecs.size);
    return {reinterpret_cast<uint8_t*>(addr), reinterpret_cast<uint64_t>(addr), buffSpecs.size};
}

void DummyBufferManager::deallocate(DeviceBuffer& devBuffer) {
    free(reinterpret_cast<void*>(devBuffer.cpu_addr()));
}

void DummyBufferManager::lock(DeviceBuffer& devBuffer) {
    (void)devBuffer;
}

void DummyBufferManager::unlock(DeviceBuffer& devBuffer) {
    (void)devBuffer;
}

size_t DummyBufferManager::copy(DeviceBuffer& to, const uint8_t* from, size_t count) {
    memcpy(to.cpu_addr(), from, count);
    return count;
}

// ----- HeapBufferManager -----

HeapBufferManager::HeapBufferManager(std::string_view name): _name(name) {
}

DeviceBuffer HeapBufferManager::allocate(const BufferSpecs& buffSpecs) {
    auto ptr = static_cast<uint8_t*>(operator new[](sizeof(uint8_t) * buffSpecs.size,
                                                    static_cast<std::align_val_t>(buffSpecs.alignment)));
    VPUX_ELF_THROW_UNLESS(ptr, RuntimeError, "Allocation failure");
    _allocations[ptr] = buffSpecs.alignment;  // Store alignment for correct deallocation

    // All allocations have CPU VA
    auto cpuAddr = reinterpret_cast<uint8_t*>(ptr);
    // Only NPU allocations have NPU VA
    // Initializing to 0 could help early detection of faulty allocation logic from loader
    auto npuAddr = static_cast<uint64_t>(0);

    // Update statistics
    ++_allocStats._currentTotalCount;
    _allocStats._currentTotalSize += buffSpecs.size;
    if (utils::hasNPUAccess(buffSpecs.procFlags)) {
        npuAddr = reinterpret_cast<uint64_t>(ptr);

        ++_allocStats._totalNPUCount;
        _allocStats._totalNPUSize += buffSpecs.size;
    } else {
        ++_allocStats._totalCPUCount;
        _allocStats._totalCPUSize += buffSpecs.size;
    }

    return DeviceBuffer(cpuAddr, npuAddr, buffSpecs.size);
}

void HeapBufferManager::deallocate(DeviceBuffer& devBuffer) {
    auto buffAlignment = _allocations.find(devBuffer.cpu_addr());
    VPUX_ELF_THROW_WHEN(buffAlignment == _allocations.end(), RuntimeError, "Buffer not found in allocations");
    operator delete[](devBuffer.cpu_addr(), static_cast<std::align_val_t>(buffAlignment->second));
    _allocations.erase(buffAlignment);

    VPUX_ELF_THROW_WHEN(_allocStats._currentTotalSize < devBuffer.size(), RuntimeError,
                        "Freeing more memory than allocated");
    _allocStats._currentTotalSize -= devBuffer.size();
}

void HeapBufferManager::lock(DeviceBuffer&) {
}

void HeapBufferManager::unlock(DeviceBuffer&) {
}

size_t HeapBufferManager::copy(DeviceBuffer& to, const uint8_t* from, size_t count) {
    std::memcpy(to.cpu_addr(), from, count);
    return count;
}

const HeapBufferManager::AllocStats& HeapBufferManager::getStats() {
    return _allocStats;
}

void HeapBufferManager::printAllocationStats() {
    std::cout << "================================================================================\n";
    std::cout << _name << " allocation statistics:\n";
    std::cout << " - Current allocated size: " << _allocStats._currentTotalSize << " bytes in "
              << _allocStats._currentTotalCount << " buffers\n";
    std::cout << " - All-time CPU allocated size: " << _allocStats._totalCPUSize << " bytes in "
              << _allocStats._totalCPUCount << " buffers\n";
    std::cout << " - All-time NPU allocated size: " << _allocStats._totalNPUSize << " bytes in "
              << _allocStats._totalNPUCount << " buffers\n";
    std::cout << "================================================================================\n";
    std::cout << std::endl;
}
// ---- CountingBufferManager -----
DeviceBuffer CountingBufferManager::allocate(const BufferSpecs& buffSpecs) {
    ++allocateCalls;
    lastRequestedSpecs = buffSpecs;

    lastAllocation.resize(buffSpecs.size);
    return DeviceBuffer(lastAllocation.data(), reinterpret_cast<uint64_t>(lastAllocation.data()), buffSpecs.size);
}

void CountingBufferManager::deallocate(DeviceBuffer& devAddress) {
    ++deallocateCalls;
    deallocatedCpuAddr = devAddress.cpu_addr();
}

void CountingBufferManager::lock(DeviceBuffer& devAddress) {
    (void)devAddress;
    ++lockCalls;
}

void CountingBufferManager::unlock(DeviceBuffer& devAddress) {
    (void)devAddress;
    ++unlockCalls;
}

size_t CountingBufferManager::copy(DeviceBuffer& to, const uint8_t* from, size_t count) {
    ++copyCalls;
    std::memcpy(to.cpu_addr(), from, count);
    return count;
}

// ----- BadAllocSizeBufferManager -----

DeviceBuffer BadAllocSizeBufferManager::allocate(const BufferSpecs& buffSpecs) {
    lastRequested = buffSpecs;
    backing.resize(1);
    return DeviceBuffer(backing.data(), reinterpret_cast<uint64_t>(backing.data()), 1);
}

void BadAllocSizeBufferManager::deallocate(DeviceBuffer& devAddress) {
    (void)devAddress;
}

void BadAllocSizeBufferManager::lock(DeviceBuffer& devAddress) {
    (void)devAddress;
}

void BadAllocSizeBufferManager::unlock(DeviceBuffer& devAddress) {
    (void)devAddress;
}

size_t BadAllocSizeBufferManager::copy(DeviceBuffer& to, const uint8_t* from, size_t count) {
    (void)to;
    (void)from;
    return count;
}
