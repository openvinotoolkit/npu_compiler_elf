//
// Copyright (C) 2026 Intel Corporation.
// SPDX-License-Identifier: Apache-2.0
//

#include <gtest/gtest.h>

#include <cstdint>
#include <cstring>
#include <limits>
#include <vector>

#include "allocator_utils/buffer_managers.hpp"
#include <vpux_elf/utils/error.hpp>
#include <vpux_headers/buffer_manager.hpp>
#include <vpux_headers/managed_buffer.hpp>

using namespace elf;

namespace {

TEST(ManagedBuffer, DynamicBufferRejectsNonPowerOfTwoAlignment) {
    ASSERT_THROW((void)DynamicBuffer(BufferSpecs{3, 16, 0}), RuntimeError);
}

TEST(ManagedBuffer, DynamicBufferRespectsRequestedAlignmentAndSize) {
    const BufferSpecs specs{128, 37, 0};
    DynamicBuffer buffer(specs);

    auto devBuffer = buffer.getBuffer();
    ASSERT_NE(devBuffer.cpu_addr(), nullptr);
    ASSERT_EQ(devBuffer.size(), specs.size);
    ASSERT_EQ(reinterpret_cast<uintptr_t>(devBuffer.cpu_addr()) % specs.alignment, 0U);
}

TEST(ManagedBuffer, DynamicBufferLoadCopiesDataToBuffer) {
    const BufferSpecs specs{64, 8, 0};
    DynamicBuffer buffer(specs);

    const std::vector<uint8_t> input = {1, 3, 5, 7, 9, 11, 13, 15};
    buffer.load(input.data(), input.size());

    ASSERT_EQ(std::memcmp(buffer.getBuffer().cpu_addr(), input.data(), input.size()), 0);
}

TEST(ManagedBuffer, DynamicBufferLoadWithLockCopiesDataToBuffer) {
    const BufferSpecs specs{64, 8, 0};
    DynamicBuffer buffer(specs);

    const std::vector<uint8_t> input = {2, 4, 6, 8, 10, 12, 14, 16};
    buffer.loadWithLock(input.data(), input.size());

    ASSERT_EQ(std::memcmp(buffer.getBuffer().cpu_addr(), input.data(), input.size()), 0);
}

TEST(ManagedBuffer, DynamicBufferResetBufferOverridesDeviceBufferView) {
    const BufferSpecs specs{64, 8, 0};
    DynamicBuffer buffer(specs);

    std::vector<uint8_t> external(8, 0x5A);
    DeviceBuffer replacement(external.data(), reinterpret_cast<uint64_t>(external.data()), external.size());
    buffer.resetBuffer(replacement);

    ASSERT_EQ(buffer.getBuffer().cpu_addr(), external.data());
    ASSERT_EQ(buffer.getBuffer().size(), external.size());
}

TEST(ManagedBuffer, StaticBufferMoveConstructorTransfersAndClearsSource) {
    std::vector<uint8_t> raw(16, 0xAA);
    const BufferSpecs specs{8, 16, 0};

    StaticBuffer source(raw.data(), specs);
    StaticBuffer moved(std::move(source));

    ASSERT_EQ(moved.getBuffer().cpu_addr(), raw.data());
    ASSERT_EQ(moved.getBuffer().size(), specs.size);
    ASSERT_EQ(source.getBuffer().cpu_addr(), nullptr);
    ASSERT_EQ(source.getBuffer().size(), 0U);
}

TEST(ManagedBuffer, StaticBufferMoveAssignmentTransfersAndClearsSource) {
    std::vector<uint8_t> rawA(8, 0x11);
    std::vector<uint8_t> rawB(8, 0x22);
    const BufferSpecs specs{8, 8, 0};

    StaticBuffer source(rawA.data(), specs);
    StaticBuffer target(rawB.data(), specs);

    target = std::move(source);

    ASSERT_EQ(target.getBuffer().cpu_addr(), rawA.data());
    ASSERT_EQ(target.getBuffer().size(), specs.size);
    ASSERT_EQ(source.getBuffer().cpu_addr(), nullptr);
    ASSERT_EQ(source.getBuffer().size(), 0U);
}

TEST(ManagedBuffer, StaticBufferCreateNewReturnsDynamicBufferWithSameSpecs) {
    std::vector<uint8_t> raw(32, 0x5A);
    const BufferSpecs specs{16, 32, 0};
    StaticBuffer source(raw.data(), specs);

    auto created = source.createNew();

    ASSERT_NE(created, nullptr);
    ASSERT_EQ(created->getBufferSpecs().alignment, specs.alignment);
    ASSERT_EQ(created->getBufferSpecs().size, specs.size);
    ASSERT_NE(created->getBuffer().cpu_addr(), nullptr);
    ASSERT_NE(created->getBuffer().cpu_addr(), raw.data());
}

TEST(ManagedBuffer, AllocatedDeviceBufferCallsBufferManagerHooks) {
    CountingBufferManager manager;
    const BufferSpecs specs{64, 32, 0};

    {
        AllocatedDeviceBuffer buffer(&manager, specs);

        ASSERT_EQ(manager.allocateCalls, 1);
        ASSERT_EQ(manager.lastRequestedSpecs.size, specs.size);
        ASSERT_EQ(manager.lastRequestedSpecs.alignment, specs.alignment);

        std::vector<uint8_t> payload(specs.size, 0x3C);
        buffer.load(payload.data(), payload.size());
        buffer.loadWithLock(payload.data(), payload.size());

        buffer.lock();
        buffer.unlock();

        ASSERT_GE(manager.copyCalls, 2);
        ASSERT_EQ(manager.lockCalls, 2);
        ASSERT_EQ(manager.unlockCalls, 2);
        ASSERT_EQ(std::memcmp(buffer.getBuffer().cpu_addr(), payload.data(), payload.size()), 0);
    }

    ASSERT_EQ(manager.deallocateCalls, 1);
    ASSERT_NE(manager.deallocatedCpuAddr, nullptr);
}

TEST(ManagedBuffer, AllocatedDeviceBufferCreateNewUsesSameSpecs) {
    CountingBufferManager manager;
    const BufferSpecs specs{64, 24, 0};

    AllocatedDeviceBuffer source(&manager, specs);
    auto created = source.createNew();

    ASSERT_NE(created, nullptr);
    ASSERT_EQ(manager.allocateCalls, 2);
    ASSERT_EQ(created->getBufferSpecs().alignment, specs.alignment);
    ASSERT_EQ(created->getBufferSpecs().size, specs.size);
}

TEST(ManagedBuffer, AllocatedDeviceBufferThrowsOnNullBufferManager) {
    ASSERT_THROW((void)AllocatedDeviceBuffer(nullptr, BufferSpecs{8, 8, 0}), ArgsError);
}

TEST(ManagedBuffer, AllocatedDeviceBufferThrowsWhenReturnedBufferIsTooSmall) {
    BadAllocSizeBufferManager badManager;

    ASSERT_THROW((void)AllocatedDeviceBuffer(&badManager, BufferSpecs{8, 64, 0}), AllocError);
}

TEST(ManagedBuffer, ElfBufferLockGuardLocksAndUnlocksWithinScope) {
    CountingBufferManager manager;
    AllocatedDeviceBuffer buffer(&manager, BufferSpecs{64, 8, 0});

    {
        ElfBufferLockGuard guard(&buffer);
        ASSERT_EQ(manager.lockCalls, 1);
        ASSERT_EQ(manager.unlockCalls, 0);
    }

    ASSERT_EQ(manager.unlockCalls, 1);
}

TEST(ManagedBuffer, DynamicBufferThrowsOnSizeAlignmentOverflowPattern) {
    // This value makes alignUp(size, 64) wrap on 64-bit arithmetic if unchecked.
    const size_t craftedSize = std::numeric_limits<size_t>::max() - 31;
    const size_t alignment = 64;

    ASSERT_THROW((void)DynamicBuffer(BufferSpecs{alignment, craftedSize, 0}), ArgsError);
}

TEST(ManagedBuffer, DynamicBufferThrowsForAlignUpOverflowWindowBoundaries) {
    const size_t alignment = 64;
    const size_t max = std::numeric_limits<size_t>::max();

    // alignUp(size, 64) overflows for size in [max - 62, max].
    const std::vector<size_t> craftedSizes = {max - 62, max - 1, max};

    for (const auto craftedSize : craftedSizes) {
        SCOPED_TRACE(craftedSize);
        ASSERT_THROW((void)DynamicBuffer(BufferSpecs{alignment, craftedSize, 0}), ArgsError);
    }
}

}  // namespace
