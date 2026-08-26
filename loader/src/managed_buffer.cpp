//
// Copyright (C) 2023-2026 Intel Corporation
// SPDX-License-Identifier: Apache-2.0
//

#include <cstring>
#include <limits>
#include <memory>
#include <vector>

#include <vpux_elf/utils/error.hpp>
#include <vpux_elf/utils/utils.hpp>
#include <vpux_headers/managed_buffer.hpp>
#include "vpux_headers/device_buffer.hpp"

namespace elf {

static_assert(sizeof(size_t) >= sizeof(uintptr_t));

ManagedBuffer::ManagedBuffer(BufferSpecs bSpecs): mDevBuffer(), mBufferSpecs(bSpecs), mUserPrivateData(nullptr) {
}

DeviceBuffer ManagedBuffer::getBuffer() const {
    return mDevBuffer;
}

void ManagedBuffer::resetBuffer(const DeviceBuffer& newBuffer) {
    mDevBuffer = newBuffer;
}

BufferSpecs ManagedBuffer::getBufferSpecs() const {
    return mBufferSpecs;
}

void ManagedBuffer::lock() {
}

void ManagedBuffer::unlock() {
}

void ManagedBuffer::load(const uint8_t* from, size_t count) {
    VPUX_ELF_THROW_UNLESS(from, ArgsError, "nullptr source buffer");
    VPUX_ELF_THROW_UNLESS(mDevBuffer.cpu_addr(), RuntimeError, "DeviceBuffer not initialized");
    VPUX_ELF_THROW_WHEN(count > mDevBuffer.size(), ArgsError, "copy size exceeds buffer size");

    std::memcpy(mDevBuffer.cpu_addr(), from, count);
}

void ManagedBuffer::loadWithLock(const uint8_t* from, size_t count) {
    lock();
    load(from, count);
    unlock();
}

AllocatedDeviceBuffer::AllocatedDeviceBuffer(BufferManager* bManager, BufferSpecs bSpecs)
        : ManagedBuffer(bSpecs), mBufferManager(bManager) {
    VPUX_ELF_THROW_UNLESS(bManager, ArgsError, "nullptr BufferManager");
    mDevBuffer = mBufferManager->allocate(mBufferSpecs);
    VPUX_ELF_THROW_WHEN((mDevBuffer.vpu_addr() != 0) && (mDevBuffer.size() < bSpecs.size), AllocError,
                        "Failed to allocate DeviceBuffer");
}

AllocatedDeviceBuffer::~AllocatedDeviceBuffer() {
    mBufferManager->deallocate(mDevBuffer);
    mBufferManager = nullptr;
}

std::unique_ptr<ManagedBuffer> AllocatedDeviceBuffer::createNew() const {
    return std::make_unique<AllocatedDeviceBuffer>(mBufferManager, mBufferSpecs);
}

void AllocatedDeviceBuffer::lock() {
    mBufferManager->lock(mDevBuffer);
}

void AllocatedDeviceBuffer::unlock() {
    mBufferManager->unlock(mDevBuffer);
}

void AllocatedDeviceBuffer::load(const uint8_t* from, size_t count) {
    mBufferManager->copy(mDevBuffer, from, count);
}

DynamicBuffer::DynamicBuffer(BufferSpecs bSpecs): ManagedBuffer(bSpecs) {
    // Reject unreasonable attacker-controlled alignment up front.
    static constexpr size_t kMaxAlignment = 1U << 16;
    const auto requestedAlignment = utils::normalizeAlignment(bSpecs.alignment);

    VPUX_ELF_THROW_UNLESS(utils::isPowerOfTwo(mDefaultSafeAlignment), RuntimeError,
                          "Default safe alignment is not a power of 2");
    VPUX_ELF_THROW_UNLESS(utils::isPowerOfTwo(requestedAlignment), RuntimeError,
                          "Requested alignment is not a power of 2");
    VPUX_ELF_THROW_WHEN(requestedAlignment > kMaxAlignment, ArgsError, "Unreasonable alignment");

    const size_t bufferAlignment =
            (requestedAlignment < mDefaultSafeAlignment) ? mDefaultSafeAlignment : requestedAlignment;

    VPUX_ELF_THROW_WHEN(bSpecs.size > std::numeric_limits<size_t>::max() - mDefaultSafeAlignment, ArgsError,
                        "size overflow");
    const size_t bufferSize = utils::alignUp(static_cast<size_t>(bSpecs.size), mDefaultSafeAlignment);

    VPUX_ELF_THROW_WHEN(bufferSize > std::numeric_limits<size_t>::max() - bufferAlignment, ArgsError,
                        "size+align overflow");
    mData.resize(bufferSize + bufferAlignment);

    const auto bufferBase = reinterpret_cast<uintptr_t>(mData.data());
    const size_t bufferBaseAligned = utils::alignUp(bufferBase, bufferAlignment);

    VPUX_ELF_THROW_WHEN(bufferBaseAligned < bufferBase, RuntimeError, "Invalid aligned base");
    const size_t pad = bufferBaseAligned - bufferBase;
    VPUX_ELF_THROW_WHEN(
            static_cast<size_t>(bSpecs.size) > mData.size() || pad > mData.size() - static_cast<size_t>(bSpecs.size),
            AllocError, "Usable buffer range exceeds parent buffer");

    mDevBuffer = DeviceBuffer(reinterpret_cast<uint8_t*>(bufferBaseAligned), bufferBaseAligned, bSpecs.size);
}

std::unique_ptr<ManagedBuffer> DynamicBuffer::createNew() const {
    return std::make_unique<DynamicBuffer>(mBufferSpecs);
}

StaticBuffer::StaticBuffer(uint8_t* cpuAddr, BufferSpecs bSpecs): ManagedBuffer(bSpecs) {
    mDevBuffer = DeviceBuffer(cpuAddr, reinterpret_cast<uintptr_t>(cpuAddr), mBufferSpecs.size);
}

StaticBuffer::StaticBuffer(StaticBuffer&& other): ManagedBuffer(other.mBufferSpecs) {
    mDevBuffer = other.mDevBuffer;
    other.mDevBuffer = DeviceBuffer();
}

StaticBuffer& StaticBuffer::operator=(StaticBuffer&& rhs) {
    if (this != &rhs) {
        mBufferSpecs = rhs.mBufferSpecs;
        mDevBuffer = rhs.mDevBuffer;
        rhs.mDevBuffer = DeviceBuffer();
    }
    return *this;
}

std::unique_ptr<ManagedBuffer> StaticBuffer::createNew() const {
    return std::make_unique<DynamicBuffer>(mBufferSpecs);
}

}  // namespace elf
