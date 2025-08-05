//
// Copyright (C) 2023-2025 Intel Corporation
// SPDX-License-Identifier: Apache-2.0
//

#include <cstring>
#include <memory>
#include <vector>

#include <vpux_elf/utils/error.hpp>
#include <vpux_elf/utils/utils.hpp>
#include <vpux_headers/managed_buffer.hpp>
#include "vpux_headers/device_buffer.hpp"

namespace elf {

static_assert(sizeof(size_t) >= sizeof(uintptr_t), "");

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
    VPUX_ELF_THROW_UNLESS(utils::isPowerOfTwo(mDefaultSafeAlignment), RuntimeError,
                          "Default safe alignment is not a power of 2");
    VPUX_ELF_THROW_UNLESS(utils::isPowerOfTwo(bSpecs.alignment), RuntimeError,
                        "Requested alignment is not a power of 2");

    size_t bufferSize, bufferAlignment;
    bSpecs.alignment < mDefaultSafeAlignment ? bufferAlignment = mDefaultSafeAlignment
                                             : bufferAlignment = bSpecs.alignment;
    bufferSize = utils::alignUp(bSpecs.size, mDefaultSafeAlignment);

    mData.reserve(bufferSize + bufferAlignment);

    size_t bufferBase = reinterpret_cast<uintptr_t>(mData.data());
    size_t bufferBaseAligned = utils::alignUp(bufferBase, bufferAlignment);

    VPUX_ELF_THROW_WHEN(bufferBaseAligned < bufferBase, RuntimeError, "Invalid aligned buffer base address");
    VPUX_ELF_THROW_WHEN((bufferBaseAligned - bufferBase + bSpecs.size) > mData.capacity(), RuntimeError,
                        "Usable buffer range exceeds parent buffer");

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
