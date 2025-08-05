//
// Copyright (C) 2023-2025 Intel Corporation
// SPDX-License-Identifier: Apache-2.0
//

#pragma once

#include <memory>
#include <vector>

#include <vpux_headers/buffer_manager.hpp>
#include <vpux_headers/buffer_specs.hpp>
#include <vpux_headers/device_buffer.hpp>

namespace elf {

class ManagedBuffer {
public:
    explicit ManagedBuffer(BufferSpecs bSpecs);
    ManagedBuffer(const ManagedBuffer& other) = delete;
    ManagedBuffer(ManagedBuffer&& other) = delete;

    ManagedBuffer& operator=(const ManagedBuffer& rhs) = delete;
    ManagedBuffer& operator=(ManagedBuffer&& rhs) = delete;

    void resetBuffer(const DeviceBuffer& newBuffer);

    virtual ~ManagedBuffer() = default;

    virtual std::unique_ptr<ManagedBuffer> createNew() const = 0;
    virtual DeviceBuffer getBuffer() const;
    virtual BufferSpecs getBufferSpecs() const;
    virtual void lock();
    virtual void unlock();
    virtual void load(const uint8_t* from, size_t count);
    virtual void loadWithLock(const uint8_t* from, size_t count);

protected:
    DeviceBuffer mDevBuffer;
    BufferSpecs mBufferSpecs;
    void* mUserPrivateData;
};

class AllocatedDeviceBuffer final : public ManagedBuffer {
public:
    AllocatedDeviceBuffer(BufferManager* bManager, BufferSpecs bSpecs);

    ~AllocatedDeviceBuffer();

    std::unique_ptr<ManagedBuffer> createNew() const override;
    void lock() override;
    void unlock() override;
    void load(const uint8_t* from, size_t count) override;

private:
    BufferManager* mBufferManager;
};

class DynamicBuffer final : public ManagedBuffer {
public:
    explicit DynamicBuffer(BufferSpecs bSpecs);

    ~DynamicBuffer() = default;

    std::unique_ptr<ManagedBuffer> createNew() const override;

private:
    static constexpr size_t mDefaultSafeAlignment = 64;
    std::vector<uint8_t> mData;
};

class StaticBuffer final : public ManagedBuffer {
public:
    explicit StaticBuffer(uint8_t* cpuAddr, BufferSpecs bSpecs);
    StaticBuffer(StaticBuffer&& other);
    StaticBuffer& operator=(StaticBuffer&& rhs);

    ~StaticBuffer() = default;

    std::unique_ptr<ManagedBuffer> createNew() const override;
};

/**
 * Class wrapper which ensures that a locked buffer will be unlocked in case of
 * an event that prevents further execution.
 */
class ElfBufferLockGuard {
public:
    ElfBufferLockGuard(ManagedBuffer* devBuff) {
        if (devBuff) {
            mDevBuffer = devBuff;
            mDevBuffer->lock();
        }
    }
    ~ElfBufferLockGuard() {
        if (mDevBuffer) {
            mDevBuffer->unlock();
        }
    }

private:
    ManagedBuffer* mDevBuffer = nullptr;
};

}  // namespace elf
