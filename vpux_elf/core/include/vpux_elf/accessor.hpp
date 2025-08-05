//
// Copyright (C) 2023-2025 Intel Corporation
// SPDX-License-Identifier: Apache-2.0
//

//

#pragma once

#include <cstring>
#include <fstream>
#include <memory>

#include <vpux_headers/buffer_manager.hpp>
#include <vpux_headers/managed_buffer.hpp>

#include "vpux_elf/utils/error.hpp"
#include "vpux_elf/utils/utils.hpp"

namespace elf {

/*
Abstraction class to encapsulate access to ELF binary.
*/

class AccessManager {
public:
    AccessManager() = default;
    explicit AccessManager(size_t binarySize);
    AccessManager(const AccessManager& other) = default;
    AccessManager(AccessManager&& other) = default;
    AccessManager& operator=(const AccessManager& rhs) = default;
    AccessManager& operator=(AccessManager&& rhs) = default;
    virtual ~AccessManager() = default;

    virtual std::unique_ptr<ManagedBuffer> readInternal(size_t offset, const BufferSpecs& specs) = 0;
    virtual void readExternal(size_t offset, ManagedBuffer& buffer) = 0;
    size_t getSize() const;

protected:
    size_t mSize = 0;
};

/*
Demo classes.
*/

// Full NPU access compatible when run by the NPU itself
// Not full NPU access compatible when run by the host CPU
class DDRStandardEmplace {
public:
    static bool canEmplace(uint8_t* addr, BufferSpecs specs) {
        auto addrValue = reinterpret_cast<size_t>(addr);
        if (specs.alignment) {
            if (!elf::utils::isPowerOfTwo(specs.alignment)) {
                return false;
            }
            if (addrValue & (specs.alignment - 1)) {
                return false;
            }
        }
        return true;
    }
};

// Full NPU access compatible when coupled with an NPU compatible buffer factory
class DDRNeverEmplace {
public:
    static bool canEmplace(uint8_t*, BufferSpecs) {
        return false;
    }
};

// Not NPU access compatible - to be used only for CPU simulations
class DDRAlwaysEmplace {
public:
    static bool canEmplace(uint8_t*, BufferSpecs) {
        return true;
    }
};

class BufferFactoryBase {
public:
    static std::unique_ptr<ManagedBuffer> getEmplacedBufferStatic(uint8_t* addr, BufferSpecs specs) {
        VPUX_ELF_THROW_UNLESS(addr, RuntimeError, "nullptr buffer");
        return std::make_unique<StaticBuffer>(addr, specs);
    }
    std::unique_ptr<ManagedBuffer> getEmplacedBuffer(uint8_t* addr, BufferSpecs specs) {
        return getEmplacedBufferStatic(addr, specs);
    }
};

class AllocatedDeviceBufferFactory : public BufferFactoryBase {
public:
    AllocatedDeviceBufferFactory(BufferManager* bufferManager): mBufferManager(bufferManager) {
        VPUX_ELF_THROW_UNLESS(mBufferManager, RuntimeError, "Received nullptr BufferManager");
    }

    std::unique_ptr<ManagedBuffer> getAllocatedBuffer(BufferSpecs specs) {
        return std::make_unique<AllocatedDeviceBuffer>(mBufferManager, specs);
    }

private:
    BufferManager* mBufferManager = nullptr;
};

class DynamicBufferFactory : public BufferFactoryBase {
public:
    std::unique_ptr<ManagedBuffer> getAllocatedBuffer(BufferSpecs specs) {
        return std::make_unique<DynamicBuffer>(specs);
    }
};

class HybridBufferFactory : public BufferFactoryBase {
public:
    HybridBufferFactory(BufferManager* bufferManager): mBufferManager(bufferManager) {
        VPUX_ELF_THROW_UNLESS(mBufferManager, RuntimeError, "Received nullptr BufferManager");
    }

    std::unique_ptr<ManagedBuffer> getAllocatedBuffer(BufferSpecs specs) {
        if (utils::hasNPUAccess(specs.procFlags)) {
            return std::make_unique<AllocatedDeviceBuffer>(mBufferManager, specs);
        } else {
            return std::make_unique<DynamicBuffer>(specs);
        }
    }

private:
    BufferManager* mBufferManager = nullptr;
};

class DDRAccessManagerBase : public AccessManager {
public:
    DDRAccessManagerBase(const uint8_t* blob, size_t size): AccessManager(size), mBlob(blob) {
        VPUX_ELF_THROW_UNLESS(mBlob, ArgsError, "Invalid binary file arg");
    }

    void readExternal(size_t offset, ManagedBuffer& buffer) override {
        VPUX_ELF_THROW_WHEN((offset + buffer.getBufferSpecs().size) > mSize, AccessError, "Read request out of bounds");

        auto devBuffer = buffer.getBuffer();
        auto lock = ElfBufferLockGuard(&buffer);
        std::memcpy(devBuffer.cpu_addr(), mBlob + offset, devBuffer.size());
    }

protected:
    const uint8_t* mBlob = nullptr;
};

template <typename EmplaceLogic, typename... Args>
class DDRAccessManager final : public DDRAccessManagerBase {};

// Generic specialization which allows user to supply EmplaceLogic and BufferFactory to control
// how emplacing is decided and what buffer types to create
template <typename EmplaceLogic, typename BufferFactory>
class DDRAccessManager<EmplaceLogic, BufferFactory> final : public DDRAccessManagerBase {
public:
    DDRAccessManager(const uint8_t* blob, size_t size,
                     std::shared_ptr<BufferFactory> factory = std::make_shared<BufferFactory>())
            : DDRAccessManagerBase(blob, size), mBufferFactory(factory) {
        VPUX_ELF_THROW_UNLESS(mBufferFactory, RuntimeError, "nullptr buffer factory");
    }

    std::unique_ptr<ManagedBuffer> readInternal(size_t offset, const BufferSpecs& specs) override {
        VPUX_ELF_THROW_WHEN((offset + specs.size) > mSize, AccessError, "Read request out of bounds");

        auto targetAddr = const_cast<uint8_t*>(mBlob) + offset;

        if (EmplaceLogic::canEmplace(targetAddr, specs)) {
            return mBufferFactory->getEmplacedBuffer(targetAddr, specs);
        } else {
            auto buffer = mBufferFactory->getAllocatedBuffer(specs);
            auto lock = ElfBufferLockGuard(buffer.get());
            std::memcpy(buffer->getBuffer().cpu_addr(), targetAddr, buffer->getBuffer().size());
            return buffer;
        }
    }

private:
    std::shared_ptr<BufferFactory> mBufferFactory = nullptr;
};

// Specialization for DDRAlwaysEmplace where we only produce static (emplaced) buffers
// DDRAlwaysEmplace can be used with the more generic specialization if a different buffer creation mechanism is
// desired or to track statistics
template <>
class DDRAccessManager<DDRAlwaysEmplace> final : public DDRAccessManagerBase {
public:
    DDRAccessManager(const uint8_t* blob, size_t size): DDRAccessManagerBase(blob, size) {
    }

    std::unique_ptr<ManagedBuffer> readInternal(size_t offset, const BufferSpecs& specs) override {
        VPUX_ELF_THROW_WHEN((offset + specs.size) > mSize, AccessError, "Read request out of bounds");

        return BufferFactoryBase::getEmplacedBufferStatic(const_cast<uint8_t*>(mBlob) + offset, specs);
    }
};

template <typename BufferFactory = DynamicBufferFactory>
class FSAccessManager final : public AccessManager {
public:
    FSAccessManager(const std::string& elfFileName,
                    std::shared_ptr<BufferFactory> factory = std::make_shared<BufferFactory>())
            : mFileStream(elfFileName, std::ifstream::binary), mBufferFactory(factory) {
        VPUX_ELF_THROW_WHEN(!mFileStream.good(), AccessError,
                            std::string("unable to access binary file " + elfFileName).c_str());
        mFileStream.seekg(0, mFileStream.end);
        mSize = mFileStream.tellg();
    }
    FSAccessManager(const FSAccessManager&) = default;
    FSAccessManager(FSAccessManager&&) = default;
    FSAccessManager& operator=(const FSAccessManager&) = default;
    FSAccessManager& operator=(FSAccessManager&&) = default;
    ~FSAccessManager() {
        mFileStream.close();
    }

    std::unique_ptr<ManagedBuffer> readInternal(size_t offset, const BufferSpecs& specs) override {
        VPUX_ELF_THROW_WHEN((offset + specs.size) > mSize, AccessError, "Read request out of bounds");
        auto buffer = mBufferFactory->getAllocatedBuffer(specs);
        mFileStream.seekg(offset, mFileStream.beg);
        auto lock = ElfBufferLockGuard(buffer.get());
        mFileStream.read(reinterpret_cast<char*>(buffer->getBuffer().cpu_addr()), buffer->getBuffer().size());

        return buffer;
    }
    void readExternal(size_t offset, ManagedBuffer& buffer) override {
        VPUX_ELF_THROW_WHEN((offset + buffer.getBufferSpecs().size) > mSize, AccessError, "Read request out of bounds");
        mFileStream.seekg(offset, mFileStream.beg);
        auto lock = ElfBufferLockGuard(&buffer);
        mFileStream.read(reinterpret_cast<char*>(buffer.getBuffer().cpu_addr()), buffer.getBuffer().size());
    }

private:
    std::ifstream mFileStream;
    std::shared_ptr<BufferFactory> mBufferFactory = nullptr;
};

}  // namespace elf
