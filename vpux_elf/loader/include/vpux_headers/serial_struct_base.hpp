//
// Copyright (C) 2023-2025 Intel Corporation
// SPDX-License-Identifier: Apache-2.0
//

#pragma once

#include <cstring>
#include <memory>
#include <string>
#include <vector>

#include <vpux_elf/utils/error.hpp>
#include <vpux_elf/utils/utils.hpp>

namespace elf {

struct SerialDescriptor {
    uint64_t mDataOffset = 0;
    uint64_t mNextDescOffset = 0;
    uint64_t mElementCount = 0;
    uint64_t mElementSize = 0;
};

template <typename DataType>
class SerialBufferBase {
public:
    static_assert(sizeof(DataType) == 1, "unsupported buffer data type");

    using BufferDataType = DataType;

    struct AddressOffsetPair {
        BufferDataType* mAddress;
        uint64_t mOffset;
    };

protected:
    BufferDataType* mBuffer;
    const uint64_t mSize;
    uint64_t mOffset;

    SerialBufferBase(BufferDataType* buffer, uint64_t size): mBuffer(buffer), mSize(size) {
        VPUX_ELF_THROW_UNLESS(mBuffer, RuntimeError, "received nullptr buffer address");
        VPUX_ELF_THROW_UNLESS(mSize, RuntimeError, "received 0 buffer size");
        mOffset = 0;
    }

    void checkDataPointer(BufferDataType* data, uint64_t size) {
        auto dataStartAddress = reinterpret_cast<uint64_t>(data);
        auto dataEndAddress = dataStartAddress + (size - 1);
        auto bufferStartAddress = reinterpret_cast<uint64_t>(&mBuffer[0]);
        auto bufferEndAddress = reinterpret_cast<uint64_t>(&mBuffer[mSize - 1]);

        VPUX_ELF_THROW_WHEN((dataStartAddress < bufferStartAddress) || (dataStartAddress > bufferEndAddress) ||
                                    (dataEndAddress > bufferEndAddress),
                            RuntimeError, "pointer out of bounds");
    }
};

class SerialInputBuffer : public SerialBufferBase<const uint8_t> {
public:
    SerialInputBuffer(BufferDataType* buffer, uint64_t size): SerialBufferBase(buffer, size) {
    }

    BufferDataType* getAddressOfOffset(uint64_t offset, uint64_t size) {
        VPUX_ELF_THROW_WHEN((offset + size) > mSize, RuntimeError, "read request out of bounds");
        checkDataPointer(&mBuffer[offset], size);
        return &mBuffer[offset];
    }
};

class SerialOutputBuffer : public SerialBufferBase<uint8_t> {
public:
    SerialOutputBuffer(BufferDataType* buffer, uint64_t size): SerialBufferBase(buffer, size) {
    }

    AddressOffsetPair getNextBufferSlice(uint64_t size, uint64_t alignment = 0) {
        mOffset = utils::alignUp(mOffset, alignment);
        auto entry = &mBuffer[mOffset];
        auto offset = mOffset;
        mOffset += size;

        VPUX_ELF_THROW_WHEN(mOffset > mSize, RuntimeError, "offset out of bounds");

        return {entry, offset};
    }
};

class SerialElementInterface {
public:
    virtual ~SerialElementInterface() {
    }

    virtual void clear() = 0;
    virtual void resize(uint64_t count) = 0;
    virtual uint64_t getSize() = 0;
    virtual uint64_t getCount() = 0;
    virtual void copyFromIndex(uint8_t* to, uint64_t index) = 0;
    virtual void copyToIndex(const uint8_t* from, uint64_t index, uint64_t size) = 0;
};

template <typename DataType>
class SerialElement : public SerialElementInterface {
public:
    DataType& mData;

    SerialElement(DataType& dataRef): mData(dataRef) {
    }

    void clear() override {
        mData = {};
    }

    void resize(uint64_t count) override {
        VPUX_ELF_THROW_WHEN(count > 1, RuntimeError, "unsupported resize request");
    }

    uint64_t getSize() override {
        return sizeof(DataType);
    }

    uint64_t getCount() override {
        return 1;
    }

    void copyFromIndex(uint8_t* to, uint64_t index) override {
        VPUX_ELF_THROW_WHEN(index >= getCount(), RuntimeError, "index out of bounds");
        std::memcpy(to, &mData, sizeof(DataType));
    }

    void copyToIndex(const uint8_t* from, uint64_t index, uint64_t size) override {
        VPUX_ELF_THROW_WHEN(index >= getCount(), RuntimeError, "index out of bounds");
        VPUX_ELF_THROW_WHEN(size != sizeof(DataType), RuntimeError, "unexpected size received");
        std::memcpy(&mData, from, size);
    }
};

template <typename DataType>
class SerialElementVector : public SerialElementInterface {
public:
    std::vector<DataType>& mData;

    SerialElementVector(std::vector<DataType>& dataRef): mData(dataRef) {
    }

    void clear() override {
        mData.clear();
    }

    void resize(uint64_t count) override {
        mData.resize(count);
    }

    uint64_t getSize() override {
        return sizeof(DataType);
    }

    uint64_t getCount() override {
        return mData.size();
    }

    void copyFromIndex(uint8_t* to, uint64_t index) override {
        VPUX_ELF_THROW_WHEN(index >= getCount(), RuntimeError, "index out of bounds");
        std::memcpy(to, &mData[index], sizeof(DataType));
    }

    void copyToIndex(const uint8_t* from, uint64_t index, uint64_t size) override {
        VPUX_ELF_THROW_WHEN(index >= getCount(), RuntimeError, "index out of bounds");
        VPUX_ELF_THROW_WHEN(size != sizeof(DataType), RuntimeError, "unexpected size received");

        std::memcpy(&mData[index], from, size);
    }
};

class SerialStructBase {
public:
    SerialStructBase() = default;

    template <typename DataType>
    void addElement(DataType& value) {
        mElements.push_back(std::make_unique<SerialElement<DataType>>(value));
    }

    template <typename DataType>
    void addElementVector(std::vector<DataType>& value) {
        mElements.push_back(std::make_unique<SerialElementVector<DataType>>(value));
    }

    std::vector<uint8_t> serialize() {
        std::vector<uint8_t> buffer;

        buffer.resize(calculateBufferSize());

        // Create serial data buffer
        SerialOutputBuffer serialBuffer(&buffer[0], buffer.size());

        SerialDescriptor* previousDescriptor = nullptr;
        for (auto& elem : mElements) {
            previousDescriptor = serializeElement(serialBuffer, previousDescriptor, elem);
        }

        return buffer;
    }

    void deserialize(const uint8_t* buffer, uint64_t size) {
        // Buffer should contain at least one descriptor
        VPUX_ELF_THROW_UNLESS(size >= sizeof(SerialDescriptor), RuntimeError, "size mismatch");
        SerialInputBuffer serialBuffer(buffer, size);

        SerialDescriptor currentDescriptor;

        std::memcpy(
                &currentDescriptor,
                reinterpret_cast<const SerialDescriptor*>(serialBuffer.getAddressOfOffset(0, sizeof(SerialDescriptor))),
                sizeof(SerialDescriptor));

        for (auto& elem : mElements) {
            VPUX_ELF_THROW_WHEN(
                currentDescriptor.mElementSize * currentDescriptor.mElementCount + currentDescriptor.mDataOffset > size,
                RuntimeError, "element is out of bound");
            currentDescriptor = deserializeElement(serialBuffer, currentDescriptor, elem);
        }
    }

private:
    std::vector<std::unique_ptr<SerialElementInterface>> mElements;

    static uint64_t updateRequiredBufferSize(uint64_t currentBufferSize, uint64_t elementSize, uint64_t elementCount) {
        // Only data type reinterpret casted from the serial buffer is SerialDescriptor, so ensure alignment for it is
        // considered
        currentBufferSize += utils::alignUp(sizeof(SerialDescriptor) + (elementSize * elementCount), 8);
        return currentBufferSize;
    }

    uint64_t calculateBufferSize() {
        uint64_t requiredBufferSize = 0;

        for (auto& elem : mElements) {
            requiredBufferSize = updateRequiredBufferSize(requiredBufferSize, elem->getSize(), elem->getCount());
        }

        return requiredBufferSize;
    }

    SerialDescriptor* serializeElement(SerialOutputBuffer& buffer, SerialDescriptor* previousDescriptor,
                                       std::unique_ptr<SerialElementInterface>& element) {
        VPUX_ELF_THROW_UNLESS(element.get(), RuntimeError, "nullptr received for element");

        // Add descriptor
        auto bufferDesc = buffer.getNextBufferSlice(sizeof(SerialDescriptor), alignof(SerialDescriptor));
        auto currentDescriptor = reinterpret_cast<SerialDescriptor*>(bufferDesc.mAddress);

        if (previousDescriptor) {
            // Link descriptors
            previousDescriptor->mNextDescOffset = bufferDesc.mOffset;
        }

        if (auto elementCount = element->getCount()) {
            auto elementSize = element->getSize();
            currentDescriptor->mElementCount = elementCount;
            currentDescriptor->mElementSize = elementSize;

            for (uint64_t idx = 0; idx < elementCount; ++idx) {
                auto dataBufferDesc = buffer.getNextBufferSlice(elementSize);
                auto dataPtr = dataBufferDesc.mAddress;
                if (!idx) {
                    currentDescriptor->mDataOffset = dataBufferDesc.mOffset;
                }
                element->copyFromIndex(dataPtr, idx);
            }
        } else {
            currentDescriptor->mElementCount = 0;
            currentDescriptor->mElementSize = 0;
        }

        return currentDescriptor;
    }

    SerialDescriptor deserializeElement(SerialInputBuffer& buffer, const SerialDescriptor& currentDescriptor,
                                        std::unique_ptr<SerialElementInterface>& element) {
        VPUX_ELF_THROW_UNLESS(element.get(), RuntimeError, "nullptr received for element");

        // Clear current contents
        element->clear();

        auto elemCount = currentDescriptor.mElementCount;
        auto elemSize = currentDescriptor.mElementSize;

        if (elemCount) {
            element->resize(elemCount);
            auto currentDataOffset = currentDescriptor.mDataOffset;
            for (uint64_t idx = 0; idx < elemCount; ++idx) {
                auto dataPtr = buffer.getAddressOfOffset(currentDataOffset, elemSize);
                currentDataOffset += elemSize;
                element->copyToIndex(dataPtr, idx, elemSize);
            }
        }

        SerialDescriptor nextDescriptor;
        if (currentDescriptor.mNextDescOffset) {
            std::memcpy(&nextDescriptor,
                        reinterpret_cast<const SerialDescriptor*>(
                                buffer.getAddressOfOffset(currentDescriptor.mNextDescOffset, sizeof(SerialDescriptor))),
                        sizeof(SerialDescriptor));
        }

        return nextDescriptor;
    }
};

}  // namespace elf
