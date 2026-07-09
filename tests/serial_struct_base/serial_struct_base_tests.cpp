//
// Copyright (C) 2026 Intel Corporation.
// SPDX-License-Identifier: Apache-2.0
//

#include <gtest/gtest.h>

#include <cstring>
#include <limits>
#include <string>
#include <vector>

#include <vpux_headers/serial_struct_base.hpp>

namespace {

class SerialSingleByteElement final : public elf::SerialStructBase {
public:
    SerialSingleByteElement() {
        addElement(value);
    }

    uint8_t value = 0;
};

TEST(SerialBufferBase, ThrowWhenInputBufferIsNullptr) {
    ASSERT_THROW((elf::SerialInputBuffer(nullptr, 8)), elf::RuntimeError);
}

TEST(SerialBufferBase, ThrowWhenInputBufferHasZeroSize) {
    uint8_t storage[8] = {};
    ASSERT_THROW((elf::SerialInputBuffer(storage, 0)), elf::RuntimeError);
}

TEST(SerialBufferBase, ReturnValidSliceForInBoundsRead) {
    uint8_t storage[8] = {10, 11, 12, 13, 14, 15, 16, 17};
    elf::SerialInputBuffer buffer(storage, sizeof(storage));

    auto* ptr = buffer.getAddressOfOffset(2, 3);

    ASSERT_EQ(ptr, &storage[2]);
    ASSERT_EQ(ptr[0], 12);
    ASSERT_EQ(ptr[2], 14);
}

TEST(SerialBufferBase, ThrowWhenReadRequestExceedsBounds) {
    uint8_t storage[8] = {};
    elf::SerialInputBuffer buffer(storage, sizeof(storage));

    ASSERT_THROW((buffer.getAddressOfOffset(7, 2)), elf::RuntimeError);
}

TEST(SerialBufferBase, ThrowWhenReadRequestSizeIsZero) {
    uint8_t storage[8] = {};
    elf::SerialInputBuffer buffer(storage, sizeof(storage));

    ASSERT_THROW((buffer.getAddressOfOffset(0, 0)), elf::RuntimeError);
}

TEST(SerialBufferBase, ThrowWhenOutputSliceExceedsBounds) {
    uint8_t storage[8] = {};
    elf::SerialOutputBuffer buffer(storage, sizeof(storage));

    ASSERT_NO_THROW((void)buffer.getNextBufferSlice(6));
    ASSERT_THROW((void)buffer.getNextBufferSlice(3), elf::RuntimeError);
}

TEST(SerialBufferBase, AlignOutputSlices) {
    uint8_t storage[32] = {};
    elf::SerialOutputBuffer buffer(storage, sizeof(storage));

    const auto first = buffer.getNextBufferSlice(1);
    const auto second = buffer.getNextBufferSlice(1, 8);

    ASSERT_EQ(first.mOffset, 0);
    ASSERT_EQ(first.mAddress, &storage[0]);
    ASSERT_EQ(second.mOffset, 8);
    ASSERT_EQ(second.mAddress, &storage[8]);
}

TEST(SerialStructBase, ThrowWhenDescriptorArithmeticOverflows) {
    std::vector<uint8_t> serialized(sizeof(elf::SerialDescriptor), 0);

    elf::SerialDescriptor descriptor;
    descriptor.mDataOffset = 0;
    descriptor.mNextDescOffset = 0;
    descriptor.mElementCount = (uint64_t{1} << 63);
    descriptor.mElementSize = 2;
    std::memcpy(serialized.data(), &descriptor, sizeof(descriptor));

    SerialSingleByteElement element;

    try {
        element.deserialize(serialized.data(), serialized.size());
        FAIL() << "Expected RuntimeError due to overflowed descriptor arithmetic";
    } catch (const elf::RuntimeError& ex) {
        // The overflow should be rejected by the top-level bound check, before element resize.
        const std::string message = ex.what();
        ASSERT_NE(message.find("element is out of bound"), std::string::npos);
    }
}

}  // namespace
