//
// Copyright (C) 2026 Intel Corporation.
// SPDX-License-Identifier: Apache-2.0
//

#include <gtest/gtest.h>

#include <cstdio>
#include <filesystem>
#include <fstream>
#include <memory>
#include <string>
#include <vector>

#include <vpux_elf/accessor.hpp>

using namespace elf;

namespace {

TEST(Accessor, DDRAlwaysEmplaceReturnsBlobBackedSlice) {
    std::vector<uint8_t> blob = {1, 2, 3, 4, 5, 6};
    DDRAccessManager<DDRAlwaysEmplace> accessor(blob.data(), blob.size());

    BufferSpecs specs{1, 3, 0};
    auto buffer = accessor.readInternal(2, specs);

    ASSERT_NE(buffer, nullptr);
    ASSERT_EQ(buffer->getBuffer().cpu_addr(), blob.data() + 2);
    ASSERT_EQ(buffer->getBuffer().size(), 3);
}

TEST(Accessor, DDRNeverEmplaceCopiesDataWithDynamicFactory) {
    std::vector<uint8_t> blob = {10, 11, 12, 13, 14, 15};
    auto factory = std::make_shared<DynamicBufferFactory>();
    DDRAccessManager<DDRNeverEmplace, DynamicBufferFactory> accessor(blob.data(), blob.size(), factory);

    BufferSpecs specs{1, 4, 0};
    auto buffer = accessor.readInternal(1, specs);

    ASSERT_NE(buffer, nullptr);
    ASSERT_NE(buffer->getBuffer().cpu_addr(), blob.data() + 1);
    ASSERT_EQ(buffer->getBuffer().size(), 4);
    ASSERT_EQ(std::memcmp(buffer->getBuffer().cpu_addr(), blob.data() + 1, 4), 0);
}

TEST(Accessor, DDRReadInternalThrowsWhenOutOfBounds) {
    std::vector<uint8_t> blob = {1, 2, 3, 4};
    DDRAccessManager<DDRAlwaysEmplace> accessor(blob.data(), blob.size());

    BufferSpecs specs{1, 2, 0};
    ASSERT_THROW((void)accessor.readInternal(3, specs), AccessError);
}

TEST(Accessor, DDRReadExternalCopiesAndThrowsOutOfBounds) {
    std::vector<uint8_t> blob = {9, 8, 7, 6, 5};
    DDRAccessManager<DDRAlwaysEmplace> accessor(blob.data(), blob.size());

    DynamicBuffer target(BufferSpecs{1, 3, 0});
    ASSERT_NO_THROW(accessor.readExternal(1, target));
    ASSERT_EQ(std::memcmp(target.getBuffer().cpu_addr(), blob.data() + 1, 3), 0);

    DynamicBuffer tooLarge(BufferSpecs{1, 6, 0});
    ASSERT_THROW(accessor.readExternal(0, tooLarge), AccessError);
}

TEST(Accessor, FSAccessManagerReadsData) {
    const auto filePath = std::filesystem::temp_directory_path() / "accessor_tests_blob.bin";
    const auto filePathStr = filePath.string();
    const std::vector<uint8_t> blob = {21, 22, 23, 24, 25, 26};

    {
        std::ofstream out(filePath, std::ios::binary | std::ios::trunc);
        ASSERT_TRUE(out.good());
        out.write(reinterpret_cast<const char*>(blob.data()), static_cast<std::streamsize>(blob.size()));
    }

    {
        FSAccessManager<> accessor(filePathStr);

        auto buffer = accessor.readInternal(2, BufferSpecs{1, 3, 0});
        ASSERT_NE(buffer, nullptr);
        ASSERT_EQ(buffer->getBuffer().size(), 3);
        ASSERT_EQ(std::memcmp(buffer->getBuffer().cpu_addr(), blob.data() + 2, 3), 0);

        DynamicBuffer external(BufferSpecs{1, 2, 0});
        ASSERT_NO_THROW(accessor.readExternal(0, external));
        ASSERT_EQ(std::memcmp(external.getBuffer().cpu_addr(), blob.data(), 2), 0);
    }

    std::error_code ec;
    std::filesystem::remove(filePath, ec);
}

// ---------------------------------------------------------------------------
// Regression tests: integer-overflow bypass of the bounds check
// Because both operands are size_t (64-bit unsigned), a crafted ELF field
// can cause the addition to wrap around to a small value that is less than
// mSize, silently bypassing the check.  A safe implementation must use an
// overflow-aware comparison such as:
//
//   offset > mSize || size > (mSize - offset)
//
// The tests below supply wrap-around (offset, size) pairs and assert that
// AccessError is thrown.

// Helper: the largest offset that, when added to kOverflowSize, wraps to a
// small value well below any realistic blob size.
static constexpr size_t kOverflowSize   = 0x20;
static constexpr size_t kOverflowOffset = SIZE_MAX - kOverflowSize + 1;
// kOverflowOffset + kOverflowSize == 0  (wraps to 0 on 64-bit unsigned)

TEST(Accessor, DDRAlwaysEmplace_ReadInternal_OverflowBypassThrows) {
    // A realistic blob — large enough that the wrapped sum (0) would be < mSize
    // were the vulnerable check used.
    std::vector<uint8_t> blob(256, 0xAB);
    DDRAccessManager<DDRAlwaysEmplace> accessor(blob.data(), blob.size());

    BufferSpecs specs{1, kOverflowSize, 0};
    // offset + kOverflowSize wraps to 0, which is < 256, so the naive check passes.
    // A correct overflow-safe check must detect offset >= mSize and throw.
    ASSERT_THROW((void)accessor.readInternal(kOverflowOffset, specs), AccessError)
        << "Bounds check bypassed via size_t overflow in DDRAccessManager<DDRAlwaysEmplace>::readInternal()";
}

TEST(Accessor, DDRNeverEmplace_ReadInternal_OverflowBypassThrows) {
    std::vector<uint8_t> blob(256, 0xCD);
    auto factory = std::make_shared<DynamicBufferFactory>();
    DDRAccessManager<DDRNeverEmplace, DynamicBufferFactory> accessor(blob.data(), blob.size(), factory);

    BufferSpecs specs{1, kOverflowSize, 0};
    ASSERT_THROW((void)accessor.readInternal(kOverflowOffset, specs), AccessError)
        << "Bounds check bypassed via size_t overflow in DDRAccessManager<DDRNeverEmplace,DynamicBufferFactory>::readInternal()";
}

TEST(Accessor, DDRBase_ReadExternal_OverflowBypassThrows) {
    std::vector<uint8_t> blob(256, 0xEF);
    DDRAccessManager<DDRAlwaysEmplace> accessor(blob.data(), blob.size());

    DynamicBuffer target(BufferSpecs{1, kOverflowSize, 0});
    // buffer.getBufferSpecs().size == kOverflowSize; kOverflowOffset + kOverflowSize wraps to 0.
    ASSERT_THROW(accessor.readExternal(kOverflowOffset, target), AccessError)
        << "Bounds check bypassed via size_t overflow in DDRAccessManagerBase::readExternal()";
}

TEST(Accessor, FSAccessManager_ReadInternal_OverflowBypassThrows) {
    const auto filePath = std::filesystem::temp_directory_path() / "accessor_overflow_test.bin";
    const auto filePathStr = filePath.string();
    const std::vector<uint8_t> blob(256, 0x12);

    {
        std::ofstream out(filePath, std::ios::binary | std::ios::trunc);
        ASSERT_TRUE(out.good());
        out.write(reinterpret_cast<const char*>(blob.data()), static_cast<std::streamsize>(blob.size()));
    }

    {
        FSAccessManager<> accessor(filePathStr);

        BufferSpecs specs{1, kOverflowSize, 0};
        ASSERT_THROW((void)accessor.readInternal(kOverflowOffset, specs), AccessError)
            << "Bounds check bypassed via size_t overflow in FSAccessManager::readInternal()";
    }

    std::error_code ec;
    std::filesystem::remove(filePath, ec);
}

TEST(Accessor, FSAccessManager_ReadExternal_OverflowBypassThrows) {
    const auto filePath = std::filesystem::temp_directory_path() / "accessor_overflow_ext_test.bin";
    const auto filePathStr = filePath.string();
    const std::vector<uint8_t> blob(256, 0x34);

    {
        std::ofstream out(filePath, std::ios::binary | std::ios::trunc);
        ASSERT_TRUE(out.good());
        out.write(reinterpret_cast<const char*>(blob.data()), static_cast<std::streamsize>(blob.size()));
    }

    {
        FSAccessManager<> accessor(filePathStr);

        DynamicBuffer target(BufferSpecs{1, kOverflowSize, 0});
        ASSERT_THROW(accessor.readExternal(kOverflowOffset, target), AccessError)
            << "Bounds check bypassed via size_t overflow in FSAccessManager::readExternal()";
    }

    std::error_code ec;
    std::filesystem::remove(filePath, ec);
}

}  // namespace
