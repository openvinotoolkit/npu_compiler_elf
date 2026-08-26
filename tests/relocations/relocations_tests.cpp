//
// Copyright (C) 2025-2026 Intel Corporation.
// SPDX-License-Identifier: Apache-2.0
//

//

#include <stdint.h>

#include <gtest/gtest.h>
#include <nnrt_headers_40xx.hpp>
#include <vpux_headers/relocations.hpp>

// TODO: move to utils
#define OV_ASSERT_NO_THROW(statement) OV_ASSERT_NO_THROW_(statement, GTEST_FATAL_FAILURE_)
#define OV_ASSERT_NO_THROW_(statement, fail)                              \
    GTEST_AMBIGUOUS_ELSE_BLOCKER_                                         \
    if (::testing::internal::AlwaysTrue()) {                              \
        try {                                                             \
            GTEST_SUPPRESS_UNREACHABLE_CODE_WARNING_BELOW_(statement);    \
        } catch (const std::exception& e) {                               \
            fail("Expected: " #statement " doesn't throw an exception.\n" \
                 "  Actual: it throws.")                                  \
                    << e.what();                                          \
        } catch (...) {                                                   \
            fail("Expected: " #statement " doesn't throw an exception.\n" \
                 "  Actual: it throws.");                                 \
        }                                                                 \
    }

using namespace elf;
using namespace elf::relocations;

namespace {

struct ReduceDmaTestsParams {
    std::string testName;
    uint32_t dmaShapes[DMA_SYMBOL_MAX_TENSOR_DIMENSIONS];
    uint32_t dmaStrides[DMA_SYMBOL_MAX_TENSOR_DIMENSIONS];
    std::array<uint32_t, DMA_SYMBOL_MAX_TENSOR_DIMENSIONS> expectedReducedDmaShapes;
    std::array<uint32_t, DMA_SYMBOL_MAX_TENSOR_DIMENSIONS> expectedReducedDmaStrides;
    uint32_t dmaSize;
};

class ReduceDmaTest : public testing::TestWithParam<ReduceDmaTestsParams> {};

TEST_P(ReduceDmaTest, ReduceResultsAreCorrect) {
    auto params = GetParam();

    std::array<uint32_t, DMA_SYMBOL_MAX_TENSOR_DIMENSIONS> reducedDmaShapes{1, 1, 1, 1, 1, 1};
    std::array<uint32_t, DMA_SYMBOL_MAX_TENSOR_DIMENSIONS> reducedDmaStrides{0, 0, 0, 0, 0, 0};

    reduceDmaDims(params.dmaShapes, params.dmaStrides, params.dmaSize, reducedDmaShapes, reducedDmaStrides);

    for (size_t idx = 0; idx < DMA_SYMBOL_MAX_TENSOR_DIMENSIONS; idx++) {
        ASSERT_EQ(reducedDmaShapes[idx], params.expectedReducedDmaShapes[idx]);
        ASSERT_EQ(reducedDmaStrides[idx], params.expectedReducedDmaStrides[idx]);
    }
}

INSTANTIATE_TEST_SUITE_P(ReduceDmaTestSuite, ReduceDmaTest,
                         testing::Values(ReduceDmaTestsParams{"CompactDmaByteElement",
                                                              {6, 2, 4, 1, 1, 1},
                                                              {1, 6, 12, 48, 0, 0},
                                                              {48, 1, 1, 1, 1, 1},
                                                              {1, 0, 0, 0, 0, 0},
                                                              1},
                                         ReduceDmaTestsParams{"ContinuousDmaSlicedOnInnermostDimByteElement",
                                                              {3, 2, 4, 1, 1, 1},
                                                              {1, 6, 12, 48, 0, 0},
                                                              {3, 2, 4, 1, 1, 1},
                                                              {1, 6, 12, 48, 0, 0},
                                                              1},
                                         ReduceDmaTestsParams{"ContinuousDmaSlicedOnOuterDimByteElement",
                                                              {6, 2, 2, 1, 1, 1},
                                                              {1, 6, 12, 48, 0, 0},
                                                              {24, 1, 1, 1, 1, 1},
                                                              {1, 48, 0, 0, 0, 0},
                                                              1},
                                         ReduceDmaTestsParams{"ContinuousDmaSlicedOnMiddleDimByteElement",
                                                              {6, 2, 4, 1, 10, 1},
                                                              {1, 6, 12, 48, 96, 960},
                                                              {48, 10, 1, 1, 1, 1},
                                                              {1, 96, 960, 0, 0, 0},
                                                              1},
                                         ReduceDmaTestsParams{"StridedDmaSlicedOnInnermostDimByteElement",
                                                              {6, 2, 4, 1, 1, 1},
                                                              {2, 12, 24, 96, 0, 0},
                                                              {1, 6, 2, 4, 1, 1},
                                                              {1, 2, 12, 24, 96, 0},
                                                              1},
                                         ReduceDmaTestsParams{"CompactDmaNonByteElement",
                                                              {6, 2, 4, 1, 1, 1},
                                                              {1, 6, 12, 48, 0, 0},
                                                              {192, 1, 1, 1, 1, 1},
                                                              {4, 0, 0, 0, 0, 0},
                                                              4},
                                         ReduceDmaTestsParams{"ContinuousDmaSlicedOnInnermostDimNonByteElement",
                                                              {3, 2, 4, 1, 1, 1},
                                                              {1, 6, 12, 48, 0, 0},
                                                              {12, 2, 4, 1, 1, 1},
                                                              {4, 24, 48, 192, 0, 0},
                                                              4},
                                         ReduceDmaTestsParams{"ContinuousDmaSlicedOnOuterDimNonByteElement",
                                                              {6, 2, 2, 1, 1, 1},
                                                              {1, 6, 12, 48, 0, 0},
                                                              {96, 1, 1, 1, 1, 1},
                                                              {4, 192, 0, 0, 0, 0},
                                                              4},
                                         ReduceDmaTestsParams{"ContinuousDmaSlicedOnMiddleDimNonByteElement",
                                                              {6, 2, 4, 1, 10, 1},
                                                              {1, 6, 12, 48, 96, 960},
                                                              {192, 10, 1, 1, 1, 1},
                                                              {4, 384, 3840, 0, 0, 0},
                                                              4},
                                         ReduceDmaTestsParams{"StridedDmaSlicedOnInnermostDimNonByteElement",
                                                              {6, 2, 4, 1, 1, 1},
                                                              {2, 12, 24, 96, 0, 0},
                                                              {4, 6, 2, 4, 1, 1},
                                                              {4, 8, 48, 96, 384, 0},
                                                              4}),
                         [](const testing::TestParamInfo<ReduceDmaTestsParams>& info) {
                             return info.param.testName;
                         });

struct TileAddressCalculationParams {
    std::string testName;
    uint32_t tileOffsets[DMA_SYMBOL_MAX_TENSOR_DIMENSIONS];
    uint32_t strides[DMA_SYMBOL_MAX_TENSOR_DIMENSIONS];
    uint64_t baseAddress;
    uint64_t expectedAddress;
    uint32_t elementSize;
};

class TileAddressCalculationTest : public testing::TestWithParam<TileAddressCalculationParams> {};

TEST_P(TileAddressCalculationTest, ResultsAreCorrect) {
    auto params = GetParam();

    auto actualAddress =
            calculateDmaAddress(params.baseAddress, params.tileOffsets, params.strides, params.elementSize);

    ASSERT_EQ(actualAddress, params.expectedAddress);
}

INSTANTIATE_TEST_SUITE_P(TileAddressCalculationTestSuite, TileAddressCalculationTest,
                         testing::Values(TileAddressCalculationParams{"NoOffsets",
                                                                      {0, 0, 0, 0, 0, 0},
                                                                      {1, 2, 3, 4, 5, 6},
                                                                      0xA0000000,
                                                                      0xA0000000,
                                                                      1},
                                         TileAddressCalculationParams{"OffsetOnFirstDimByteElement",
                                                                      {2, 0, 0, 0, 0, 0},
                                                                      {2, 4, 8, 16, 0, 0},
                                                                      0xA0000000,
                                                                      0xA0000004,
                                                                      1},
                                         TileAddressCalculationParams{"OffsetOnMultipleDimsByteElement",
                                                                      {2, 0, 4, 0, 0, 0},
                                                                      {2, 4, 8, 16, 0, 0},
                                                                      0xA0000000,
                                                                      0xA0000024,
                                                                      1},
                                         TileAddressCalculationParams{"OffsetOnFirstDimNonByteElement",
                                                                      {2, 0, 0, 0, 0, 0},
                                                                      {1, 2, 3, 4, 5, 6},
                                                                      0xA0000000,
                                                                      0xA0000008,
                                                                      4},
                                         TileAddressCalculationParams{"OffsetOnMultipleDimsNonByteElement",
                                                                      {2, 0, 4, 3, 0, 0},
                                                                      {2, 4, 8, 16, 0, 0},
                                                                      0xA0000000,
                                                                      0xA0000150,
                                                                      4}),
                         [](const testing::TestParamInfo<TileAddressCalculationParams>& info) {
                             return info.param.testName;
                         });

struct BitAddressCalculationParams {
    std::string testName;
    uint32_t tileOffsets[DMA_SYMBOL_MAX_TENSOR_DIMENSIONS];
    uint32_t strides[DMA_SYMBOL_MAX_TENSOR_DIMENSIONS];
    uint64_t baseAddress;
    uint64_t expectedAddress;
    uint32_t elementSize;
};

class BitAddressCalculationTest : public testing::TestWithParam<BitAddressCalculationParams> {};

TEST_P(BitAddressCalculationTest, ResultsAreCorrect) {
    auto params = GetParam();

    uint64_t actualAddress = 0;
    OV_ASSERT_NO_THROW(actualAddress = calculateDmaBitAddress(params.baseAddress, params.tileOffsets, params.strides,
                                                              params.elementSize));

    ASSERT_EQ(actualAddress, params.expectedAddress);
}

INSTANTIATE_TEST_SUITE_P(BitAddressCalculationTestSuite, BitAddressCalculationTest,
                         testing::Values(BitAddressCalculationParams{"NoOffsets",
                                                                     {0, 0, 0, 0, 0, 0},
                                                                     {8, 16, 24, 32, 40, 48},
                                                                     0xA0000000,
                                                                     0xA0000000,
                                                                     1},
                                         BitAddressCalculationParams{"OffsetOnFirstDimByteAligned",
                                                                     {2, 0, 0, 0, 0, 0},
                                                                     {16, 32, 64, 128, 0, 0},
                                                                     0xA0000000,
                                                                     0xA0000004,
                                                                     1},
                                         BitAddressCalculationParams{"OffsetOnMultipleDimsByteAligned",
                                                                     {2, 0, 4, 0, 0, 0},
                                                                     {16, 32, 64, 128, 0, 0},
                                                                     0xA0000000,
                                                                     0xA0000024,
                                                                     1},
                                         BitAddressCalculationParams{"SubByteElementStillByteAlignedOverall",
                                                                     // 4-bit elements: 2*4bits*4 + 4*16bits*4 = 32 +
                                                                     // 256 = 288 bits = 36 bytes
                                                                     {2, 0, 4, 0, 0, 0},
                                                                     {4, 8, 16, 32, 0, 0},
                                                                     0xA0000000,
                                                                     0xA0000024,
                                                                     4}),
                         [](const testing::TestParamInfo<BitAddressCalculationParams>& info) {
                             return info.param.testName;
                         });

TEST(BitAddressCalculationErrorTest, ThrowsWhenBitOffsetIsNotByteAligned) {
    // 1 element offset on a dim with a 4-bit stride and elementSize=1 bit results in a 4-bit
    // (sub-byte) total offset, which must trigger an error.
    uint32_t tileOffsets[DMA_SYMBOL_MAX_TENSOR_DIMENSIONS] = {1, 0, 0, 0, 0, 0};
    uint32_t strides[DMA_SYMBOL_MAX_TENSOR_DIMENSIONS] = {4, 0, 0, 0, 0, 0};

    EXPECT_THROW(calculateDmaBitAddress(0xA0000000, tileOffsets, strides, 1), std::exception);
}

//
// dmaTaskInputBitRelocation / dmaTaskOutputBitRelocation tests
//
// These relocation functions reduce the DMA dims/strides (expressed in bits), compute the
// bit-granular start address, validate that the resulting width and strides are byte aligned,
// and populate the target DmaDescriptor fields (converting bit values to bytes).
//

namespace {

DmaSymbolEntry makeByteAlignedDmaSymbolEntry() {
    DmaSymbolEntry sym{};
    sym.address = 0x1000;
    // Compact i4-like (4 bit, sub-byte elements) shape {2, 3, 4}; dmaSize expressed in bits.
    // Total transfer is still byte aligned overall (4*3*2*4 = 96 bits = 12 bytes) even though
    // the element size itself is sub-byte.
    sym.dmaShapes[0] = 4;
    sym.dmaShapes[1] = 3;
    sym.dmaShapes[2] = 2;
    sym.dmaShapes[3] = 1;
    sym.dmaShapes[4] = 1;
    sym.dmaShapes[5] = 1;
    sym.dmaStrides[0] = 1;
    sym.dmaStrides[1] = 4;
    sym.dmaStrides[2] = 12;
    sym.dmaStrides[3] = 24;
    sym.dmaStrides[4] = 24;
    sym.dmaStrides[5] = 24;
    sym.dmaSize = 4;  // bits per element (sub-byte)
    // No tile offsets/strides so the base address is used as-is.
    for (auto& tileOffset : sym.tileOffsets) {
        tileOffset = 0;
    }
    for (auto& stride : sym.strides) {
        stride = 1;
    }
    return sym;
}

}  // namespace

TEST(DmaTaskBitRelocationTest, InputRelocationPopulatesDescriptorFromByteAlignedSymbol) {
    const auto sym = makeByteAlignedDmaSymbolEntry();
    elf::DmaDescriptor dmaTask{};

    OV_ASSERT_NO_THROW(dmaTaskInputBitRelocation(&dmaTask, sym, 0));

    // Fully compact shape -> reduceDmaDims collapses everything into width, in bits: 4*3*2*4 = 96 bits = 12 bytes.
    EXPECT_EQ(dmaTask.width.src, 12U);
    EXPECT_EQ(dmaTask.src_offsetof, sym.address);
}

TEST(DmaTaskBitRelocationTest, OutputRelocationPopulatesDescriptorFromByteAlignedSymbol) {
    const auto sym = makeByteAlignedDmaSymbolEntry();
    elf::DmaDescriptor dmaTask{};

    OV_ASSERT_NO_THROW(dmaTaskOutputBitRelocation(&dmaTask, sym, 0));

    EXPECT_EQ(dmaTask.width.dst, 12U);
    EXPECT_EQ(dmaTask.dst_offsetof, sym.address);
}

TEST(DmaTaskBitRelocationTest, InputRelocationThrowsWhenWidthIsNotByteAligned) {
    auto sym = makeByteAlignedDmaSymbolEntry();
    // Make the innermost (compact) size non byte aligned: 3 elements * 4 bits = 12 bits.
    sym.dmaShapes[0] = 3;
    sym.dmaSize = 4;
    sym.dmaStrides[0] = 1;
    sym.dmaStrides[1] = 3;
    sym.dmaStrides[2] = 3;
    sym.dmaStrides[3] = 3;
    sym.dmaStrides[4] = 3;
    sym.dmaStrides[5] = 3;

    elf::DmaDescriptor dmaTask{};
    EXPECT_THROW(dmaTaskInputBitRelocation(&dmaTask, sym, 0), std::exception);
}

TEST(DmaTaskBitRelocationTest, OutputRelocationThrowsWhenWidthIsNotByteAligned) {
    auto sym = makeByteAlignedDmaSymbolEntry();
    sym.dmaShapes[0] = 3;
    sym.dmaSize = 4;
    sym.dmaStrides[0] = 1;
    sym.dmaStrides[1] = 3;
    sym.dmaStrides[2] = 3;
    sym.dmaStrides[3] = 3;
    sym.dmaStrides[4] = 3;
    sym.dmaStrides[5] = 3;

    elf::DmaDescriptor dmaTask{};
    EXPECT_THROW(dmaTaskOutputBitRelocation(&dmaTask, sym, 0), std::exception);
}

TEST(DmaTaskBitRelocationTest, InputRelocationKeepsMultipleDimsWhenByteAlignedButNonCompact) {
    // dmaSize = 4 bits (sub-byte element, e.g. i4). dim0 {size=4, stride=1} is compact:
    // continuousSize = 4 * 4 bits = 16 bits. dim1 {size=2, stride=6} is non-compact
    // (6*4=24 bits != 16 bits), but still byte aligned, so reduceDmaDims must NOT collapse
    // everything into a single dimension. Trailing dims {size=1, stride=2} also resolve to a byte
    // aligned stride (2*4=8 bits), so the whole transfer stays byte aligned overall despite using
    // a sub-byte element size.
    auto sym = makeByteAlignedDmaSymbolEntry();
    sym.dmaShapes[0] = 4;
    sym.dmaShapes[1] = 2;
    sym.dmaShapes[2] = 1;
    sym.dmaShapes[3] = 1;
    sym.dmaShapes[4] = 1;
    sym.dmaShapes[5] = 1;
    sym.dmaSize = 4;
    sym.dmaStrides[0] = 1;
    sym.dmaStrides[1] = 6;
    sym.dmaStrides[2] = 2;
    sym.dmaStrides[3] = 2;
    sym.dmaStrides[4] = 2;
    sym.dmaStrides[5] = 2;

    elf::DmaDescriptor dmaTask{};
    OV_ASSERT_NO_THROW(dmaTaskInputBitRelocation(&dmaTask, sym, 0));

    // Innermost compact run: 4 elements * 4 bits = 16 bits = 2 bytes.
    EXPECT_EQ(dmaTask.width.src, 2U);
    // Second dim keeps its original size (2), stored as size - 1.
    EXPECT_EQ(dmaTask.dim_size_1.src, 1U);
    // Second dim stride: 6 * 4 bits = 24 bits = 3 bytes.
    EXPECT_EQ(dmaTask.stride_src_1, 3U);
    // Remaining dims: stride 2 * 4 bits = 8 bits = 1 byte, size collapses to 0 (size - 1 with size=1).
    EXPECT_EQ(dmaTask.dim_size_2.src, 0U);
    EXPECT_EQ(dmaTask.stride_src_2, 1U);
}

TEST(DmaTaskBitRelocationTest, InputRelocationThrowsWhenNonInnermostStrideIsNotByteAligned) {
    auto sym = makeByteAlignedDmaSymbolEntry();
    // With dmaSize=4 bits: dim0 {size=2, stride=1} is compact (continuousSize reaches 8 bits, byte
    // aligned), then dim1 {size=3, stride=3} is non-compact, producing reducedDmaStrides[1] = 3 * 4
    // = 12 bits, which is NOT byte aligned, while reducedDmaShapes[0] = 8 bits (byte aligned width).
    // This isolates the stride byte-alignment check from the width byte-alignment check.
    sym.dmaShapes[0] = 2;
    sym.dmaShapes[1] = 3;
    sym.dmaShapes[2] = 1;
    sym.dmaShapes[3] = 1;
    sym.dmaShapes[4] = 1;
    sym.dmaShapes[5] = 1;
    sym.dmaSize = 4;
    sym.dmaStrides[0] = 1;
    sym.dmaStrides[1] = 3;
    sym.dmaStrides[2] = 1;
    sym.dmaStrides[3] = 1;
    sym.dmaStrides[4] = 1;
    sym.dmaStrides[5] = 1;

    elf::DmaDescriptor dmaTask{};
    EXPECT_THROW(dmaTaskInputBitRelocation(&dmaTask, sym, 0), std::exception);
}

}  // namespace
