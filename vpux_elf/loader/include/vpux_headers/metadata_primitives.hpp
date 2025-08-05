//
// Copyright (C) 2023-2025 Intel Corporation
// SPDX-License-Identifier: Apache-2.0
//

#pragma once

#include <cstddef>
#include <cstdint>

#if defined(_MSC_VER)
#define VPUX_ALIGNED_STRUCT(alignment) __declspec(align(alignment))
#elif defined(__GNUC__) || defined(__clang__)
#define VPUX_ALIGNED_STRUCT(alignment) __attribute__((aligned(alignment)))
#else
#error Define alignment macro
#endif

#pragma pack(push, 1)

namespace elf {

constexpr uint8_t MAX_TENSOR_REF_DIMS = 8;
constexpr uint8_t MAX_TENSOR_REF_STRIDES = MAX_TENSOR_REF_DIMS + 1;
constexpr uint8_t MAX_METADATA_IO = 32;
constexpr uint8_t MAX_OV_NODES = MAX_METADATA_IO;

// Common string size used by the drivers
// It is highly recommended to keep this size identical between loader and drivers
constexpr uint16_t MAX_STRING_LEN = 256;

using BasicString = char[MAX_STRING_LEN];
using ArchName = BasicString;
using BlobName = BasicString;
using TensorName = BasicString;

// The enums below are used by the compiler and by the L0 UMD. They are used to pass information from the compiler to
// L0 UMD. The loader does not use them and acts as a simple carrier of opaque data.
// All conversions from ELF types to L0 types are done by L0 UMD. This means changing them can break compatibility and
// it must be done only with great care.
//
// Compatibility-breaking changes (require at least a minor version update):
//  - modifying value of an enum label (e.g. chaning DType_FP32 value from 2 to 100)
//
// Build-breaking changes (require code changes in compiler and/or L0 UMD):
//  - renaming an enum label (e.g. renaming DType_FP8 to DType_F8E5M2)
//
// To avoid unnecessarily breaking compatibility, new types must always be added at the end of the list.
// Ideally, the loader should not define these types and simply treat them as opaque data.

enum DType {
    DType_NOT_SET = 0,
    DType_FP64 = 1,
    DType_FP32 = 2,
    DType_FP16 = 3,
    DType_F8E5M2 = 4,
    DType_U64 = 5,
    DType_U32 = 6,
    DType_U16 = 7,
    DType_U8 = 8,
    DType_I64 = 9,
    DType_I32 = 10,
    DType_I16 = 11,
    DType_I8 = 12,
    DType_I4 = 13,
    DType_I2 = 14,
    DType_I4X = 15,
    DType_BIN = 16,
    DType_LOG = 17,
    DType_I2X = 18,
    DType_BFP16 = 19,
    DType_U4 = 20,
    DType_F8E4M3FN = 21,
    DType_F8E8M0 = 22,
    DType_MIN = DType_NOT_SET,
    DType_MAX = DType_F8E8M0
};

enum PreProcessColorSpace {
    PreProcessColorSpace_DEFAULT = 0,
    PreProcessColorSpace_BGR = 1,
    PreProcessColorSpace_RGB = 2,
    PreProcessColorSpace_NV12 = 3,
    PreProcessColorSpace_I420 = 4,
    PreProcessColorSpace_MIN = PreProcessColorSpace_DEFAULT,
    PreProcessColorSpace_MAX = PreProcessColorSpace_I420
};

enum PreProcessResizeAlgorithm {
    PreProcessResizeAlgorithm_NO_RESIZE = 0,
    PreProcessResizeAlgorithm_RESIZE_BILINEAR = 1,
    PreProcessResizeAlgorithm_RESIZE_AREA = 2,
    PreProcessResizeAlgorithm_MIN = PreProcessResizeAlgorithm_NO_RESIZE,
    PreProcessResizeAlgorithm_MAX = PreProcessResizeAlgorithm_RESIZE_AREA
};

enum OVNodeType {
    OVNodeType_UNDEFINED = 0,
    OVNodeType_DYNAMIC = 1,
    OVNodeType_BOOLEAN = 2,
    OVNodeType_BF16 = 3,
    OVNodeType_F16 = 4,
    OVNodeType_F32 = 5,
    OVNodeType_F64 = 6,
    OVNodeType_I4 = 7,
    OVNodeType_I8 = 8,
    OVNodeType_I16 = 9,
    OVNodeType_I32 = 10,
    OVNodeType_I64 = 11,
    OVNodeType_U1 = 12,
    OVNodeType_U4 = 13,
    OVNodeType_U8 = 14,
    OVNodeType_U16 = 15,
    OVNodeType_U32 = 16,
    OVNodeType_U64 = 17,
    OVNodeType_F8E4M3FN = 18,
    OVNodeType_F8E5M2 = 19,
    OVNodeType_NF4 = 20,
    OVNodeType_F8E8M0 = 21,
    OVNodeType_I2 = 22,
    OVNodeType_U2 = 23,
    OVNodeType_MIN = OVNodeType_UNDEFINED,
    OVNodeType_MAX = OVNodeType_U2,
};

struct VPUX_ALIGNED_STRUCT(8) Identification {
    // Contains the VPU architecture name null-terminated string provided by the compiler.
    // The loader expects an identical string to the one provided by the comiler.
    ArchName arch_name;
    // Contains the network name null-terminated string provided by the compiler.
    // If no name is provided by the compiler, a default name is used.
    // The driver expects an identical string as initially provided to the compiler.
    BlobName blob_name;
};

struct VPUX_ALIGNED_STRUCT(8) TensorRef {
    uint64_t strides[MAX_TENSOR_REF_STRIDES];
    uint32_t dimensions[MAX_TENSOR_REF_DIMS];
    TensorName name;
    uint64_t order;
    DType data_type;
    uint32_t dimensions_size;
    uint32_t strides_size;
    uint8_t pad1_[4] = {0};
};

static_assert(sizeof(TensorRef) == 384, "TensorRef size != 384");
static_assert(offsetof(TensorRef, name) % 8 == 0, "Alignment error");

struct VPUX_ALIGNED_STRUCT(4) PreprocessingInfo {
    TensorName input_name;
    PreProcessColorSpace input_format;
    PreProcessColorSpace output_format;
    PreProcessResizeAlgorithm algorithm;
};

static_assert(sizeof(PreprocessingInfo) == 268, "PreprocessingInfo size != 268");
static_assert(offsetof(PreprocessingInfo, input_format) % 8 == 0, "Alignment error");

struct VPUX_ALIGNED_STRUCT(8) OVNode {
    TensorName tensor_names[MAX_METADATA_IO];
    uint64_t shape[MAX_TENSOR_REF_DIMS];
    TensorName friendly_name;
    TensorName input_name;
    OVNodeType type;
    uint32_t shape_size;
    uint32_t tensor_names_count = 0;
    uint8_t pad_[4] = {0};
};

static_assert(sizeof(OVNode) == 8784, "OVNode size != 8784");

struct VPUX_ALIGNED_STRUCT(4) ResourceRequirements {
    uint32_t nn_slice_length_;
    uint8_t pad_[6] = {0};
    uint8_t nn_slice_count_;
    uint8_t nn_barriers_;
};

static_assert(sizeof(ResourceRequirements) == 12, "ResourceRequirements size != 12");

#pragma pack(pop)

}  // namespace elf
