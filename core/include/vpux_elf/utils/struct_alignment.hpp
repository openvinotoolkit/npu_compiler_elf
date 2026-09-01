//
// Copyright (C) 2026 Intel Corporation
// SPDX-License-Identifier: Apache-2.0
//

#pragma once

#if defined(_MSC_VER)
#define VPUX_ALIGNED_STRUCT(alignment) __declspec(align(alignment))
#elif defined(__GNUC__) || defined(__clang__)
#define VPUX_ALIGNED_STRUCT(alignment) __attribute__((aligned(alignment)))
#else
#error Define alignment macro
#endif
