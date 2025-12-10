//
// Copyright (C) 2023-2025 Intel Corporation
// SPDX-License-Identifier: Apache-2.0
//

#pragma once

#include <cstring>
#include <functional>
#include <memory>
#include <string>
#include <vector>

#include <vpux_headers/metadata_primitives.hpp>

namespace elf {

struct NetworkMetadata {
    Identification mIdentification;
    ResourceRequirements mResourceRequirements;
    std::vector<TensorRef> mNetInputs;
    std::vector<TensorRef> mNetOutputs;
    std::vector<TensorRef> mInTensorDescriptors;
    std::vector<TensorRef> mOutTensorDescriptors;
    std::vector<TensorRef> mProfilingOutputs;
    std::vector<PreprocessingInfo> mPreprocessingInfo;
    std::vector<OVNode> mOVParameters;
    std::vector<OVNode> mOVResults;
};

}  // namespace elf
