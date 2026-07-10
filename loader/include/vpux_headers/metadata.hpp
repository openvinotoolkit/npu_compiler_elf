//
// Copyright (C) 2023-2026 Intel Corporation
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

    bool operator==(const NetworkMetadata& rhs) const {
        if (this != &rhs) {
            return (mIdentification == rhs.mIdentification && mResourceRequirements == rhs.mResourceRequirements &&
                    mNetInputs == rhs.mNetInputs && mNetOutputs == rhs.mNetOutputs &&
                    mInTensorDescriptors == rhs.mInTensorDescriptors &&
                    mOutTensorDescriptors == rhs.mOutTensorDescriptors && mProfilingOutputs == rhs.mProfilingOutputs &&
                    mPreprocessingInfo == rhs.mPreprocessingInfo && mOVParameters == rhs.mOVParameters &&
                    mOVResults == rhs.mOVResults);
        }
        return true;
    }
    bool operator!=(const NetworkMetadata& rhs) const {
        return (!(*this == rhs));
    }
};

}  // namespace elf
