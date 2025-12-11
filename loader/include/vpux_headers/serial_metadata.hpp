//
// Copyright (C) 2023-2025 Intel Corporation
// SPDX-License-Identifier: Apache-2.0
//

#include <vpux_headers/metadata.hpp>
#include <vpux_headers/serial_struct_base.hpp>

#pragma once

namespace elf {

class SerialMetadata : public SerialStructBase {
public:
    SerialMetadata(NetworkMetadata& metaObj) {
        addElement(metaObj.mIdentification);
        addElement(metaObj.mResourceRequirements);
        addElementVector(metaObj.mNetInputs);
        addElementVector(metaObj.mNetOutputs);
        addElementVector(metaObj.mInTensorDescriptors);
        addElementVector(metaObj.mOutTensorDescriptors);
        addElementVector(metaObj.mProfilingOutputs);
        addElementVector(metaObj.mPreprocessingInfo);
        addElementVector(metaObj.mOVParameters);
        addElementVector(metaObj.mOVResults);
    }
};

using MetadataSerialization = SerialAccess<NetworkMetadata, SerialMetadata>;

}  // namespace elf
