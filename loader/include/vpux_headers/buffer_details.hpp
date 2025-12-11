//
// Copyright (C) 2023-2025 Intel Corporation
// SPDX-License-Identifier: Apache-2.0
//

#pragma once

struct BufferDetails {
    bool mHasData = false;
    bool mIsShared = false;
    bool mIsProcessed = false;

    BufferDetails() = default;
};
