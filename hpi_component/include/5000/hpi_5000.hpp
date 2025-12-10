//
// Copyright (C) 2025 Intel Corporation
// SPDX-License-Identifier: Apache-2.0
//

#pragma once

#include <hpi_4000.hpp>

namespace elf {
// Derive from 4000 class and override only differences
class HostParsedInference_5000 : public HostParsedInference_4000_Base {
public:
    explicit HostParsedInference_5000(elf::platform::ArchKind archKind);
    elf::Version getELFLibABIVersion() const override;
};

}  // namespace elf
