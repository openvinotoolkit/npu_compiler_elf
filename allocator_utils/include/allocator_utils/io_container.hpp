//
// Copyright (C) 2026 Intel Corporation.
// SPDX-License-Identifier: Apache-2.0
//

#pragma once

#include <vector>

#include "vpux_headers/buffer_manager.hpp"
#include "vpux_headers/buffer_specs.hpp"
#include "vpux_headers/device_buffer.hpp"
#include "vpux_headers/device_buffer_container.hpp"

// Helper class for allocating and storing IO buffers for HPI object(s)
class IOBuffersContainer {
public:
    IOBuffersContainer(std::shared_ptr<elf::BufferManager> bufferManager,
                       const std::vector<elf::DeviceBuffer>& inputDescriptions,
                       const std::vector<elf::DeviceBuffer>& outputDescriptions,
                       const std::vector<elf::DeviceBuffer>& profilingDescriptions);

    std::vector<elf::DeviceBuffer>& getInputBuffers();
    std::vector<elf::DeviceBuffer>& getOutputBuffers();
    std::vector<elf::DeviceBuffer>& getProfilingBuffers();

    static void allocIO(elf::DeviceBufferContainer& bufferContainer,
                        const std::vector<elf::DeviceBuffer>& bufferSpecs);

private:
    // DeviceBufferContainer operates with raw pointer of BufferManager, so keep the BufferManager referenced to be able
    // to deallocate all buffers when destroying the DeviceBufferContainer objects
    std::shared_ptr<elf::BufferManager> _bufferManager;
    elf::DeviceBufferContainer _inputBuffersContainer;
    elf::DeviceBufferContainer _outputBuffersContainer;
    elf::DeviceBufferContainer _profilingBuffersContainer;

    std::vector<elf::DeviceBuffer> _inputBuffers = {};
    std::vector<elf::DeviceBuffer> _outputBuffers = {};
    std::vector<elf::DeviceBuffer> _profilingBuffers = {};
};
