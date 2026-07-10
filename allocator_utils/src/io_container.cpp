//
// Copyright (C) 2026 Intel Corporation.
// SPDX-License-Identifier: Apache-2.0
//

#include "allocator_utils/io_container.hpp"

IOBuffersContainer::IOBuffersContainer(std::shared_ptr<elf::BufferManager> bufferManager,
                                       const std::vector<elf::DeviceBuffer>& inputDescriptions,
                                       const std::vector<elf::DeviceBuffer>& outputDescriptions,
                                       const std::vector<elf::DeviceBuffer>& profilingDescriptions)
        : _bufferManager(bufferManager),
          _inputBuffersContainer(bufferManager.get()),
          _outputBuffersContainer(bufferManager.get()),
          _profilingBuffersContainer(bufferManager.get()) {
    allocIO(_inputBuffersContainer, inputDescriptions);
    allocIO(_outputBuffersContainer, outputDescriptions);
    allocIO(_profilingBuffersContainer, profilingDescriptions);

    _inputBuffers = _inputBuffersContainer.getBuffersAsVector();
    _outputBuffers = _outputBuffersContainer.getBuffersAsVector();
    _profilingBuffers = _profilingBuffersContainer.getBuffersAsVector();
}

std::vector<elf::DeviceBuffer>& IOBuffersContainer::getInputBuffers() {
    return _inputBuffers;
}

std::vector<elf::DeviceBuffer>& IOBuffersContainer::getOutputBuffers() {
    return _outputBuffers;
}

std::vector<elf::DeviceBuffer>& IOBuffersContainer::getProfilingBuffers() {
    return _profilingBuffers;
}

void IOBuffersContainer::allocIO(elf::DeviceBufferContainer& bufferContainer,
                                 const std::vector<elf::DeviceBuffer>& bufferSpecs) {
    for (size_t index = 0; index < bufferSpecs.size(); ++index) {
        auto& bufferInfo = bufferContainer.safeInitBufferInfoAtIndex(index);
        bufferInfo.mBuffer =
                bufferContainer.buildAllocatedDeviceBuffer(elf::BufferSpecs(1024, bufferSpecs[index].size(), 0));
    }
}
