//
// Copyright (C) 2023-2025 Intel Corporation
// SPDX-License-Identifier: Apache-2.0
//

#include <utility>
#include <vpux_headers/device_buffer_container.hpp>
#include "vpux_elf/utils/error.hpp"
#include "vpux_elf/utils/utils.hpp"

namespace elf {

DeviceBufferContainer::DeviceBufferContainer(BufferManager* bManager): mBufferManager(bManager) {
}

DeviceBufferContainer::DeviceBufferContainer(const DeviceBufferContainer& other) {
    VPUX_ELF_LOG(LogLevel::LOG_TRACE, "Copying DeviceBuffer container");
    mBufferManager = other.mBufferManager;
    copyBufferMap(other.mBufferMap);
}

DeviceBufferContainer& DeviceBufferContainer::operator=(const DeviceBufferContainer& rhs) {
    if (this == &rhs) {
        return *this;
    }

    VPUX_ELF_LOG(LogLevel::LOG_TRACE, "Copying DeviceBuffer container");
    mBufferManager = rhs.mBufferManager;
    copyBufferMap(rhs.mBufferMap);
    return *this;
}

DeviceBufferContainer::BufferPtr DeviceBufferContainer::buildAllocatedDeviceBuffer(BufferSpecs bSpecs) {
    return std::make_shared<AllocatedDeviceBuffer>(mBufferManager, bSpecs);
}

DeviceBufferContainer::BufferInfo& DeviceBufferContainer::safeInitBufferInfoAtIndex(size_t index) {
    VPUX_ELF_THROW_WHEN(hasBufferInfoAtIndex(index), RuntimeError, "BufferInfo already exists at requested index");

    return mBufferMap[index] = {};
}

DeviceBufferContainer::BufferInfo& DeviceBufferContainer::getBufferInfoFromIndex(size_t index) {
    return mBufferMap.at(index);
}

bool DeviceBufferContainer::hasBufferInfoAtIndex(size_t index) {
    return (mBufferMap.find(index) != mBufferMap.end());
}

size_t DeviceBufferContainer::getBufferInfoCount() {
    return mBufferMap.size();
}

std::vector<DeviceBuffer> DeviceBufferContainer::getBuffersAsVector() const {
    std::vector<DeviceBuffer> devBuffersVector;
    devBuffersVector.reserve(mBufferMap.size());
    for (const auto& buffer : mBufferMap) {
        devBuffersVector.push_back((buffer.second).mBuffer->getBuffer());
    }
    return devBuffersVector;
}

void DeviceBufferContainer::copyBufferMap(const BufferMap& otherBufferMap) {
    VPUX_ELF_THROW_WHEN(&otherBufferMap == &mBufferMap, RuntimeError, "Cloning self map");
    for (auto& it : otherBufferMap) {
        auto& index = it.first;
        auto& bufferInfo = it.second;
        if (bufferInfo.mBufferDetails.mIsShared) {
            mBufferMap[index] = bufferInfo;
        } else {
            BufferInfo newBufferInfo;
            newBufferInfo.mBuffer = bufferInfo.mBuffer->createNew();
            newBufferInfo.mBufferDetails = bufferInfo.mBufferDetails;
            mBufferMap[index] = newBufferInfo;
        }
    }
}

}  // namespace elf
