//
// Copyright (C) 2023-2025 Intel Corporation
// SPDX-License-Identifier: Apache-2.0
//

#pragma once

#include <unordered_map>
#include <vector>

#include <vpux_elf/utils/log.hpp>
#include <vpux_headers/buffer_details.hpp>
#include <vpux_headers/buffer_manager.hpp>
#include <vpux_headers/buffer_specs.hpp>
#include <vpux_headers/device_buffer.hpp>
#include <vpux_headers/managed_buffer.hpp>

namespace elf {

class DeviceBufferContainer {
public:
    using BufferType = ManagedBuffer;
    using BufferPtr = std::shared_ptr<BufferType>;

    struct BufferInfo {
        BufferPtr mBuffer = nullptr;
        BufferDetails mBufferDetails = {};
    };

    using BufferMap = std::unordered_map<size_t, BufferInfo>;

    DeviceBufferContainer(BufferManager* bManager);
    DeviceBufferContainer(const DeviceBufferContainer& other);
    DeviceBufferContainer(DeviceBufferContainer&&) = default;
    ~DeviceBufferContainer() = default;
    DeviceBufferContainer& operator=(const DeviceBufferContainer& rhs);
    DeviceBufferContainer& operator=(DeviceBufferContainer&&) = default;

    auto cbegin() const {
        return mBufferMap.cbegin();
    }
    auto cend() const {
        return mBufferMap.cend();
    }
    auto begin() {
        return mBufferMap.begin();
    }
    auto end() {
        return mBufferMap.end();
    }

    BufferPtr buildAllocatedDeviceBuffer(BufferSpecs bSpecs);
    BufferInfo& safeInitBufferInfoAtIndex(size_t index);
    BufferInfo& getBufferInfoFromIndex(size_t index);
    bool hasBufferInfoAtIndex(size_t index);
    size_t getBufferInfoCount();
    std::vector<DeviceBuffer> getBuffersAsVector() const;

private:
    BufferMap mBufferMap;
    BufferManager* mBufferManager;

    void copyBufferMap(const BufferMap& otherBufferMap);
};

}  // namespace elf
