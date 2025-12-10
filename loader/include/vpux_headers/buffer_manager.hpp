//
// Copyright (C) 2023-2025 Intel Corporation
// SPDX-License-Identifier: Apache-2.0
//

#pragma once

#include <memory>
#include <vpux_elf/utils/error.hpp>
#include <vpux_headers/buffer_specs.hpp>
#include <vpux_headers/device_buffer.hpp>

namespace elf {

class BufferManager {
public:
    virtual DeviceBuffer allocate(const BufferSpecs& buffSpecs) = 0;
    virtual void deallocate(DeviceBuffer& devAddress) = 0;
    /// @brief
    /// This API is used by the loader to mark that it actively uses the DeviceBuffer.
    /// A successful lock call should ensure that the DeviceBuffer:
    ///  - has a valid cpu_addr
    ///  - remains in DDR while in use by the loader
    /// The driver-loader contract is not frozen yet, so below are a few cautious assumptions:
    ///  - the DeviceBuffer does not have a valid cpu_addr until lock is performed
    ///  - the sys calls behind the lock and unlock APIs might be state sensitive (i.e. an arbitrary call order is not
    ///    supported). Therefore, for every DeviceBuffer:
    ///    -> consider a lock counter initialized to 0 when the DeviceBuffer is created
    ///    -> every lock call increments the lock counter by 1
    ///    -> every unlock call decrements the lock counter by 1
    ///    -> incrementing from 1 is forbidden
    ///    -> decrementing from 0 is forbidden
    /// @param devAddress - DeviceBuffer reference
    virtual void lock(DeviceBuffer& devAddress) = 0;
    /// @brief This API releases a DeviceBuffer that was previously locked by a lock call.
    /// @param devAddress - DeviceBuffer reference
    virtual void unlock(DeviceBuffer& devAddress) = 0;
    virtual size_t copy(DeviceBuffer& to, const uint8_t* from, size_t count) = 0;
    virtual ~BufferManager() = default;
};

}  // namespace elf
