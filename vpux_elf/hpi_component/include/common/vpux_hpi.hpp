//
// Copyright (C) 2023-2025 Intel Corporation
// SPDX-License-Identifier: Apache-2.0
//

#pragma once

#include <memory>
#include <vector>
#include <vpux_elf/accessor.hpp>
#include <vpux_elf/utils/version.hpp>
#include <vpux_headers/buffer_manager.hpp>
#include <vpux_headers/device_buffer.hpp>
#include <vpux_headers/managed_buffer.hpp>
#include <vpux_headers/metadata.hpp>
#include <vpux_headers/platform.hpp>

namespace elf {

class VPUXLoader;
class HostParsedInferenceCommon;

// For documentation see vcl_device_desc_t in Driver/Plugin/VCL
struct DeviceDescriptor {
    uint64_t size;
    uint32_t deviceID;
    uint16_t revision;
    uint32_t tileCount;
};

// Structure that gathers configuration options for HPI instances.
// Subject to various additions/modifications in the future
struct HPIConfigs {
    elf::Version nnVersion;
    elf::platform::ArchKind archKind = elf::platform::ArchKind::UNKNOWN;
};

class VersionsProvider final {
public:
    explicit VersionsProvider(platform::ArchKind architecture);
    ~VersionsProvider();
    Version getLibraryELFVersion() const;
    Version getLibraryMIVersion() const;

private:
    std::unique_ptr<HostParsedInferenceCommon> impl;
};

class HostParsedInference final {
public:
    HostParsedInference(BufferManager* bufferMgr, AccessManager* accessMgr, elf::HPIConfigs hpiConfigs, DeviceDescriptor* deviceDescriptor = nullptr);
    HostParsedInference(const HostParsedInference& other);
    HostParsedInference(HostParsedInference&& other);
    ~HostParsedInference();

    HostParsedInference& operator=(const HostParsedInference& rhs);
    HostParsedInference& operator=(HostParsedInference&& rhs);

    DeviceBuffer getParsedInference() const;
    std::vector<DeviceBuffer> getAllocatedBuffers() const;
    std::vector<DeviceBuffer> getInputBuffers() const;
    std::vector<DeviceBuffer> getOutputBuffers() const;
    std::vector<DeviceBuffer> getProfBuffers() const;
    std::shared_ptr<const NetworkMetadata> getMetadata();
    std::shared_ptr<const elf::platform::PlatformInfo> getPlatformInfo();
    elf::Version getElfABIVersion() const;
    elf::Version getMIVersion() const;
    elf::Version getLibraryELFVersion() const;
    elf::Version getLibraryMIVersion() const;
    size_t getHPISize() const;

    void applyInputOutput(std::vector<DeviceBuffer>& inputs, std::vector<DeviceBuffer>& outputs,
                          std::vector<DeviceBuffer>& profiling);
    void load();

    void updateSharedScratchBuffers(const std::vector<DeviceBuffer>& buffers);

private:
    BufferManager* bufferManager;
    AccessManager* accessManager;
    std::shared_ptr<NetworkMetadata> metadata;
    std::shared_ptr<elf::platform::PlatformInfo> platformInfo;
    std::shared_ptr<ManagedBuffer> perfMetrics;
    std::vector<std::unique_ptr<VPUXLoader>> loaders;
    std::shared_ptr<AllocatedDeviceBuffer> parsedInference;
    elf::HPIConfigs hpiCfg;
    std::shared_ptr<AllocatedDeviceBuffer> entries;

    // helpers
    void readMetadata();
    void readPlatformInfo();
    std::shared_ptr<ManagedBuffer> readPerfMetrics();
    elf::Version readVersioningInfo(uint32_t versionType) const;
    void checkCompilerHash();
};

}  // namespace elf
