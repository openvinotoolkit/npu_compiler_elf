//
// Copyright (C) 2023-2025 Intel Corporation
// SPDX-License-Identifier: Apache-2.0
//

#include "vpux_elf/utils/error.hpp"
#include "vpux_headers/managed_buffer.hpp"
#include "vpux_headers/platform.hpp"
#ifndef VPUX_ELF_LOG_UNIT_NAME
#define VPUX_ELF_LOG_UNIT_NAME "VpuxHpi"
#endif
// clang-format off
#include <vpux_loader/vpux_loader.hpp>
#include <vpux_elf/accessor.hpp>
#include <vpux_elf/utils/log.hpp>
#include <vpux_hpi.hpp>
#include <sstream>
#include <cstdlib>
#include <cstring>

#if defined(CONFIG_TARGET_SOC_3720) || defined(HOST_BUILD)
#include <hpi_3720.hpp>
#endif

#if defined(CONFIG_TARGET_SOC_4000) || defined(HOST_BUILD)
#include <hpi_4000.hpp>
#endif


#include <string.h>
// clang-format on

namespace elf {
namespace {

static std::unique_ptr<HostParsedInferenceCommon> getArchSpecificHPI(elf::platform::ArchKind archKind) {
    VPUX_ELF_LOG(LogLevel::LOG_DEBUG, "Creating specialized HPI for arch %u", archKind);

    std::unique_ptr<HostParsedInferenceCommon> archSpecificHPI;
    switch (archKind) {
#if defined(CONFIG_TARGET_SOC_3720) || defined(HOST_BUILD)
    case elf::platform::ArchKind::VPUX37XX:
        archSpecificHPI = std::make_unique<HostParsedInference_3720>();
        break;
#endif

#if defined(CONFIG_TARGET_SOC_4000) || defined(HOST_BUILD)
    case elf::platform::ArchKind::VPUX40XX:
        archSpecificHPI = std::make_unique<HostParsedInference_4000>(archKind);
        break;
#endif
    default:
        VPUX_ELF_THROW(RangeError, (elf::platform::stringifyArchKind(archKind) + " arch is not supported").c_str());
        break;
    }

    return archSpecificHPI;
}

}  // namespace

VersionsProvider::VersionsProvider(platform::ArchKind architecture): impl(getArchSpecificHPI(architecture)) {
}
VersionsProvider::~VersionsProvider() = default;
Version VersionsProvider::getLibraryELFVersion() const {
    return impl->getELFLibABIVersion();
}
Version VersionsProvider::getLibraryMIVersion() const {
    return impl->getStaticMIVersion();
}

std::shared_ptr<ManagedBuffer> HostParsedInference::readPerfMetrics() {
    const auto& sections = loaders.front()->getSectionsOfType(elf::VPU_SHT_PERF_METRICS);
    VPUX_ELF_THROW_WHEN(sections.size() > 1, RangeError, "Expected only a single section of performance metrics.");

    if (sections.size() == 1) {
        return sections[0];
    }

    VPUX_ELF_LOG(LogLevel::LOG_WARN, "No performance metrics. Default to be used!");
    return {};
}

void HostParsedInference::readMetadata() {
    const auto& sections = loaders.front()->getSectionsOfType(elf::VPU_SHT_NETDESC);
    VPUX_ELF_THROW_UNLESS(sections.size() == 1, RangeError, "Expected only one metadata section.");

    auto metadataLock = ElfBufferLockGuard(sections[0].get());
    auto metadataBufferPtr = sections[0]->getBuffer().cpu_addr();
    auto metadataBufferSize = sections[0]->getBuffer().size();
    metadata = MetadataSerialization::deserialize(metadataBufferPtr, metadataBufferSize);
}

void HostParsedInference::readPlatformInfo() {
    const auto& sections = loaders.front()->getSectionsOfType(elf::VPU_SHT_PLATFORM_INFO);
    VPUX_ELF_THROW_UNLESS(sections.size() == 1, RangeError, "Expected only one Platform Info section.");

    auto platformInfoLock = ElfBufferLockGuard(sections[0].get());
    auto platformInfoBufferPtr = sections[0]->getBuffer().cpu_addr();
    auto platformInfoBufferSize = sections[0]->getBuffer().size();
    platformInfo = elf::platform::PlatformInfoSerialization::deserialize(platformInfoBufferPtr, platformInfoBufferSize);
}

elf::Version HostParsedInference::readVersioningInfo(uint32_t versionType) const {
    const auto& noteSections = loaders.front()->getSectionsOfType(elf::SHT_NOTE);
    for (auto section : noteSections) {
        VPUX_ELF_THROW_UNLESS(section->getBuffer().size() == sizeof(elf::elf_note::VersionNote), SectionError,
                              "Wrong Versioning Note size");

        auto sectionLock = ElfBufferLockGuard(section.get());
        elf::elf_note::VersionNote elfABIVersionNote{};
        std::memcpy(&elfABIVersionNote, section->getBuffer().cpu_addr(), sizeof(elf::elf_note::VersionNote));
        if (elfABIVersionNote.n_type == versionType) {
            return elf::Version(elfABIVersionNote);
        }
    }
    VPUX_ELF_LOG(LogLevel::LOG_ERROR, "Could not retrieve versioning info of type %x", versionType);
    VPUX_ELF_THROW(RangeError, "Requested Versioning information was not found");
}

elf::Version HostParsedInference::getElfABIVersion() const {
    return readVersioningInfo(elf::elf_note::NT_GNU_ABI_TAG);
}

elf::Version HostParsedInference::getMIVersion() const {
    return readVersioningInfo(elf::elf_note::NT_NPU_MPI_VERSION);
}

elf::Version HostParsedInference::getLibraryELFVersion() const {
    return getArchSpecificHPI(hpiCfg.archKind)->getELFLibABIVersion();
}

elf::Version HostParsedInference::getLibraryMIVersion() const {
    return getArchSpecificHPI(hpiCfg.archKind)->getStaticMIVersion();
}

size_t HostParsedInference::getHPISize() const {
    return getArchSpecificHPI(hpiCfg.archKind)->getParsedInferenceBufferSpecs().size;
}

HostParsedInference::HostParsedInference(BufferManager* bufferMgr, AccessManager* accessMgr, elf::HPIConfigs hpiConfigs, DeviceDescriptor* deviceDescriptor)
        : bufferManager(bufferMgr), accessManager(accessMgr), hpiCfg(hpiConfigs) {

#ifdef NRELEASE
    static constexpr auto ELF_THROW_COMPATIBILITY_ERROR_NAME = "ELF_THROW_COMPATIBILITY_ERROR";
    const auto elfThrowCompatibilityErrorValue = std::getenv(ELF_THROW_COMPATIBILITY_ERROR_NAME);
    VPUX_ELF_THROW_WHEN(
        elfThrowCompatibilityErrorValue != nullptr &&
        (std::strncmp(elfThrowCompatibilityErrorValue, "1", sizeof("1")) == 0),
        CompatibilityError, "Compatibility error is forced by \"ELF_THROW_COMPATIBILITY_ERROR=1\"");
#endif

    // create the loader object to cache sections
    loaders.emplace_back(std::make_unique<VPUXLoader>(accessMgr, bufferMgr));

    auto& expectedArch = hpiConfigs.archKind;
    auto archSpecificHpi = getArchSpecificHPI(expectedArch);
    // Check ELF Library ABI Compatibility
    elf::Version::checkVersionCompatibility(getLibraryELFVersion(), getElfABIVersion(),
                                            elf::VersionType::ELF_ABI_VERSION);

    readMetadata();
    readPlatformInfo();

    auto archKind = platformInfo->mArchKind;

    // Check if compiled ELF arch and HPI arch match
    if (archKind != expectedArch) {
        std::stringstream logBuffer;
        logBuffer << "Incorrect arch. Expected: " << elf::platform::stringifyArchKind(expectedArch)
                  << " vs Received: " << elf::platform::stringifyArchKind(archKind);
        VPUX_ELF_THROW(CompatibilityError, logBuffer.str().c_str());
    }

    // Check Mapped Inference Compatibility
    auto& nnExpectedVersion = hpiConfigs.nnVersion;

    // If Expected Mapped Inference version is not provided via HPI config, fall back to local version
    if (!nnExpectedVersion.checkValidity()) {
        nnExpectedVersion = getLibraryMIVersion();
    }

    elf::Version::checkVersionCompatibility(nnExpectedVersion, getMIVersion(),
                                            elf::VersionType::MAPPED_INFERENCE_VERSION);

    // Check ELF Library tile count Compatibility
    auto tileCount = metadata->mResourceRequirements.nn_slice_count_;
    // get hardware tile count, archKind has already been checked above
    uint8_t hardwareTileCount = elf::platform::getHardwareTileCount(archKind);

    if (deviceDescriptor != nullptr) {
        // IMD case is allowed to omit device descriptor for now

        VPUX_ELF_THROW_WHEN(deviceDescriptor->size < sizeof(DeviceDescriptor), ArgsError, "DeviceDescriptor is passed, but its size is too small");

        // tileCount from DeviceDescriptor is always present and "SKU-aware"
        // e.g. if we are running on 5T NPU4 SKU it will report 5 instead of 6
        // in contrast to getHardwareTileCount above

        // cast to uint8_t even though DeviceDescriptor contains uint32_t because
        // tileCount from the blob is uint8_t anyway, so no point in upcasting here
        hardwareTileCount = static_cast<uint8_t>(deviceDescriptor->tileCount);
    }

    // throw exception if tile count is greater than hardware tile count
    if (tileCount > hardwareTileCount) {
        std::stringstream tileCountLogBuffer;
        tileCountLogBuffer << "Incorrect tile count. Requested tile count '" << static_cast<int>(tileCount)
                           << "' exceeds hardware tile count '" << static_cast<int>(hardwareTileCount) << "'";
        VPUX_ELF_THROW(CompatibilityError, tileCountLogBuffer.str().c_str());
    }

    if (tileCount > hardwareTileCount / 2
        && archKind != elf::platform::ArchKind::VPUX30XX && archKind != elf::platform::ArchKind::VPUX37XX) {
        loaders.front()->setInferencesMayBeRunInParallel(false);
    }
}

void HostParsedInference::load() {
    auto archSpecificHpi = getArchSpecificHPI(platformInfo->mArchKind);

    const auto symbolSectionTypes = archSpecificHpi->getSymbolSectionTypes();
    auto symTabOverrideMode = archSpecificHpi->getSymbolSectionTypes().size() == 0 ? false : true;

    std::vector<uint64_t> entriesVct;
    if (platformInfo->mArchKind == elf::platform::ArchKind::VPUX37XX &&
        metadata->mResourceRequirements.nn_slice_count_ < archSpecificHpi->getArchTilesCount()) {
        entries = std::make_shared<AllocatedDeviceBuffer>(
                bufferManager, archSpecificHpi->getEntryBufferSpecs(archSpecificHpi->getArchTilesCount()));

        // Lock entries buffers to ensure valid cpu_va
        // dtor of ElfBufferLockGuard will automatically call unlock
        auto entriesLock = ElfBufferLockGuard(entries.get());

        entriesVct.reserve(loaders.size());
        auto entrySize = entries->getBufferSpecs().size / archSpecificHpi->getArchTilesCount();
        for (uint32_t idx = 0; idx < archSpecificHpi->getArchTilesCount(); ++idx) {
            const auto symbolTable = archSpecificHpi->getSymbolTable(idx);
            if (idx == 0) {
                // first loader is created.
                loaders[idx]->load(symbolTable, symTabOverrideMode, symbolSectionTypes);
            } else {
                // create other loaders using the first one that has
                // been initialized.
                // Pass the symbol table to override the symbols from the previous loader
                loaders.push_back(std::make_unique<VPUXLoader>(*loaders.front(), symbolTable));
            }
            auto entryDeviceBuffer = loaders[idx]->getEntry();
            auto entryLock = ElfBufferLockGuard(entryDeviceBuffer.get());

            std::memcpy(entries->getBuffer().cpu_addr() + idx * entrySize,
                        (void*)entryDeviceBuffer->getBuffer().cpu_addr(), entrySize);
            entriesVct.push_back((entries->getBuffer().vpu_addr() + idx * entrySize));
        }
    } else {
        auto symbolTable = archSpecificHpi->getSymbolTable(metadata->mResourceRequirements.nn_slice_count_);
        loaders.front()->load(symbolTable, symTabOverrideMode, symbolSectionTypes);
        entriesVct.push_back(loaders.front()->getEntry()->getBuffer().vpu_addr());
    }

    parsedInference =
            std::make_shared<AllocatedDeviceBuffer>(bufferManager, archSpecificHpi->getParsedInferenceBufferSpecs());
    auto parsedInferenceLock = ElfBufferLockGuard(parsedInference.get());

    auto parsedInferenceBuffer = parsedInference->getBuffer();
    perfMetrics = readPerfMetrics();
    auto perfMetricsLock = ElfBufferLockGuard(perfMetrics.get());
    auto perfMetricsPtr = perfMetrics ? reinterpret_cast<uint64_t*>(perfMetrics->getBuffer().cpu_addr()) : nullptr;
    archSpecificHpi->setHostParsedInference(parsedInferenceBuffer, entriesVct, metadata->mResourceRequirements,
                                            perfMetricsPtr);

}

HostParsedInference::HostParsedInference(const HostParsedInference& other)
        : bufferManager(other.bufferManager),
          accessManager(other.accessManager),
          metadata(other.metadata),
          platformInfo(other.platformInfo),
          perfMetrics(other.perfMetrics) {
    auto archSpecificHpi = getArchSpecificHPI(platformInfo->mArchKind);
    // Use clone semantics here by copy-constructing the loader object
    loaders.reserve(other.loaders.size());
    std::vector<uint64_t> entriesVct;
    entriesVct.reserve(other.loaders.size());
    if (platformInfo->mArchKind == elf::platform::ArchKind::VPUX37XX &&
        metadata->mResourceRequirements.nn_slice_count_ < archSpecificHpi->getArchTilesCount()) {
        entries = std::make_shared<AllocatedDeviceBuffer>(bufferManager,
                                                          archSpecificHpi->getEntryBufferSpecs(other.loaders.size()));

        auto entriesLock = ElfBufferLockGuard(entries.get());

        auto entrySize = entries->getBufferSpecs().size / other.loaders.size();
        for (size_t idx = 0; idx < other.loaders.size(); ++idx) {
            loaders.push_back(std::make_unique<VPUXLoader>(*other.loaders[idx]));

            auto entryDeviceBuffer = loaders[idx]->getEntry();
            auto entryLock = ElfBufferLockGuard(entryDeviceBuffer.get());

            std::memcpy(entries->getBuffer().cpu_addr() + idx * entrySize,
                        (void*)entryDeviceBuffer->getBuffer().cpu_addr(), entrySize);
            entriesVct.push_back((entries->getBuffer().vpu_addr() + idx * entrySize));
        }
    } else {
        loaders.push_back(std::make_unique<VPUXLoader>(*other.loaders.front()));
        entriesVct.push_back(loaders.front()->getEntry()->getBuffer().vpu_addr());
    }

    // Every new loader object means a new parsedInference struct as well
    parsedInference =
            std::make_shared<AllocatedDeviceBuffer>(bufferManager, archSpecificHpi->getParsedInferenceBufferSpecs());
    auto parsedInferenceLock = ElfBufferLockGuard(parsedInference.get());

    auto parsedInferenceBuffer = parsedInference->getBuffer();
    auto perfMetricsLock = ElfBufferLockGuard(perfMetrics.get());
    auto perfMetricsPtr = perfMetrics ? reinterpret_cast<uint64_t*>(perfMetrics->getBuffer().cpu_addr()) : nullptr;
    archSpecificHpi->setHostParsedInference(parsedInferenceBuffer, entriesVct, metadata->mResourceRequirements,
                                            perfMetricsPtr);
};

HostParsedInference::HostParsedInference(HostParsedInference&& other)
        : bufferManager(other.bufferManager),
          accessManager(other.accessManager),
          metadata(other.metadata),
          platformInfo(other.platformInfo),
          perfMetrics(other.perfMetrics),
          loaders(std::move(other.loaders)),
          parsedInference(other.parsedInference),
          entries(other.entries) {
}

HostParsedInference::~HostParsedInference() {
}

HostParsedInference& HostParsedInference::operator=(const HostParsedInference& rhs) {
    if (this == &rhs) {
        return *this;
    }

    bufferManager = rhs.bufferManager;
    accessManager = rhs.accessManager;
    metadata = rhs.metadata;
    platformInfo = rhs.platformInfo;
    perfMetrics = rhs.perfMetrics;

    auto archSpecificHpi = getArchSpecificHPI(platformInfo->mArchKind);
    // Use clone semantics here by copy-constructing the loader object
    loaders.reserve(rhs.loaders.size());
    std::vector<uint64_t> entriesVct;
    entriesVct.reserve(rhs.loaders.size());
    if (platformInfo->mArchKind == elf::platform::ArchKind::VPUX37XX &&
        metadata->mResourceRequirements.nn_slice_count_ < archSpecificHpi->getArchTilesCount()) {
        entries = std::make_unique<AllocatedDeviceBuffer>(bufferManager,
                                                          archSpecificHpi->getEntryBufferSpecs(rhs.loaders.size()));

        auto entriesLock = ElfBufferLockGuard(entries.get());

        auto entrySize = entries->getBufferSpecs().size / rhs.loaders.size();
        for (size_t idx = 0; idx < rhs.loaders.size(); ++idx) {
            loaders.push_back(std::make_unique<VPUXLoader>(*rhs.loaders[idx]));

            auto entryDeviceBuffer = loaders[idx]->getEntry();
            auto entryLock = ElfBufferLockGuard(entryDeviceBuffer.get());

            std::memcpy(entries->getBuffer().cpu_addr() + idx * entrySize,
                        (void*)entryDeviceBuffer->getBuffer().cpu_addr(), entrySize);
            entriesVct.push_back((entries->getBuffer().vpu_addr() + idx * entrySize));
        }
    } else {
        loaders.push_back(std::make_unique<VPUXLoader>(*rhs.loaders.front()));
        entriesVct.push_back(loaders.front()->getEntry()->getBuffer().vpu_addr());
    }
    // Every new loader object means a new parsedInference struct as well
    parsedInference =
            std::make_shared<AllocatedDeviceBuffer>(bufferManager, archSpecificHpi->getParsedInferenceBufferSpecs());
    auto parsedInferenceLock = ElfBufferLockGuard(parsedInference.get());

    auto parsedInferenceBuffer = parsedInference->getBuffer();
    auto perfMetricsLock = ElfBufferLockGuard(perfMetrics.get());
    auto perfMetricsPtr = perfMetrics ? reinterpret_cast<uint64_t*>(perfMetrics->getBuffer().cpu_addr()) : nullptr;
    archSpecificHpi->setHostParsedInference(parsedInferenceBuffer, entriesVct, metadata->mResourceRequirements,
                                            perfMetricsPtr);

    return *this;
}

HostParsedInference& HostParsedInference::operator=(HostParsedInference&& rhs) {
    if (this == &rhs) {
        return *this;
    }
    bufferManager = rhs.bufferManager;
    accessManager = rhs.accessManager;
    metadata = rhs.metadata;
    platformInfo = rhs.platformInfo;
    perfMetrics = rhs.perfMetrics;
    loaders = std::move(rhs.loaders);
    parsedInference = rhs.parsedInference;
    entries = rhs.entries;

    return *this;
}

DeviceBuffer HostParsedInference::getParsedInference() const {
    return parsedInference->getBuffer();
}

std::vector<DeviceBuffer> HostParsedInference::getAllocatedBuffers() const {
    std::vector<DeviceBuffer> vct;
    for (auto& loader : loaders) {
        std::vector<DeviceBuffer> loaderAllocations = loader->getAllocatedBuffers();
        vct.insert(vct.end(), loaderAllocations.begin(), loaderAllocations.end());
    }

    if (entries) {
        vct.push_back(entries->getBuffer());
    }

    vct.push_back(parsedInference->getBuffer());

    return vct;
}

std::vector<DeviceBuffer> HostParsedInference::getInputBuffers() const {
    return loaders.front()->getInputBuffers();
}

std::vector<DeviceBuffer> HostParsedInference::getOutputBuffers() const {
    return loaders.front()->getOutputBuffers();
}

std::vector<DeviceBuffer> HostParsedInference::getProfBuffers() const {
    return loaders.front()->getProfBuffers();
}

std::shared_ptr<const elf::NetworkMetadata> HostParsedInference::getMetadata() {
    return metadata;
}

std::shared_ptr<const elf::platform::PlatformInfo> HostParsedInference::getPlatformInfo() {
    return platformInfo;
}

void HostParsedInference::applyInputOutput(std::vector<DeviceBuffer>& inputs, std::vector<DeviceBuffer>& outputs,
                                           std::vector<DeviceBuffer>& profiling) {
    // apply same relocation for all the copies as at this point in time
    // we don't know which one would be used.
    for (auto& loader : loaders) {
        loader->applyJitRelocations(inputs, outputs, profiling);
    }
}

void HostParsedInference::updateSharedScratchBuffers(const std::vector<DeviceBuffer>& buffers) {
    auto& loader = loaders.front();
    loader->updateSharedScratchBuffers(buffers);
}

}  // namespace elf
