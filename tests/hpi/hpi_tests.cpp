//
// Copyright (C) 2026 Intel Corporation.
// SPDX-License-Identifier: Apache-2.0
//

#include <gtest/gtest.h>
#include <chrono>
#include <cstddef>
#include <ctime>

#include "allocator_utils/blob_scanner.hpp"
#include "allocator_utils/buffer_managers.hpp"
#include "allocator_utils/hpi_runner.hpp"
#include "allocator_utils/io_container.hpp"
#include "test_blob/binary_actions.hpp"
#include "test_blob/symbol_actions.hpp"
#include "test_blob/test_blob.hpp"

#include "hpi_common_interface.hpp"
#include "vpux_elf/accessor.hpp"
#include "vpux_elf/types/section_header.hpp"
#include "vpux_elf/types/vpu_extensions.hpp"
#include "vpux_headers/metadata.hpp"
#include "vpux_headers/platform.hpp"
#include "vpux_headers/serial_metadata.hpp"
#include "vpux_hpi.hpp"

using namespace elf;
using namespace std;
using namespace chrono;

namespace {

enum class RunMode {
    SimpleLoad = 0,
    SimpleClone,
};

}  // namespace

using AddNoteBinarySection = AddBinarySectionAction<elf::elf_note::VersionNote>;

struct SimpleLoadRunner : public HPIRunner<SimpleLoadRunner> {
    SimpleLoadRunner(): HPIRunner("appArgArchName", "appArgBlobPathAndName", AccessManagerType::DDRAccessManager) {
    }

    void runImpl() {
        // Get a memory consumption projection from the blob
        BlobScanner blobScanner(_accessManager.get(), getDefaultProcessorMap());
        blobScanner.printResult();

        std::cout << "\nLoading HPI..." << std::endl;

        auto start = high_resolution_clock::now();

        HostParsedInference hpi(_hpiBufferManager.get(), _accessManager.get(), _hpiConfig);
        hpi.load();

        auto end = high_resolution_clock::now();

        std::cout << "HPI loaded in " << duration_cast<milliseconds>(end - start).count() << " ms\n" << std::endl;

        IOBuffersContainer ioContainer(_ioBufferManager, hpi.getInputBuffers(), hpi.getOutputBuffers(),
                                       hpi.getProfBuffers());

        hpi.applyInputOutput(ioContainer.getInputBuffers(), ioContainer.getOutputBuffers(),
                             ioContainer.getProfilingBuffers());

        std::cout << "Projected NPU memory for HPI: "
                  << blobScanner.getRequirementsByAllocationType().getTotalRequired() + hpi.getHPISize() << " bytes\n";
        std::cout << "Total NPU buffers tracked by HPI object: " << hpi.getAllocatedBuffers().size() << "\n";
        std::cout << std::endl;

        _hpiBufferManager->printAllocationStats();
    }
};

class SimpleCloneRunner : public HPIRunner<SimpleCloneRunner> {
public:
    SimpleCloneRunner(): HPIRunner("appArgArchName", "appArgBlobPathAndName", AccessManagerType::DDRAccessManager) {
    }

    void runImpl() {
        std::cout << "Loading first HPI..." << std::endl;
        HostParsedInference hpi(_hpiBufferManager.get(), _accessManager.get(), _hpiConfig);
        hpi.load();
        std::cout << "First HPI loaded\n" << std::endl;

        // Delete AccessManager
        _accessManager = nullptr;

        // IO bindings must be possible after blob release
        IOBuffersContainer ioContainer(_ioBufferManager, hpi.getInputBuffers(), hpi.getOutputBuffers(),
                                       hpi.getProfBuffers());
        hpi.applyInputOutput(ioContainer.getInputBuffers(), ioContainer.getOutputBuffers(),
                             ioContainer.getProfilingBuffers());

        _hpiBufferManager->printAllocationStats();

        std::cout << "Loading second HPI..." << std::endl;

        // Cloning must still work after AccessManager was deleted
        HostParsedInference hpiClone(hpi);

        std::cout << "Second HPI loaded\n" << std::endl;

        _hpiBufferManager->printAllocationStats();
        hpiClone.getMetadata();
    }
};

TEST(HostParsedInference, MetadataOnlyBlobIsRejected) {
    auto elf = TestBlob({{AddRawBinarySection::build(
                                ".metadata",
                                AddRawBinarySection::Attributes{
                                        {},
                                        {
                                                VPU_SHT_NETDESC,
                                                elf::MetadataSerialization::serialize(
                                                        elf::NetworkMetadata{{"Test identification", "Test blob"}}),
                                        }})}})
                       .getBinary();

    auto accessManager =
            DDRAccessManager<elf::DDRAlwaysEmplace>(reinterpret_cast<const uint8_t*>(elf.data()), elf.size());
    auto bufferManager = DummyBufferManager();

    ASSERT_THROW(elf::HostParsedInference(&bufferManager, &accessManager, HPIConfigs{}, nullptr), std::exception);
}

ActionsSequence makeMinimalConstructible(platform::ArchKind arch) {
    const auto archSpecHpi = elf::HostParsedInferenceCommon::getArchSpecificHPI(arch);

    return ActionsSequence{{

            AddNoteBinarySection::build(
                    ".ELFVersion",
                    AddNoteBinarySection::Attributes{
                            {},
                            {elf::SHT_NOTE, std::vector<elf::elf_note::VersionNote>{elf::elf_note::VersionNote{
                                                    0,
                                                    0,
                                                    elf::elf_note::NT_GNU_ABI_TAG,
                                                    {},
                                                    archSpecHpi->getELFLibABIVersion().getMIFormat(),
                                                    archSpecHpi->getELFLibABIVersion().getMajor(),
                                                    archSpecHpi->getELFLibABIVersion().getMinor(),
                                                    archSpecHpi->getELFLibABIVersion().getPatch()}}},
                    }),

            AddNoteBinarySection::build(
                    ".MIVersion",
                    AddNoteBinarySection::Attributes{
                            {},
                            {elf::SHT_NOTE, std::vector<elf::elf_note::VersionNote>{elf::elf_note::VersionNote{
                                                    0,
                                                    0,
                                                    elf::elf_note::NT_NPU_MPI_VERSION,
                                                    {},
                                                    archSpecHpi->getStaticMIVersion().getMIFormat(),
                                                    archSpecHpi->getStaticMIVersion().getMajor(),
                                                    archSpecHpi->getStaticMIVersion().getMinor(),
                                                    archSpecHpi->getStaticMIVersion().getPatch()}}},
                    }),

            AddRawBinarySection::build(
                    ".metadata",
                    AddRawBinarySection::Attributes{{},
                                                    {
                                                            VPU_SHT_NETDESC,
                                                            elf::MetadataSerialization::serialize(elf::NetworkMetadata{
                                                                    {"Test identification", "Test blob"}}),
                                                    }}),

            AddRawBinarySection::build(
                    ".platformInfo",
                    AddRawBinarySection::Attributes{{},
                                                    {
                                                            VPU_SHT_PLATFORM_INFO,
                                                            elf::platform::PlatformInfoSerialization::serialize(
                                                                    elf::platform::PlatformInfo{arch}),
                                                    }}),
    }};
}

ActionsSequence makeMinimalLoadable(platform::ArchKind arch) {
    const auto archSpecHpi = elf::HostParsedInferenceCommon::getArchSpecificHPI(arch);
    const auto entrySectionSize = archSpecHpi->getEntryBufferSpecs(1).size;

    return makeMinimalConstructible(arch) +
           ActionsSequence{
                   {AddRawBinarySection::build(".mappedInference",
                                               AddRawBinarySection::Attributes{
                                                       {elf::SHF_ALLOC | elf::SHF_EXECINSTR},
                                                       {elf::SHT_PROGBITS, std::vector<uint8_t>(entrySectionSize)}}),

                    AddSymbolSection::build(
                            ".symtab", AddSymbolSection::Attributes{},
                            ActionsSequence{{AddSymbol::build(".entry", AddSymbol::Attributes{elf::VPU_STT_ENTRY},
                                                              AddSymbol::Operands{".mappedInference"})}})}};
}

ActionsSequence makeMinimalLoadableWithEntrySize(platform::ArchKind arch, size_t entrySectionSize) {
    return makeMinimalConstructible(arch) +
           ActionsSequence{
                   {AddRawBinarySection::build(".mappedInference",
                                               AddRawBinarySection::Attributes{
                                                       {elf::SHF_ALLOC | elf::SHF_EXECINSTR},
                                                       {elf::SHT_PROGBITS, std::vector<uint8_t>(entrySectionSize)}}),

                    AddSymbolSection::build(
                            ".symtab", AddSymbolSection::Attributes{},
                            ActionsSequence{{AddSymbol::build(".entry", AddSymbol::Attributes{elf::VPU_STT_ENTRY},
                                                              AddSymbol::Operands{".mappedInference"})}})}};
}

const auto MinimalLoadable37XX = makeMinimalLoadable(elf::platform::ArchKind::VPUX37XX);
const auto MinimalLoadable40XX = makeMinimalLoadable(elf::platform::ArchKind::VPUX40XX);
const auto MinimalLoadable501X = makeMinimalLoadable(elf::platform::ArchKind::VPUX501X);
const auto MinimalLoadable502X = makeMinimalLoadable(elf::platform::ArchKind::VPUX502X);

TEST(HostParsedInference, MinimalConstructible) {
    auto arch = elf::platform::ArchKind::VPUX40XX;
    auto archSpecHpi = elf::HostParsedInferenceCommon::getArchSpecificHPI(arch);

    auto elf = TestBlob(makeMinimalConstructible(arch)).getBinary();

    auto accessManager =
            DDRAccessManager<elf::DDRAlwaysEmplace>(reinterpret_cast<const uint8_t*>(elf.data()), elf.size());
    auto bufferManager = DummyBufferManager();

    ASSERT_NO_THROW(elf::HostParsedInference(&bufferManager, &accessManager,
                                             HPIConfigs{{}, elf::platform::ArchKind::VPUX40XX}, nullptr));
}

TEST(HostParsedInference, MinimalLoadable) {
    auto arch = elf::platform::ArchKind::VPUX40XX;
    auto archSpecHpi = elf::HostParsedInferenceCommon::getArchSpecificHPI(arch);

    auto elf = TestBlob(makeMinimalLoadable(arch)).getBinary();

    auto bufferManager = HeapBufferManager();
    auto accessManager = DDRAccessManager<elf::DDRNeverEmplace, elf::AllocatedDeviceBufferFactory>(
            reinterpret_cast<const uint8_t*>(elf.data()), elf.size(),
            std::make_shared<elf::AllocatedDeviceBufferFactory>(&bufferManager));

    auto hpi = elf::HostParsedInference(&bufferManager, &accessManager, HPIConfigs{{}, arch}, nullptr);

    ASSERT_NO_THROW(hpi.load());
}

TEST(HostParsedInference, ThrowWhenEntrySectionIsTooSmallForVPUX37XXDualEntryCopy) {
    auto arch = elf::platform::ArchKind::VPUX37XX;
    // Deliberately smaller than nn_public::VpuMappedInference to exercise entry copy validation.
    auto elf = TestBlob(makeMinimalLoadableWithEntrySize(arch, 1)).getBinary();

    auto bufferManager = HeapBufferManager();
    auto accessManager = DDRAccessManager<elf::DDRNeverEmplace, elf::AllocatedDeviceBufferFactory>(
            reinterpret_cast<const uint8_t*>(elf.data()), elf.size(),
            std::make_shared<elf::AllocatedDeviceBufferFactory>(&bufferManager));

    auto hpi = elf::HostParsedInference(&bufferManager, &accessManager, HPIConfigs{{}, arch}, nullptr);

    ASSERT_THROW(hpi.load(), elf::SectionError);
}

TEST(HostParsedInference, MinimalLoadableEachArchKind) {
    const std::vector<std::pair<elf::platform::ArchKind, const ActionsSequence*>> blobs = {
            {elf::platform::ArchKind::VPUX37XX, &MinimalLoadable37XX},
            {elf::platform::ArchKind::VPUX40XX, &MinimalLoadable40XX},
            {elf::platform::ArchKind::VPUX501X, &MinimalLoadable501X},
            {elf::platform::ArchKind::VPUX502X, &MinimalLoadable502X},
    };

    for (const auto& blob : blobs) {
        auto elf = TestBlob(*blob.second).getBinary();

        auto bufferManager = HeapBufferManager();
        auto accessManager = DDRAccessManager<elf::DDRNeverEmplace, elf::AllocatedDeviceBufferFactory>(
                reinterpret_cast<const uint8_t*>(elf.data()), elf.size(),
                std::make_shared<elf::AllocatedDeviceBufferFactory>(&bufferManager));

        auto hpi = elf::HostParsedInference(&bufferManager, &accessManager, HPIConfigs{{}, blob.first}, nullptr);

        ASSERT_NO_THROW(hpi.load()) << "Failed for arch " << static_cast<uint64_t>(blob.first);
    }
}

TEST(HostParsedInference, BaseMemoryCheck) {
    auto arch = elf::platform::ArchKind::VPUX40XX;
    auto archSpecHpi = elf::HostParsedInferenceCommon::getArchSpecificHPI(arch);

    auto elf = TestBlob(makeMinimalLoadable(arch)).getBinary();

    auto bufferManager = HeapBufferManager();
    auto accessManager = DDRAccessManager<elf::DDRNeverEmplace, elf::AllocatedDeviceBufferFactory>(
            reinterpret_cast<const uint8_t*>(elf.data()), elf.size(),
            std::make_shared<elf::AllocatedDeviceBufferFactory>(&bufferManager));

    auto blobScanner = BlobScanner(&accessManager, getDefaultProcessorMap());
    auto procReq = blobScanner.getRequirementsByProcessor().getTotalRequired() +
                   archSpecHpi->getParsedInferenceBufferSpecs().size;

    auto hpi = elf::HostParsedInference(&bufferManager, &accessManager, HPIConfigs{{}, arch}, nullptr);

    ASSERT_NO_THROW(hpi.load());

    auto procAlloc = bufferManager.getStats()._totalNPUSize;

    ASSERT_EQ(procReq, procAlloc);
}

TEST(HostParsedInference, ScratchSectionHasNoImpactOnBlobSize) {
    auto arch = elf::platform::ArchKind::VPUX40XX;
    auto archSpecHpi = elf::HostParsedInferenceCommon::getArchSpecificHPI(arch);

    auto seq0 = makeMinimalLoadable(arch) +
                ActionsSequence{{

                        AddEmptySection::build(
                                ".buffer", AddEmptySection::Attributes{{elf::SHF_ALLOC | elf::VPU_SHF_PROC_DMA, 1024},
                                                                       4 * 1024 * 1024 * 1024ULL})

                }};

    auto seq1 = makeMinimalLoadable(arch) +
                ActionsSequence{{

                        AddEmptySection::build(
                                ".buffer", AddEmptySection::Attributes{{elf::SHF_ALLOC | elf::VPU_SHF_PROC_DMA, 1024},
                                                                       2 * 1024 * 1024 * 1024ULL})}};

    auto elf0 = TestBlob(seq0).getBinary();
    auto elf1 = TestBlob(seq1).getBinary();

    ASSERT_EQ(elf0.size(), elf1.size());

    const auto loadAndReturnMemUsage = [&arch](const std::vector<uint8_t>& elf) -> size_t {
        auto bufferManager = HeapBufferManager();
        auto accessManager = DDRAccessManager<elf::DDRNeverEmplace, elf::AllocatedDeviceBufferFactory>(
                reinterpret_cast<const uint8_t*>(elf.data()), elf.size(),
                std::make_shared<elf::AllocatedDeviceBufferFactory>(&bufferManager));

        auto hpi = elf::HostParsedInference(&bufferManager, &accessManager, HPIConfigs{{}, arch}, nullptr);
        hpi.load();

        return bufferManager.getStats()._totalNPUSize;
    };

    size_t memUsage0 = 0;
    size_t memUsage1 = 0;

    ASSERT_NO_THROW(memUsage0 = loadAndReturnMemUsage(elf0));
    ASSERT_NO_THROW(memUsage1 = loadAndReturnMemUsage(elf1));

    ASSERT_GT(memUsage0, memUsage1);
}

TEST(HostParsedInference, CompatStringThrowIfEmpty) {
    ASSERT_THROW(checkCompatibilityString(DeviceDescriptor{}, ""), std::exception);
}

TEST(HostParsedInference, CompatStringThrowIfNoBlobArchKind) {
    ASSERT_THROW(checkCompatibilityString(DeviceDescriptor{}, "t=3;elf=2.0.0;mi=11.7.0"), std::exception);
}

TEST(HostParsedInference, CompatStringThrowIfNoBlobTileCount) {
    ASSERT_THROW(checkCompatibilityString(DeviceDescriptor{}, "npu=5010;elf=2.0.0;mi=11.7.0"), std::exception);
}

TEST(HostParsedInference, CompatStringThrowIfNoBlobElfVersion) {
    ASSERT_THROW(checkCompatibilityString(DeviceDescriptor{}, "npu=5010;t=3;mi=11.7.0"), std::exception);
}

TEST(HostParsedInference, CompatStringThrowIfNoBlobMiVersion) {
    ASSERT_THROW(checkCompatibilityString(DeviceDescriptor{}, "npu=5010;t=3;elf=2.0.1"), std::exception);
}

TEST(HostParsedInference, CompatStringCompatible) {
    const auto hwTileCount = 4;
    const auto deviceDescriptor = DeviceDescriptor{sizeof(DeviceDescriptor),
                                                   0x643e,  // LNL
                                                   3,       // revision
                                                   hwTileCount};
    const auto hwArch = elf::archFromDeviceId(deviceDescriptor.deviceID);
    const auto archSpecHpi = elf::HostParsedInferenceCommon::getArchSpecificHPI(hwArch);
    const auto compatibilityString = std::string{"npu=4000;"} + "t=" + std::to_string(hwTileCount) + ";" +
                                     "elf=" + archSpecHpi->getELFLibABIVersion().toString() + ";" +
                                     "mi=" + archSpecHpi->getStaticMIVersion().toString();

    ASSERT_NO_THROW(checkCompatibilityString(deviceDescriptor, compatibilityString));
}

TEST(HostParsedInference, CompatStringIncompatibleIfUnknownArchKind) {
    const auto hwTileCount = 4;
    const auto deviceDescriptor = DeviceDescriptor{sizeof(DeviceDescriptor),
                                                   0x643e,  // LNL
                                                   3,       // revision
                                                   hwTileCount};
    const auto hwArch = elf::archFromDeviceId(deviceDescriptor.deviceID);

    const auto archSpecHpi = elf::HostParsedInferenceCommon::getArchSpecificHPI(hwArch);
    const auto compatibilityString = std::string{"npu=9999;"} + "t=" + std::to_string(hwTileCount) + ";" +
                                     "elf=" + archSpecHpi->getELFLibABIVersion().toString() + ";" +
                                     "mi=" + archSpecHpi->getStaticMIVersion().toString();

    ASSERT_THROW(checkCompatibilityString(deviceDescriptor, compatibilityString), elf::RuntimeError);
}

TEST(HostParsedInference, CompatStringIncompatibleIfOlderArchKind) {
    const auto hwTileCount = 4;
    const auto deviceDescriptor = DeviceDescriptor{sizeof(DeviceDescriptor),
                                                   0x643e,  // LNL
                                                   3,       // revision
                                                   hwTileCount};
    const auto hwArch = elf::archFromDeviceId(deviceDescriptor.deviceID);

    const auto archSpecHpi = elf::HostParsedInferenceCommon::getArchSpecificHPI(hwArch);
    const auto compatibilityString = std::string{"npu=3720;"} + "t=" + std::to_string(hwTileCount) + ";" +
                                     "elf=" + archSpecHpi->getELFLibABIVersion().toString() + ";" +
                                     "mi=" + archSpecHpi->getStaticMIVersion().toString();

    ASSERT_THROW(checkCompatibilityString(deviceDescriptor, compatibilityString), elf::CompatibilityError);
}

TEST(HostParsedInference, CompatStringIncompatibleIfNewerArchKind) {
    const auto hwTileCount = 3;
    const auto deviceDescriptor = DeviceDescriptor{sizeof(DeviceDescriptor),
                                                   0x643e,  // LNL
                                                   3,       // revision
                                                   hwTileCount};
    const auto hwArch = elf::archFromDeviceId(deviceDescriptor.deviceID);

    const auto archSpecHpi = elf::HostParsedInferenceCommon::getArchSpecificHPI(hwArch);
    const auto compatibilityString = std::string{"npu=5010;"} + "t=" + std::to_string(hwTileCount) + ";" +
                                     "elf=" + archSpecHpi->getELFLibABIVersion().toString() + ";" +
                                     "mi=" + archSpecHpi->getStaticMIVersion().toString();

    ASSERT_THROW(checkCompatibilityString(deviceDescriptor, compatibilityString), elf::CompatibilityError);
}

TEST(HostParsedInference, CompatStringIncompatibleIfSameArchDifferentSKU) {
    const auto hwTileCount = 3;
    const auto deviceDescriptor = DeviceDescriptor{sizeof(DeviceDescriptor),
                                                   0xFD3E,  // WCL
                                                   3,       // revision
                                                   hwTileCount};
    const auto hwArch = elf::archFromDeviceId(deviceDescriptor.deviceID);

    const auto archSpecHpi = elf::HostParsedInferenceCommon::getArchSpecificHPI(hwArch);
    const auto compatibilityString = std::string{"npu=5010;"} + "t=" + std::to_string(hwTileCount) + ";" +
                                     "elf=" + archSpecHpi->getELFLibABIVersion().toString() + ";" +
                                     "mi=" + archSpecHpi->getStaticMIVersion().toString();

    ASSERT_THROW(checkCompatibilityString(deviceDescriptor, compatibilityString), elf::CompatibilityError);
}

TEST(HostParsedInference, CompatStringCompatibleIfLessTiles) {
    const auto hwTileCount = 4;
    const auto deviceDescriptor = DeviceDescriptor{sizeof(DeviceDescriptor),
                                                   0x643e,  // LNL
                                                   3,       // revision
                                                   hwTileCount};
    const auto hwArch = elf::archFromDeviceId(deviceDescriptor.deviceID);

    const auto archSpecHpi = elf::HostParsedInferenceCommon::getArchSpecificHPI(hwArch);
    const auto compatibilityString = std::string{"npu=4000;"} + "t=" + std::to_string(hwTileCount - 1) + ";" +
                                     "elf=" + archSpecHpi->getELFLibABIVersion().toString() + ";" +
                                     "mi=" + archSpecHpi->getStaticMIVersion().toString();

    ASSERT_NO_THROW(checkCompatibilityString(deviceDescriptor, compatibilityString));
}

TEST(HostParsedInference, CompatStringIncompatibleIfTooManyTiles) {
    const auto hwTileCount = 4;
    const auto deviceDescriptor = DeviceDescriptor{sizeof(DeviceDescriptor),
                                                   0x643e,  // LNL
                                                   3,       // revision
                                                   hwTileCount};
    const auto hwArch = elf::archFromDeviceId(deviceDescriptor.deviceID);

    const auto archSpecHpi = elf::HostParsedInferenceCommon::getArchSpecificHPI(hwArch);
    const auto compatibilityString = std::string{"npu=4000;"} + "t=" + std::to_string(hwTileCount + 1) + ";" +
                                     "elf=" + archSpecHpi->getELFLibABIVersion().toString() + ";" +
                                     "mi=" + archSpecHpi->getStaticMIVersion().toString();

    ASSERT_THROW(checkCompatibilityString(deviceDescriptor, compatibilityString), elf::CompatibilityError);
}

TEST(HostParsedInference, CompatStringCompatibleIfElfMinorLess) {
    const auto hwTileCount = 4;
    const auto deviceDescriptor = DeviceDescriptor{sizeof(DeviceDescriptor),
                                                   0x643e,  // LNL
                                                   3,       // revision
                                                   hwTileCount};
    const auto hwArch = elf::archFromDeviceId(deviceDescriptor.deviceID);

    const auto archSpecHpi = elf::HostParsedInferenceCommon::getArchSpecificHPI(hwArch);
    const auto archElfVersion = archSpecHpi->getELFLibABIVersion();

    ASSERT_NE(archElfVersion.getMinor(), 0);  // Guard against underflow in next line
    const auto elfVersion =
            elf::Version{archElfVersion.getMajor(), archElfVersion.getMinor() - 1, archElfVersion.getPatch()};
    const auto compatibilityString = std::string{"npu=4000;"} + "t=" + std::to_string(hwTileCount) + ";" +
                                     "elf=" + elfVersion.toString() + ";" +
                                     "mi=" + archSpecHpi->getStaticMIVersion().toString();

    ASSERT_NO_THROW(checkCompatibilityString(deviceDescriptor, compatibilityString));
}

TEST(HostParsedInference, CompatStringIncompatibleIfElfMajorLess) {
    const auto hwTileCount = 4;
    const auto deviceDescriptor = DeviceDescriptor{sizeof(DeviceDescriptor),
                                                   0x643e,  // LNL
                                                   3,       // revision
                                                   hwTileCount};
    const auto hwArch = elf::archFromDeviceId(deviceDescriptor.deviceID);

    const auto archSpecHpi = elf::HostParsedInferenceCommon::getArchSpecificHPI(hwArch);
    const auto archElfVersion = archSpecHpi->getELFLibABIVersion();

    ASSERT_NE(archElfVersion.getMajor(), 0);  // Guard against underflow in next line
    const auto elfVersion =
            elf::Version{archElfVersion.getMajor() - 1, archElfVersion.getMinor(), archElfVersion.getPatch()};
    const auto compatibilityString = std::string{"npu=4000;"} + "t=" + std::to_string(hwTileCount) + ";" +
                                     "elf=" + elfVersion.toString() + ";" +
                                     "mi=" + archSpecHpi->getStaticMIVersion().toString();

    ASSERT_THROW(checkCompatibilityString(deviceDescriptor, compatibilityString), elf::CompatibilityError);
}

TEST(HostParsedInference, CompatStringIncompatibleIfElfMajorGreater) {
    const auto hwTileCount = 4;
    const auto deviceDescriptor = DeviceDescriptor{sizeof(DeviceDescriptor),
                                                   0x643e,  // LNL
                                                   3,       // revision
                                                   hwTileCount};
    const auto hwArch = elf::archFromDeviceId(deviceDescriptor.deviceID);

    const auto archSpecHpi = elf::HostParsedInferenceCommon::getArchSpecificHPI(hwArch);
    const auto archElfVersion = archSpecHpi->getELFLibABIVersion();

    const auto elfVersion =
            elf::Version{archElfVersion.getMajor() + 1, archElfVersion.getMinor(), archElfVersion.getPatch()};
    const auto compatibilityString = std::string{"npu=4000;"} + "t=" + std::to_string(hwTileCount) + ";" +
                                     "elf=" + elfVersion.toString() + ";" +
                                     "mi=" + archSpecHpi->getStaticMIVersion().toString();

    ASSERT_THROW(checkCompatibilityString(deviceDescriptor, compatibilityString), elf::CompatibilityError);
}

TEST(HostParsedInference, CompatStringIncompatibleIfElfMinorGreater) {
    const auto hwTileCount = 4;
    const auto deviceDescriptor = DeviceDescriptor{sizeof(DeviceDescriptor),
                                                   0x643e,  // LNL
                                                   3,       // revision
                                                   hwTileCount};
    const auto hwArch = elf::archFromDeviceId(deviceDescriptor.deviceID);

    const auto archSpecHpi = elf::HostParsedInferenceCommon::getArchSpecificHPI(hwArch);
    const auto archElfVersion = archSpecHpi->getELFLibABIVersion();

    const auto elfVersion =
            elf::Version{archElfVersion.getMajor(), archElfVersion.getMinor() + 1, archElfVersion.getPatch()};
    const auto compatibilityString = std::string{"npu=4000;"} + "t=" + std::to_string(hwTileCount) + ";" +
                                     "elf=" + elfVersion.toString() + ";" +
                                     "mi=" + archSpecHpi->getStaticMIVersion().toString();

    ASSERT_THROW(checkCompatibilityString(deviceDescriptor, compatibilityString), elf::CompatibilityError);
}

TEST(HostParsedInference, CompatStringCompatibleIfMIMinorLess) {
    const auto hwTileCount = 4;
    const auto deviceDescriptor = DeviceDescriptor{sizeof(DeviceDescriptor),
                                                   0x643e,  // LNL
                                                   3,       // revision
                                                   hwTileCount};
    const auto hwArch = elf::archFromDeviceId(deviceDescriptor.deviceID);

    const auto archSpecHpi = elf::HostParsedInferenceCommon::getArchSpecificHPI(hwArch);
    const auto archMIVersion = archSpecHpi->getStaticMIVersion();

    ASSERT_NE(archMIVersion.getMinor(), 0);  // Guard against underflow in next line
    const auto miVersion =
            elf::Version{archMIVersion.getMajor(), archMIVersion.getMinor() - 1, archMIVersion.getPatch()};
    const auto compatibilityString = std::string{"npu=4000;"} + "t=" + std::to_string(hwTileCount) + ";" +
                                     "elf=" + archSpecHpi->getELFLibABIVersion().toString() + ";" +
                                     "mi=" + miVersion.toString();

    ASSERT_NO_THROW(checkCompatibilityString(deviceDescriptor, compatibilityString));
}

TEST(HostParsedInference, CompatStringIncompatibleIfMIMajorLess) {
    const auto hwTileCount = 4;
    const auto deviceDescriptor = DeviceDescriptor{sizeof(DeviceDescriptor),
                                                   0x643e,  // LNL
                                                   3,       // revision
                                                   hwTileCount};
    const auto hwArch = elf::archFromDeviceId(deviceDescriptor.deviceID);

    const auto archSpecHpi = elf::HostParsedInferenceCommon::getArchSpecificHPI(hwArch);
    const auto archMIVersion = archSpecHpi->getStaticMIVersion();

    ASSERT_NE(archMIVersion.getMajor(), 0);  // Guard against underflow in next line
    const auto miVersion =
            elf::Version{archMIVersion.getMajor() - 1, archMIVersion.getMinor(), archMIVersion.getPatch()};
    const auto compatibilityString = std::string{"npu=4000;"} + "t=" + std::to_string(hwTileCount) + ";" +
                                     "elf=" + archSpecHpi->getELFLibABIVersion().toString() + ";" +
                                     "mi=" + miVersion.toString();

    ASSERT_THROW(checkCompatibilityString(deviceDescriptor, compatibilityString), elf::CompatibilityError);
}

TEST(HostParsedInference, CompatStringIncompatibleIfMIMajorGreater) {
    const auto hwTileCount = 4;
    const auto deviceDescriptor = DeviceDescriptor{sizeof(DeviceDescriptor),
                                                   0x643e,  // LNL
                                                   3,       // revision
                                                   hwTileCount};
    const auto hwArch = elf::archFromDeviceId(deviceDescriptor.deviceID);

    const auto archSpecHpi = elf::HostParsedInferenceCommon::getArchSpecificHPI(hwArch);
    const auto archMIVersion = archSpecHpi->getStaticMIVersion();

    const auto miVersion =
            elf::Version{archMIVersion.getMajor() + 1, archMIVersion.getMinor(), archMIVersion.getPatch()};
    const auto compatibilityString = std::string{"npu=4000;"} + "t=" + std::to_string(hwTileCount) + ";" +
                                     "elf=" + archSpecHpi->getELFLibABIVersion().toString() + ";" +
                                     "mi=" + miVersion.toString();

    ASSERT_THROW(checkCompatibilityString(deviceDescriptor, compatibilityString), elf::CompatibilityError);
}

TEST(HostParsedInference, CompatStringIncompatibleIfMIMinorGreater) {
    const auto hwTileCount = 4;
    const auto deviceDescriptor = DeviceDescriptor{sizeof(DeviceDescriptor),
                                                   0x643e,  // LNL
                                                   3,       // revision
                                                   hwTileCount};
    const auto hwArch = elf::archFromDeviceId(deviceDescriptor.deviceID);

    const auto archSpecHpi = elf::HostParsedInferenceCommon::getArchSpecificHPI(hwArch);
    const auto archMIVersion = archSpecHpi->getStaticMIVersion();

    const auto miVersion =
            elf::Version{archMIVersion.getMajor(), archMIVersion.getMinor() + 1, archMIVersion.getPatch()};
    const auto compatibilityString = std::string{"npu=4000;"} + "t=" + std::to_string(hwTileCount) + ";" +
                                     "elf=" + archSpecHpi->getELFLibABIVersion().toString() + ";" +
                                     "mi=" + miVersion.toString();

    ASSERT_THROW(checkCompatibilityString(deviceDescriptor, compatibilityString), elf::CompatibilityError);
}
