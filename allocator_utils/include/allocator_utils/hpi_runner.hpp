//
// Copyright (C) 2026 Intel Corporation.
// SPDX-License-Identifier: Apache-2.0
//

#pragma once

#include "allocator_utils/buffer_managers.hpp"

#include "vpux_elf/accessor.hpp"
#include "vpux_elf/utils/error.hpp"
#include "vpux_headers/platform.hpp"
#include "vpux_hpi.hpp"

enum class AccessManagerType { DDRAccessManager = 0, FSAccessManager };

// Helper class intended to remove repetitive code needed to create supporting environment when creating
// HostParsedInference objects
template <typename HPIRunnerDerived>
class HPIRunner {
public:
    void run() {
        try {
            static_cast<HPIRunnerDerived*>(this)->runImpl();
            VPUX_ELF_THROW_WHEN(
                    _hpiBufferManager->getStats()._currentTotalSize || _ioBufferManager->getStats()._currentTotalSize,
                    elf::RuntimeError, "Memory leak occurred");
        } catch (std::exception& e) {
            std::cout << "Caught exception: " << e.what() << std::endl;
            // Rethrow to application level
            throw(e);
        } catch (...) {
            std::cout << "Caught unknown exception" << std::endl;
            VPUX_ELF_THROW(elf::RuntimeError, "Unkown exception occurred");
        }

        std::cout << "\n\nRun completed successfully" << std::endl;
    }

protected:
    std::shared_ptr<HeapBufferManager> _hpiBufferManager = nullptr;
    std::shared_ptr<HeapBufferManager> _ioBufferManager = nullptr;
    std::shared_ptr<elf::AccessManager> _accessManager = nullptr;
    // Blob vector storage for DDRAccessManager which doesn't work with smart pointers to ensure lifetime of blob
    // storage
    std::vector<uint8_t> _blobBinVector = {};
    elf::HPIConfigs _hpiConfig = {};

private:
    friend HPIRunnerDerived;

    HPIRunner(const std::string& archName, const std::string& blobPathAndName,
              const AccessManagerType& accessManagerType) {
        _hpiBufferManager = std::make_shared<HeapBufferManager>("HPI buffer manager");
        _ioBufferManager = std::make_shared<HeapBufferManager>("IO buffer manager");

        switch (accessManagerType) {
        case AccessManagerType::DDRAccessManager: {
            // To simulate host vs NPU memory allocations distribution during HPI loading, build accessor with:
            // - NeverEmplace - all buffers are explicitly allocated
            // - AllocatedDeviceBufferFactory - ensure all buffers are allocated by a BufferManager
            _accessManager = getDDRAccessManager<elf::DDRNeverEmplace>(
                    blobPathAndName.data(), _blobBinVector,
                    std::make_shared<elf::AllocatedDeviceBufferFactory>(_hpiBufferManager.get()));
            break;
        }
        case AccessManagerType::FSAccessManager: {
            // To simulate host vs NPU memory allocations distribution during HPI loading, build accessor with:
            // - AllocatedDeviceBufferFactory - ensure all buffers are allocated by a BufferManager
            _accessManager =
                    getFSAccessManager(blobPathAndName.data(),
                                       std::make_shared<elf::AllocatedDeviceBufferFactory>(_hpiBufferManager.get()));
            break;
        }
        default: {
            VPUX_ELF_THROW(elf::RuntimeError, "Unknown AccessManager type");
        }
        }

        _hpiConfig.archKind = elf::platform::mapArchStringToArchKind(archName);
    }

    template <typename EmplaceLogic, typename BufferFactory>
    static std::shared_ptr<elf::AccessManager> getDDRAccessManager(
            const std::string& filePathAndName, std::vector<uint8_t>& storageVector,
            std::shared_ptr<BufferFactory> bufferFactory = std::make_shared<BufferFactory>()) {
        storageVector.clear();
        std::ifstream inputStream(filePathAndName, std::ios::binary | std::ios::ate);
        storageVector.resize(inputStream.tellg());
        inputStream.seekg(0, inputStream.beg);
        inputStream.read(reinterpret_cast<char*>(storageVector.data()), storageVector.size());
        inputStream.close();

        return std::make_shared<elf::DDRAccessManager<EmplaceLogic, BufferFactory>>(
                storageVector.data(), storageVector.size(), bufferFactory);
    }

    template <typename BufferFactory>
    static std::shared_ptr<elf::AccessManager> getFSAccessManager(
            const std::string& filePathAndName,
            std::shared_ptr<BufferFactory> bufferFactory = std::make_shared<BufferFactory>()) {
        return std::make_shared<elf::FSAccessManager<BufferFactory>>(filePathAndName, bufferFactory);
    }
};
