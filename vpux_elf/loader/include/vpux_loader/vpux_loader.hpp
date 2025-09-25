//
// Copyright (C) 2023-2025 Intel Corporation
// SPDX-License-Identifier: Apache-2.0
//

//

#pragma once

#ifndef VPUX_ELF_LOG_UNIT_NAME
#define VPUX_ELF_LOG_UNIT_NAME "VpuxLoader"
#endif

#include <functional>
#include <map>
#include <memory>
#include <unordered_map>
#include <vector>

#include <vpux_elf/accessor.hpp>
#include <vpux_elf/reader.hpp>
#include <vpux_elf/utils/log.hpp>
#include <vpux_headers/buffer_manager.hpp>
#include <vpux_headers/buffer_specs.hpp>
#include <vpux_headers/device_buffer.hpp>
#include <vpux_headers/device_buffer_container.hpp>
#include <vpux_headers/managed_buffer.hpp>

#include <vpux_elf/types/elf_structs.hpp>
#include <vpux_elf/types/relocation_entry.hpp>
#include <vpux_elf/types/symbol_entry.hpp>
#include <vpux_elf/types/vpu_extensions.hpp>
#include <vpux_elf/utils/error.hpp>
#include <vpux_headers/metadata.hpp>
#include <vpux_headers/serial_metadata.hpp>

namespace elf {

class VPUXLoader {
private:
    using RelocationFunc = std::function<void(void*, const elf::SymbolEntry&, const Elf_Sxword)>;
    using RelocationType = Elf_Word;

    enum class Action {
        None,
        AllocateAndLoad,
        Allocate,
        Relocate,
        RegisterUserIO,
        RegisterNetworkMetadata,
        RegisterVersionInfo,
        Error
    };

    static const std::unordered_map<Elf_Word, Action> actionMap;
    static const std::unordered_map<RelocationType, RelocationFunc> relocationMap;

public:
    VPUXLoader(AccessManager* accessor, BufferManager* bufferManager);
    VPUXLoader(const VPUXLoader& other);
    VPUXLoader(const VPUXLoader& other, const std::vector<SymbolEntry>& runtimeSymTabs);
    VPUXLoader(VPUXLoader&& other) = delete;
    VPUXLoader& operator=(const VPUXLoader&);
    VPUXLoader& operator=(const VPUXLoader&&) = delete;
    ~VPUXLoader();

    void load(const std::vector<SymbolEntry>& runtimeSymTabs, bool symTabOverrideMode = false,
              const std::vector<elf::Elf_Word>& symbolSectionTypes = {}, bool explicitAllocations = false);
    elf::DeviceBufferContainer::BufferPtr getEntry();

    void applyJitRelocations(std::vector<DeviceBuffer>& inputs, std::vector<DeviceBuffer>& outputs,
                             std::vector<DeviceBuffer>& profiling);

    std::vector<DeviceBuffer> getAllocatedBuffers() const;
    std::vector<DeviceBuffer> getInputBuffers() const;
    std::vector<DeviceBuffer> getOutputBuffers() const;
    std::vector<DeviceBuffer> getProfBuffers() const;
    std::vector<std::shared_ptr<ManagedBuffer>> getSectionsOfType(elf::Elf_Word type);
    void setInferencesMayBeRunInParallel(bool inferencesMayBeRunInParallel);
    bool getInferencesMayBeRunInParallel() const;
    void updateSharedScratchBuffers(const std::vector<DeviceBuffer>& newBuffers);

private:
    bool checkSectionType(const elf::SectionHeader* section, Elf_Word secType) const;
    void earlyFetchIO(const elf::Reader<Elf64>::Section& section);
    void registerUserIO(std::vector<DeviceBuffer>& userIO, const elf::SymbolEntry* symbols, size_t symbolCount) const;

    void updateSharedBuffers(const std::vector<std::size_t>& relocationSectionIndexes);
    void loadBuffers();
    void reloadNewBuffers();
    void applyRelocations(const std::vector<std::size_t>& relocationSectionIndexes, bool onScratchUpdate = false);
    void cacheScratchRelocations();
    void applyScratchRelocations();

    BufferManager* m_bufferManager;
    std::shared_ptr<Reader<ELF_Bitness::Elf64>> m_reader;
    DeviceBufferContainer m_inferBufferContainer;
    DeviceBufferContainer m_backupBufferContainer;
    std::vector<SymbolEntry> m_runtimeSymTabs;

    std::shared_ptr<std::vector<std::size_t>> m_relocationSectionIndexes;
    std::shared_ptr<std::vector<std::size_t>> m_jitRelocations;

    std::shared_ptr<std::vector<DeviceBuffer>> m_userInputsDescriptors;
    std::shared_ptr<std::vector<DeviceBuffer>> m_userOutputsDescriptors;
    std::shared_ptr<std::vector<DeviceBuffer>> m_profOutputsDescriptors;

    std::shared_ptr<std::map<elf::Elf_Word /*section type*/, std::vector<size_t>>> /*section index*/
            m_sectionMap;

    bool m_symTabOverrideMode;
    bool m_explicitAllocations;
    bool m_loaded;
    std::vector<elf::Elf_Word> m_symbolSectionTypes;

    bool m_inferencesMayBeRunInParallel;
    std::vector<size_t> m_sharedScratchBuffers;

    std::shared_ptr<std::unordered_map<size_t, std::vector<size_t>>> m_scratchRelocations;
};

}  // namespace elf
