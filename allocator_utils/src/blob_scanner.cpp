//
// Copyright (C) 2026 Intel Corporation.
// SPDX-License-Identifier: Apache-2.0
//

#include "allocator_utils/blob_scanner.hpp"

std::vector<const std::pair<const std::string, MemoryRequirementsGroup>*> getSortedRequirements(
        const MemoryRequirementsMap& memoryReqMap) {
    std::vector<const std::pair<const std::string, MemoryRequirementsGroup>*> sorted;
    sorted.reserve(memoryReqMap.size());

    for (const auto& entry : memoryReqMap)
        sorted.push_back(&entry);

    std::sort(sorted.begin(), sorted.end(), [](const auto* a, const auto* b) { return a->first < b->first; });

    return sorted;
}

// Generic map of processor and their corresponding flag values
// This information would ideally be exposed by the ELF loader
const ProcessorMap& getDefaultProcessorMap() {
    static ProcessorMap map = {{"EXEC", elf::SHF_EXECINSTR},
                               {"DPU", elf::VPU_SHF_PROC_DPU},
                               {"DMA", elf::VPU_SHF_PROC_DMA},
                               {"SHAVE", elf::VPU_SHF_PROC_SHAVE}};
    return map;
}

MemoryRequirementsCategory::MemoryRequirementsCategory(std::string_view name): _name(name) {
}

void MemoryRequirementsCategory::addRequirementToGroup(
        const std::string& groupName, MemoryRequirementsGroup::IndividualRequirement& individualRequirement) {
    _map[groupName]._individualRequirements.push_back(individualRequirement);
    _map[groupName]._totalGroupRequirement += individualRequirement._header.sh_size;
    _total += individualRequirement._header.sh_size;
}

size_t MemoryRequirementsCategory::getTotalRequired() const {
    return _total;
}

void MemoryRequirementsCategory::print() {
    std::cout << " - By " << _name << " ( " << _total << " bytes):\n";
    for (const auto* entry : getSortedRequirements(_map)) {
        std::cout << "    - " << entry->first << ": " << entry->second._totalGroupRequirement << " bytes from "
                  << entry->second._individualRequirements.size() << " sections\n";
    }
    std::cout << std::endl;
}

BlobScanner::BlobScanner(elf::AccessManager* accessManager, const ProcessorMap& processorMap)
        : _processorRequirements("Processor"), _allocationTypeRequirements("Allocation type") {
    elf::Reader<elf::Elf64> reader(accessManager);

    for (size_t sectionIdx = 0; sectionIdx < reader.getSectionsNum(); ++sectionIdx) {
        auto sectionHeader = reader.getSection(sectionIdx).getHeader();

        if (sectionHeader->sh_flags & elf::SHF_ALLOC) {
            Requirement requirement{sectionIdx, *sectionHeader};
            // Track individual processor requirements
            // This implementation does not account for situations where 2 processors need to access the same section
            for (auto& procMapElem : processorMap) {
                if (sectionHeader->sh_flags & procMapElem.second) {
                    _processorRequirements.addRequirementToGroup(procMapElem.first, requirement);
                }
            }
            // Track global requirements for binary sections
            if (sectionHeader->sh_type == elf::SHT_PROGBITS) {
                _allocationTypeRequirements.addRequirementToGroup("Data (backed by blob data)", requirement);
            }
            // Track global requirements for scratch sections
            if (sectionHeader->sh_type == elf::SHT_NOBITS) {
                _allocationTypeRequirements.addRequirementToGroup("Empty (not backed by blob data)", requirement);
            }
        }
    }
}

const MemoryRequirementsCategory& BlobScanner::getRequirementsByProcessor() {
    return _processorRequirements;
}

const MemoryRequirementsCategory& BlobScanner::getRequirementsByAllocationType() {
    return _allocationTypeRequirements;
}

void BlobScanner::printResult() {
    std::cout << "================================================================================\n";
    std::cout << "Blob NPU memory requirements scan results:\n\n";

    _processorRequirements.print();
    std::cout << "\n";
    _allocationTypeRequirements.print();
    std::cout << "================================================================================\n";
    std::cout << std::endl;
}
