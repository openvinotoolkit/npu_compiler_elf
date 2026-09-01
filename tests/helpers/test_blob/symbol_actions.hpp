//
// Copyright (C) 2026 Intel Corporation.
// SPDX-License-Identifier: Apache-2.0
//

#pragma once

#include <algorithm>
#include <cstdint>
#include <cstring>
#include <sstream>
#include <string>

#include "test_blob/actions_base.hpp"
#include "test_blob/interfaces.hpp"
#include "test_blob/test_blob.hpp"

#include "vpux_elf/types/dma_symbol_entry.hpp"
#include "vpux_elf/writer.hpp"
#include "vpux_elf/writer/dma_symbol.hpp"
#include "vpux_elf/writer/dma_symbol_section.hpp"
#include "vpux_elf/writer/symbol.hpp"
#include "vpux_elf/writer/symbol_section.hpp"

struct AddSymbolAttributes {
    elf::Elf_Word _type = {};
    elf::Elf_Word _binding = {};
    uint8_t _visibility = {};
    elf::Elf64_Addr _value = {};
    size_t _size = {};

    std::string getStringified() const {
        std::stringstream stream;
        stream << "type = " << _type << ", binding = " << _binding
               << ", visibility = " << static_cast<uint32_t>(_visibility) << ", value = " << _value
               << ", size = " << _size;
        return stream.str();
    }
};

struct AddDMASymbolAttributes {
    elf::DmaSymbolEntry _symbolEntry = {};

    AddDMASymbolAttributes() {
        std::memset(&_symbolEntry, 0, sizeof(_symbolEntry));
    }

    AddDMASymbolAttributes(const elf::DmaSymbolEntry& symbolEntry): AddDMASymbolAttributes() {
        _symbolEntry.ioIndex = symbolEntry.ioIndex;
        _symbolEntry.address = symbolEntry.address;
        std::copy_n(symbolEntry.shapes, elf::DMA_SYMBOL_MAX_TENSOR_DIMENSIONS, _symbolEntry.shapes);
        std::copy_n(symbolEntry.strides, elf::DMA_SYMBOL_MAX_TENSOR_DIMENSIONS, _symbolEntry.strides);
        std::copy_n(symbolEntry.tileOffsets, elf::DMA_SYMBOL_MAX_TENSOR_DIMENSIONS, _symbolEntry.tileOffsets);
        std::copy_n(symbolEntry.dmaShapes, elf::DMA_SYMBOL_MAX_TENSOR_DIMENSIONS, _symbolEntry.dmaShapes);
        std::copy_n(symbolEntry.dmaStrides, elf::DMA_SYMBOL_MAX_TENSOR_DIMENSIONS, _symbolEntry.dmaStrides);
        _symbolEntry.dmaSize = symbolEntry.dmaSize;
    }

    std::string getStringified() const {
        std::stringstream stream;
        stream << "IO_index = 0x" << std::hex << _symbolEntry.ioIndex << ", address = 0x" << _symbolEntry.address;
        return stream.str();
    }
};

struct AddSymbolOperands {
    Operand<ISectionResult> _relatedSection;
    Operand<ISymbolSectionResult<elf::writer::SymbolSection>> _symbolSection;

    using ImplicitOperandType = decltype(_symbolSection);
    ImplicitOperandType& getImplicitOperand() {
        return _symbolSection;
    }

    std::string getStringified() const {
        std::stringstream stream;
        stream << "relatedSection = " << _relatedSection._name << ", symbolSection = " << _symbolSection._name;
        return stream.str();
    }
};

struct AddDMASymbolOperands {
    Operand<ISymbolSectionResult<elf::writer::DmaSymbolSection>> _symbolSection;

    using ImplicitOperandType = decltype(_symbolSection);
    ImplicitOperandType& getImplicitOperand() {
        return _symbolSection;
    }

    std::string getStringified() const {
        std::stringstream stream;
        stream << "symbolSection = " << _symbolSection._name;
        return stream.str();
    }
};

struct SymbolTraits {
    using AttributesType = AddSymbolAttributes;
    using OperandsType = AddSymbolOperands;
    using ResultType = SymbolResult<elf::writer::Symbol, elf::writer::SymbolSection>;

    static elf::writer::Symbol* buildSymbol(TestBlobHandle& handle, const std::string& name,
                                            elf::writer::SymbolSection* section, const AttributesType& attrs,
                                            const OperandsType& operands) {
        auto symbol = section->addSymbolEntry(name);
        symbol->setType(attrs._type);
        symbol->setBinding(attrs._binding);
        symbol->setVisibility(attrs._visibility);
        symbol->setValue(attrs._value);
        symbol->setSize(attrs._size);

        auto sectionResult = operands._relatedSection.get(handle);
        symbol->setRelatedSection(sectionResult->getSection());

        return symbol;
    }
};

struct DMASymbolTraits {
    using AttributesType = AddDMASymbolAttributes;
    using OperandsType = AddDMASymbolOperands;
    using ResultType = SymbolResult<elf::writer::DmaSymbol, elf::writer::DmaSymbolSection>;

    static elf::writer::DmaSymbol* buildSymbol(TestBlobHandle& handle, const std::string&,
                                               elf::writer::DmaSymbolSection* section, const AttributesType& attrs,
                                               const OperandsType& operands) {
        auto* symbol = section->addDmaSymbolEntry();
        symbol->setDmaSymbol(attrs._symbolEntry);

        return symbol;
    }
};

template <typename Traits>
class AddSymbolAction :
        public Action,
        public ActionWithAttributes<typename Traits::AttributesType>,
        public ActionWithOperandsWithImplicitOperand<typename Traits::OperandsType>,
        public ActionWithBuilder<AddSymbolAction<Traits>, typename Traits::AttributesType,
                                 typename Traits::OperandsType>,
        public ActionWithPrinter<AddSymbolAction<Traits>> {
public:
    AddSymbolAction(std::string name, typename Traits::AttributesType attrs, typename Traits::OperandsType operands)
            : Action(std::move(name)),
              ActionWithAttributes<typename Traits::AttributesType>(std::move(attrs)),
              ActionWithOperandsWithImplicitOperand<typename Traits::OperandsType>(std::move(operands)) {
    }

private:
    virtual void execute(TestBlobHandle& handle) override {
        auto symSectionResult = this->getOperands()._symbolSection.get(handle);

        auto symbolSection = symSectionResult->getSymbolSection();
        auto symbol = Traits::buildSymbol(handle, getName(), symbolSection, this->getAttributes(), this->getOperands());

        handle.addResult(this, std::make_shared<typename Traits::ResultType>(symbol, symbolSection));
    }
};

using AddSymbol = AddSymbolAction<SymbolTraits>;
using AddDMASymbol = AddSymbolAction<DMASymbolTraits>;

struct SymbolSectionAttributes {
    uint32_t _info = {};

    std::string getStringified() const {
        std::stringstream stream;
        stream << "info = " << _info;
        return stream.str();
    }
};

struct AddSymbolSectionAttributes {
    CommonSectionAttributes _commonSectionAttrs = {};
    SymbolSectionAttributes _symbolSectionAttrs = {};

    std::string getStringified() const {
        std::stringstream stream;
        stream << _commonSectionAttrs.getStringified() << ", " << _symbolSectionAttrs.getStringified();
        return stream.str();
    }
};

struct SymbolSectionTraits {
    using ExpectedNestedActionType = AddSymbolAction<SymbolTraits>;
    using AttributesType = AddSymbolSectionAttributes;
    using ResultType = SymbolSectionResult<elf::writer::SymbolSection>;
    using ResultBaseType = ISymbolSectionResult<elf::writer::SymbolSection>;

    static elf::writer::SymbolSection* buildSymbolSection(elf::Writer* writer, const std::string& name) {
        return writer->addSymbolSection(name);
    }
};

struct DMASymbolSectionTraits {
    using ExpectedNestedActionType = AddSymbolAction<DMASymbolTraits>;
    using AttributesType = AddSymbolSectionAttributes;
    using ResultType = SymbolSectionResult<elf::writer::DmaSymbolSection>;
    using ResultBaseType = ISymbolSectionResult<elf::writer::DmaSymbolSection>;

    static elf::writer::DmaSymbolSection* buildSymbolSection(elf::Writer* writer, const std::string& name) {
        return writer->addDmaSymbolSection(name);
    }
};

template <typename Traits>
class AddSymbolSectionAction :
        public Action,
        public ActionWithAttributes<typename Traits::AttributesType>,
        public ActionWithNest<AddSymbolSectionAction<Traits>, typename Traits::ExpectedNestedActionType,
                              Operand<typename Traits::ResultBaseType>>,
        public ActionWithBuilder<AddSymbolSectionAction<Traits>, typename Traits::AttributesType, ActionsSequence>,
        public ActionWithPrinter<AddSymbolSectionAction<Traits>> {
public:
    AddSymbolSectionAction(std::string name, typename Traits::AttributesType attrs, ActionsSequence actions)
            : Action(std::move(name)),
              ActionWithAttributes<typename Traits::AttributesType>(std::move(attrs)),
              ActionWithNestBase(std::move(actions)) {
    }

private:
    using ActionWithNestBase = ActionWithNest<AddSymbolSectionAction<Traits>, typename Traits::ExpectedNestedActionType,
                                              Operand<typename Traits::ResultBaseType>>;

    virtual void execute(TestBlobHandle& handle) override {
        auto writer = handle.getWriter();

        auto symbolSection = Traits::buildSymbolSection(writer, getName());
        symbolSection->setFlags(this->getAttributes()._commonSectionAttrs._flags);
        symbolSection->setAddrAlign(this->getAttributes()._commonSectionAttrs._alignment);
        symbolSection->setInfo(this->getAttributes()._symbolSectionAttrs._info);

        handle.addResult(this, std::make_shared<typename Traits::ResultType>(symbolSection));

        this->executeNested(handle);
    }
};

using AddSymbolSection = AddSymbolSectionAction<SymbolSectionTraits>;
using AddDMASymbolSection = AddSymbolSectionAction<DMASymbolSectionTraits>;
