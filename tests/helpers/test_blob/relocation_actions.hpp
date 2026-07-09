//
// Copyright (C) 2026 Intel Corporation.
// SPDX-License-Identifier: Apache-2.0
//

#pragma once

#include <string>

#include "test_blob/actions_base.hpp"
#include "test_blob/interfaces.hpp"
#include "test_blob/test_blob.hpp"

#include "vpux_elf/types/data_types.hpp"
#include "vpux_elf/writer/dma_symbol.hpp"
#include "vpux_elf/writer/dma_symbol_section.hpp"
#include "vpux_elf/writer/relocation.hpp"
#include "vpux_elf/writer/relocation_section.hpp"
#include "vpux_elf/writer/symbol.hpp"
#include "vpux_elf/writer/symbol_section.hpp"

// Result interfaces are not enforced by the TestBlob class(es) or by IAction interface.
// An action may or may not have a result interface. This is a design choice of developers building actions that work
// together/reference each other.

//
// Dependency chain of a Relocation:
// - Relocation is defined within a RelocationSection
// - RelocationSection references a SymbolSection
// - Relocation references a Symbol from the SymbolSection referenced by its parent RelocationSection
//
// The current implementation has the Relocation object directly reference a pointer to a Symbol object.
// This makes it difficult to directly enforce that the referenced Symbol belongs to the SymbolSection referenced by the
// Relocation parent RelocationSection. This is because the ELF library does not provide a mechanism to enforce this
// dependency. This means the test infra needs to account for this if it is to not allow such invalid cases to be
// generated. However, there may be cases where such invalid configs are desired to test ELF lib behavior.
//

struct AddRelocationAttributes {
    elf::Elf_Word _type = {};
    elf::Elf_Xword _offset = {};
    elf::Elf_Sxword _addend = {};

    std::string getStringified() const {
        std::stringstream stream;
        stream << std::hex << "type = 0x" << _type << ", offset = 0x" << _offset << ", addend = 0x" << _addend;
        return stream.str();
    }
};

struct AddRelocationOperands {
    Operand<ISymbolResult<elf::writer::Symbol, elf::writer::SymbolSection>> _symbol = {};
    Operand<IRelocationSectionResult<elf::writer::RelocationSection, elf::writer::SymbolSection>> _relocationSection =
            {};

    using ImplicitOperandType = decltype(_relocationSection);
    ImplicitOperandType& getImplicitOperand() {
        return _relocationSection;
    }

    std::string getStringified() const {
        std::stringstream stream;
        stream << "symbol = " << _symbol._name << ", relocationSection = " << _relocationSection._name;
        return stream.str();
    }
};

struct AddDMARelocationOperands {
    Operand<ISymbolResult<elf::writer::DmaSymbol, elf::writer::DmaSymbolSection>> _symbol = {};
    Operand<IRelocationSectionResult<elf::writer::RelocationSection, elf::writer::DmaSymbolSection>>
            _relocationSection = {};

    using ImplicitOperandType = decltype(_relocationSection);
    ImplicitOperandType& getImplicitOperand() {
        return _relocationSection;
    }

    std::string getStringified() const {
        std::stringstream stream;
        stream << "symbol = " << _symbol._name << ", relocationSection = " << _relocationSection._name;
        return stream.str();
    }
};

struct RelocationTraits {
    using AttributesType = AddRelocationAttributes;
    using OperandsType = AddRelocationOperands;
    using ResultType = RelocationResult<elf::writer::Relocation, elf::writer::Symbol>;

    static void setSymbol(elf::writer::Relocation* reloc, const elf::writer::Symbol* symbol) {
        reloc->setSymbol(symbol);
    }
};

struct DMARelocationTraits {
    using AttributesType = AddRelocationAttributes;
    using OperandsType = AddDMARelocationOperands;
    using ResultType = RelocationResult<elf::writer::Relocation, elf::writer::DmaSymbol>;

    static void setSymbol(elf::writer::Relocation* reloc, const elf::writer::DmaSymbol* symbol) {
        reloc->setSpecialSymbol(symbol->getIndex());
    }
};

template <typename Traits>
class AddRelocationAction :
        public Action,
        public ActionWithAttributes<typename Traits::AttributesType>,
        public ActionWithOperandsWithImplicitOperand<typename Traits::OperandsType>,
        public ActionWithBuilder<AddRelocationAction<Traits>, typename Traits::AttributesType,
                                 typename Traits::OperandsType>,
        public ActionWithPrinter<AddRelocationAction<Traits>> {
public:
    AddRelocationAction(std::string name, typename Traits::AttributesType attrs, typename Traits::OperandsType operands)
            : Action(std::move(name)),
              ActionWithAttributes<typename Traits::AttributesType>(std::move(attrs)),
              ActionWithOperandsWithImplicitOperand<typename Traits::OperandsType>(std::move(operands)) {
    }

private:
    virtual void execute(TestBlobHandle& handle) override {
        // Verify the symbol belongs to the symbol section provided to the parent relocation section of this relocation.
        //
        // Following actions need to have been executed by this point:
        //  1. one that produces a SymbolSectionResult
        //  2. one that produces a RelocationSectionResult (depends on 1.)
        //  3. one that produces a SymbolResult (depends on 1.)

        auto relocSectionResult = this->getOperands()._relocationSection.get(handle);
        auto symbolResult = this->getOperands()._symbol.get(handle);

        auto symbolSectionFromRelocation = relocSectionResult->getSymbolSection();
        auto symbolSectionFromSymbol = symbolResult->getSymbolSection();

        if (symbolSectionFromSymbol != symbolSectionFromRelocation) {
            throw(std::runtime_error("Symbol table section mismatch:\n - parent section of symbol: " +
                                     symbolSectionFromSymbol->getName() +
                                     "\n - symbol section used by relocation parent section: " +
                                     symbolSectionFromRelocation->getName()));
        }

        auto relocSection = relocSectionResult->getRelocationSection();
        auto sym = symbolResult->getSymbol();

        auto relocation = relocSection->addRelocationEntry();
        relocation->setOffset(this->getAttributes()._offset);
        relocation->setType(this->getAttributes()._type);
        relocation->setAddend(this->getAttributes()._addend);

        Traits::setSymbol(relocation, sym);

        handle.addResult(this, std::make_shared<typename RelocationTraits::ResultType>(relocation));
    }
};

using AddRelocation = AddRelocationAction<RelocationTraits>;
using AddDMARelocation = AddRelocationAction<DMARelocationTraits>;

struct RelocationSectionAttributes {
    CommonSectionAttributes _commonSectionAttrs = {};

    std::string getStringified() const {
        std::stringstream stream;
        stream << _commonSectionAttrs.getStringified();
        return stream.str();
    }
};

struct RelocationSectionOperands {
    Operand<ISymbolSectionResult<elf::writer::SymbolSection>> _symbolSection = {};
    Operand<ISectionResult> _targetSection = {};

    std::string getStringified() const {
        std::stringstream stream;
        stream << "symbolSection = " << _symbolSection._name << ", targetSection = " << _targetSection._name;
        return stream.str();
    }
};

struct DMARelocationSectionOperands {
    Operand<ISymbolSectionResult<elf::writer::DmaSymbolSection>> _symbolSection = {};
    Operand<ISectionResult> _targetSection = {};

    std::string getStringified() const {
        std::stringstream stream;
        stream << "symbolSection = " << _symbolSection._name << ", targetSection = " << _targetSection._name;
        return stream.str();
    }
};

struct RelocationSectionTraits {
    using ExpectedNestedActionType = AddRelocationAction<RelocationTraits>;
    using AttributesType = RelocationSectionAttributes;
    using OperandsType = RelocationSectionOperands;
    using ResultType = RelocationSectionResult<elf::writer::RelocationSection, elf::writer::SymbolSection>;
    using ResultBaseType = IRelocationSectionResult<elf::writer::RelocationSection, elf::writer::SymbolSection>;

    static void setSymbolTable(elf::writer::RelocationSection* relocationSection,
                               const elf::writer::SymbolSection* symbolSection) {
        relocationSection->setSymbolTable(symbolSection);
    }
};

struct DMARelocationSectionTraits {
    using ExpectedNestedActionType = AddRelocationAction<DMARelocationTraits>;
    using AttributesType = RelocationSectionAttributes;
    using OperandsType = DMARelocationSectionOperands;
    using ResultType = RelocationSectionResult<elf::writer::RelocationSection, elf::writer::DmaSymbolSection>;
    using ResultBaseType = IRelocationSectionResult<elf::writer::RelocationSection, elf::writer::DmaSymbolSection>;

    static void setSymbolTable(elf::writer::RelocationSection* relocationSection,
                               const elf::writer::DmaSymbolSection* symbolSection) {
        relocationSection->setSpecialSymbolTable(symbolSection->getIndex());
    }
};

template <typename Traits>
class AddRelocationSectionAction :
        public Action,
        public ActionWithNest<AddRelocationSectionAction<Traits>, typename Traits::ExpectedNestedActionType,
                              Operand<typename Traits::ResultBaseType>>,
        public ActionWithAttributes<typename Traits::AttributesType>,
        public ActionWithOperands<typename Traits::OperandsType>,
        public ActionWithBuilder<AddRelocationSectionAction<Traits>, typename Traits::AttributesType,
                                 typename Traits::OperandsType, ActionsSequence>,
        public ActionWithPrinter<AddRelocationSectionAction<Traits>> {
public:
    AddRelocationSectionAction(std::string name, typename Traits::AttributesType attrs,
                               typename Traits::OperandsType operands, ActionsSequence nested)
            : Action(std::move(name)),
              ActionWithNestBase(std::move(nested)),
              ActionWithAttributes<typename Traits::AttributesType>(std::move(attrs)),
              ActionWithOperands<typename Traits::OperandsType>(std::move(operands)) {
    }

private:
    using ActionWithNestBase =
            ActionWithNest<AddRelocationSectionAction<Traits>, typename Traits::ExpectedNestedActionType,
                           Operand<typename Traits::ResultBaseType>>;

    virtual void execute(TestBlobHandle& handle) override {
        auto writer = handle.getWriter();

        auto relocationSection = writer->addRelocationSection(getName());
        auto symbolSection = this->getOperands()._symbolSection.get(handle)->getSymbolSection();

        // Any section can be patched by a relocation -> accept the generic ISectionResult
        relocationSection->setSectionToPatch(this->getOperands()._targetSection.get(handle)->getSection());
        relocationSection->setFlags(this->getAttributes()._commonSectionAttrs._flags);
        relocationSection->setAddrAlign(this->getAttributes()._commonSectionAttrs._alignment);

        Traits::setSymbolTable(relocationSection, symbolSection);

        handle.addResult(this, std::make_shared<typename Traits::ResultType>(relocationSection, symbolSection));

        this->executeNested(handle);
    }
};

using AddRelocationSection = AddRelocationSectionAction<RelocationSectionTraits>;
using AddDMARelocationSection = AddRelocationSectionAction<DMARelocationSectionTraits>;
