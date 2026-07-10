//
// Copyright (C) 2026 Intel Corporation.
// SPDX-License-Identifier: Apache-2.0
//

#pragma once

#include <memory>
#include <type_traits>
#include <utility>

#include "test_blob/interfaces.hpp"
#include "test_blob/test_blob.hpp"
#include "utils/cast_utils.hpp"
#include "utils/printing.hpp"

struct CommonSectionAttributes {
    elf::Elf_Xword _flags = {};
    elf::Elf_Xword _alignment = 8;

    std::string getStringified() const {
        std::stringstream stream;
        stream << "flags = " << std::hex << "0x" << _flags << std::dec << ", alignment = " << _alignment;
        return stream.str();
    }
};

template <typename T>
struct Operand {
    std::string _name = {};
    constexpr T* getType() const;
    auto get(TestBlobHandle& handle) const {
        return dyn_cast_or_throw<T*>(handle.getResult(_name).get());
    }
};

class Action : public IAction {
public:
    explicit Action(std::string name): _name(std::move(name)) {
    }

    virtual const std::string& getName() const override final {
        return _name;
    }

private:
    const std::string _name = {};

    virtual void finalize(TestBlobHandle&) override {};
};

template <typename ActionType, typename... Args>
class ActionWithBuilder {
public:
    static std::shared_ptr<ActionType> build(std::string name, Args&&... args) {
        return std::make_shared<ActionType>(std::move(name), std::forward<Args>(args)...);
    }
};

template <typename Impl, typename ExpectedNestedType = void, typename OperandType = void>
class ActionWithNest : public IActionWithNest {
public:
    explicit ActionWithNest(ActionsSequence actions): _actions(std::move(actions)) {
    }

    void printNested(std::ostream* os, const std::string& indent) const {
        for (auto& action : _actions._actions) {
            if (auto ptr = dynamic_cast<IPrintable*>(action.get())) {
                ptr->print(os, indent + "    ");
            }
        }
    }

protected:
    ActionsSequence _actions = {};

    void executeNested(TestBlobHandle& handle) {
        for (auto& action : _actions._actions) {
            if constexpr (!std::is_same<ExpectedNestedType, void>()) {
                // Expect a certain result type interface to allow only certain results
                assert_isa<ExpectedNestedType*>(action.get());
            }

            if constexpr (!std::is_same_v<OperandType, void>) {
                // If expecting an implicit operand, set it if the action accepts it
                if (auto actionWithImplicitOperand =
                            dynamic_cast<IActionWithImplicitOperand<OperandType>*>(action.get())) {
                    auto implicitOperand = OperandType{};
                    implicitOperand._name = static_cast<Impl*>(this)->getName();
                    actionWithImplicitOperand->setImplicitOperand(implicitOperand);
                }
            }
            // Forward to TestBlob for tracking and execution
            handle.execute(action);
        }
    }

    virtual const ActionsSequence& getActions() const override final {
        return _actions;
    }
};

template <typename AttrsType>
class ActionWithAttributes {
public:
    using Attributes = AttrsType;

    const AttrsType& getAttributes() const {
        return _attrs;
    }

protected:
    explicit ActionWithAttributes(AttrsType attrs): _attrs(std::move(attrs)) {
    }

    static AttrsType getType();

private:
    AttrsType _attrs = {};
};

template <typename OperandsType>
class ActionWithOperands {
public:
    using Operands = OperandsType;

    const OperandsType& getOperands() const {
        return _operands;
    }

protected:
    explicit ActionWithOperands(OperandsType operands): _operands(std::move(operands)) {
    }

    static OperandsType getType();
    OperandsType& getMutableOperands() {
        return _operands;
    }

private:
    OperandsType _operands = {};
};

template <typename OperandsType>
class ActionWithOperandsWithImplicitOperand :
        public ActionWithOperands<OperandsType>,
        public IActionWithImplicitOperand<typename OperandsType::ImplicitOperandType>

{
public:
    ActionWithOperandsWithImplicitOperand(OperandsType operands)
            : ActionWithOperands<OperandsType>(std::move(operands)) {
    }

protected:
    using OperandType = typename OperandsType::ImplicitOperandType;

    virtual void setImplicitOperand(OperandType operand) override final {
        auto& implicitOperand = this->getMutableOperands().getImplicitOperand();
        if (!implicitOperand._name.empty() && implicitOperand._name != operand._name) {
            throw std::runtime_error("Implicit operand already set with a different value");
        }
        implicitOperand._name = operand._name;
    }
};

template <typename ActionType>
class ActionWithPrinter : public IPrintable {
public:
    virtual void print(std::ostream* os, const std::string& indent) const override final {
        auto* impl = static_cast<const ActionType*>(this);

        *os << indent << "[" << impl->getName() << " : "
            << Printing::demangle(typeid(typename std::decay<ActionType>::type).name()) << "]";

        if constexpr (hasGetAttributes<ActionType>::value) {
            auto attrs = impl->getAttributes();
            if constexpr (hasGetStringified<decltype(attrs)>::value) {
                *os << "(";
                *os << attrs.getStringified();
                *os << ")";
            }
        }
        if constexpr (hasGetOperands<ActionType>::value) {
            auto operands = impl->getOperands();
            if constexpr (hasGetStringified<decltype(operands)>::value) {
                *os << "(";
                *os << operands.getStringified();
                *os << ")";
            }
        }
        if constexpr (hasPrintNested<ActionType>::value) {
            *os << "\n" << indent + "{\n";
            impl->printNested(os, indent);
            *os << indent + "}";
        }
        *os << std::endl;
    }

private:
    template <typename T, typename = void>
    struct hasGetAttributes : std::false_type {};
    template <typename T>
    struct hasGetAttributes<T, std::void_t<decltype(&T::getAttributes)>> : std::true_type {};

    template <typename T, typename = void>
    struct hasGetOperands : std::false_type {};
    template <typename T>
    struct hasGetOperands<T, std::void_t<decltype(&T::getOperands)>> : std::true_type {};

    template <typename T, typename = void>
    struct hasGetStringified : std::false_type {};
    template <typename T>
    struct hasGetStringified<T, std::void_t<decltype(&T::getStringified)>> : std::true_type {};

    template <typename T, typename = void>
    struct hasPrintNested : std::false_type {};
    template <typename T>
    struct hasPrintNested<T, std::void_t<decltype(&T::printNested)>> : std::true_type {};
};

template <typename BinaryDataSectionType>
class BinarySectionResult : public IBinarySectionResult<BinaryDataSectionType> {
public:
    explicit BinarySectionResult(BinaryDataSectionType* binarySection): _binarySection(binarySection) {
    }

    virtual elf::writer::Section* getSection() override final {
        return _binarySection;
    }
    virtual BinaryDataSectionType* getBinarySection() override final {
        return _binarySection;
    }

protected:
    BinaryDataSectionType* _binarySection = {};
};

template <typename SymbolType, typename SymbolSectionType>
class SymbolResult : public ISymbolResult<SymbolType, SymbolSectionType> {
public:
    SymbolResult(SymbolType* symbol, SymbolSectionType* symbolSection): _symbol(symbol), _symbolSection(symbolSection) {
    }

    // Main result (a symbol)
    virtual SymbolType* getSymbol() override final {
        return _symbol;
    }
    // Dependent result (a symbol section must exist beforehand)
    virtual SymbolSectionType* getSymbolSection() override final {
        return _symbolSection;
    }

protected:
    SymbolType* _symbol = {};
    SymbolSectionType* _symbolSection = {};
};

template <typename SymbolSectionType>
class SymbolSectionResult : public ISymbolSectionResult<SymbolSectionType> {
public:
    explicit SymbolSectionResult(SymbolSectionType* symbolSection): _symbolSection(symbolSection) {
    }

    virtual elf::writer::Section* getSection() override final {
        return _symbolSection;
    }
    virtual SymbolSectionType* getSymbolSection() override final {
        return _symbolSection;
    }

protected:
    SymbolSectionType* _symbolSection = {};
};

template <typename RelocationType, typename SymbolType>
class RelocationResult : public IRelocationResult<RelocationType, SymbolType> {
public:
    explicit RelocationResult(RelocationType* relocation): _relocation(relocation) {
    }

    virtual RelocationType* getRelocation() override final {
        return _relocation;
    }

protected:
    RelocationType* _relocation = {};
};

template <typename RelocationSectionType, typename SymbolSectionType>
class RelocationSectionResult : public IRelocationSectionResult<RelocationSectionType, SymbolSectionType> {
public:
    RelocationSectionResult(RelocationSectionType* relocationSection, SymbolSectionType* symbolSection)
            : _relocationSection(relocationSection), _symbolSection(symbolSection) {
    }

    virtual elf::writer::Section* getSection() override final {
        return _relocationSection;
    }
    virtual RelocationSectionType* getRelocationSection() override final {
        return _relocationSection;
    }
    virtual SymbolSectionType* getSymbolSection() override final {
        return _symbolSection;
    }

protected:
    RelocationSectionType* _relocationSection = {};
    SymbolSectionType* _symbolSection = {};
};
