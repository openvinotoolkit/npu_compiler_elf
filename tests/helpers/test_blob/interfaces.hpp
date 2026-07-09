//
// Copyright (C) 2026 Intel Corporation.
// SPDX-License-Identifier: Apache-2.0
//

#pragma once

#include <iostream>
#include <string>

#include "vpux_elf/writer/section.hpp"

class TestBlobHandle;

// All actions are to be executed by a TestBlob class which supplies a TestBlobHandle.
// Direct interactions with classes implementing IAction after their construction shall be considered undefined
// behavior. This is given mainly by the fact that actions may store blob generation artifacts (such as pointers to ELF
// library objects), which are meant to be accessed by actions only during execution phase of blob building.

// Keep interfaces clean (no data members)

class IAction {
public:
    friend class TestBlobCore;

    virtual const std::string& getName() const = 0;

protected:
    virtual void execute(TestBlobHandle& handle) = 0;
    virtual void finalize(TestBlobHandle&) = 0;
};

template <typename OperandType>
struct IActionWithImplicitOperand {
    virtual void setImplicitOperand(OperandType operand) = 0;
};

struct ActionsSequence;
class IActionWithNest {
public:
    virtual const ActionsSequence& getActions() const = 0;
};

struct IPrintable {
    virtual void print(std::ostream* os, const std::string& indent = {}) const = 0;
};

struct IResult {
    virtual ~IResult() = default;
};

struct ISectionResult : public IResult {
    virtual elf::writer::Section* getSection() = 0;
};

template <typename BinaryDataSectionType>
struct IBinarySectionResult : public ISectionResult {
    virtual BinaryDataSectionType* getBinarySection() = 0;
};

template <typename SymbolType, typename SymbolSectionType>
struct ISymbolResult : public IResult {
    // Main result (a symbol)
    virtual SymbolType* getSymbol() = 0;
    // Dependent result (a symbol section must exist beforehand)
    virtual SymbolSectionType* getSymbolSection() = 0;
};

template <typename SymbolSectionType>
struct ISymbolSectionResult : public ISectionResult {
    virtual SymbolSectionType* getSymbolSection() = 0;
};

template <typename RelocationType, typename SymbolType>
struct IRelocationResult : public IResult {
    virtual RelocationType* getRelocation() = 0;
};

template <typename RelocationSectionType, typename SymbolSectionType>
struct IRelocationSectionResult : public ISectionResult {
    // Main result (a relocation section)
    virtual RelocationSectionType* getRelocationSection() = 0;
    // Dependent result (a symbol section must exist beforehand).
    // Grab SymbolSection* directly here.
    // When action producing this result executes, an action producing a result using SymbolSection* must already
    // have been executed. For now, seems unnecessary to use a middleman when we can grab the SymbolSection*
    // directly.
    virtual SymbolSectionType* getSymbolSection() = 0;
};
