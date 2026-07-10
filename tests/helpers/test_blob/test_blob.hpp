//
// Copyright (C) 2026 Intel Corporation.
// SPDX-License-Identifier: Apache-2.0
//

#pragma once

#include <memory>
#include <string>

#include "test_blob/interfaces.hpp"

#include "vpux_elf/writer.hpp"

struct ActionsSequence {
    std::vector<std::shared_ptr<IAction>> _actions;

    void print(std::ostream* os = &std::cout) const {
        *os << std::endl;
        for (auto& action : _actions) {
            if (auto ptr = dynamic_cast<IPrintable*>(action.get())) {
                ptr->print(os, "");
            }
        }
    }

    ActionsSequence operator+(const ActionsSequence& other) const {
        ActionsSequence result;
        result._actions.reserve(this->_actions.size() + other._actions.size());
        result._actions.insert(result._actions.end(), this->_actions.begin(), this->_actions.end());
        result._actions.insert(result._actions.end(), other._actions.begin(), other._actions.end());
        return result;
    }
};

// Class implementing full test blob functionality
class TestBlobCore;

// Class to expose full set of TestBlobCore APIs for tests creation
class TestBlob {
public:
    TestBlob();
    explicit TestBlob(const ActionsSequence& sequence);

    void execute(std::shared_ptr<IAction> action);
    void execute(const ActionsSequence& sequence);
    std::vector<uint8_t> getBinary();
    std::shared_ptr<IAction> getAction(const std::string& name);
    static void dumpToFile(const std::string& fileName, const std::vector<uint8_t>& binary);

private:
    std::shared_ptr<TestBlobCore> _core = {};
};

// Class to expose only subset of TestBlobCore APIs to classes implementing IAction
class TestBlobHandle {
public:
    void execute(std::shared_ptr<IAction> action);
    void execute(const ActionsSequence& sequence);
    elf::Writer* getWriter();
    void addResult(const IAction* action, std::shared_ptr<IResult> result);
    std::shared_ptr<IResult> getResult(const std::string& name);

private:
    friend TestBlobCore;

    TestBlobCore* _core = {};

    explicit TestBlobHandle(TestBlobCore* core);
};
