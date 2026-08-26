//
// Copyright (C) 2026 Intel Corporation.
// SPDX-License-Identifier: Apache-2.0
//

#include <fstream>

#include "test_blob/interfaces.hpp"
#include "test_blob/string_map.hpp"
#include "test_blob/test_blob.hpp"
#include "vpux_elf/writer.hpp"

class TestBlobCore {
public:
    TestBlobCore(): _handle(new TestBlobHandle(this)) {
    }
    explicit TestBlobCore(const ActionsSequence& sequence): _handle(new TestBlobHandle(this)) {
        execute(sequence);
    }

    void execute(std::shared_ptr<IAction> action) {
        // Insert before execution for following main reasons:
        // 1. Check whether action was already executed (insertAction will throw when action with the same name has
        // already been registered)
        // 2. Allow nested actions to reference current action
        insertAction(action);
        action->execute(*_handle);
    }
    void execute(const ActionsSequence& sequence) {
        for (auto& elem : sequence._actions) {
            execute(elem);
        }
    }
    std::vector<uint8_t> getBinary() {
        _writer.prepareWriter();
        std::vector<uint8_t> elf(_writer.getTotalSize());
        _writer.generateELF(elf.data());
        _writer.setSectionsStartAddr(elf.data());

        for (const auto& action : _actionMap) {
            action.second->finalize(*_handle);
        }

        return elf;
    }
    elf::Writer* getWriter() {
        return &_writer;
    }
    std::shared_ptr<IAction> getAction(const std::string& name) {
        return _actionMap.get(name);
    }
    void addResult(const std::string& name, std::shared_ptr<IResult> result) {
        _resultMap.insert(name, result);
    }
    std::shared_ptr<IResult> getResult(const std::string& name) {
        return _resultMap.get(name);
    }
    static void dumpToFile(const std::string& fileName, const std::vector<uint8_t>& binary) {
        auto stream = std::ofstream(fileName);
        stream.write(reinterpret_cast<const char*>(binary.data()), binary.size());
    }

private:
    std::unique_ptr<TestBlobHandle> _handle = {};
    elf::Writer _writer = {};
    StringMap<std::shared_ptr<IAction>> _actionMap = {};
    StringMap<std::shared_ptr<IResult>> _resultMap = {};

    void insertAction(std::shared_ptr<IAction> action) {
        _actionMap.insert(action->getName(), std::move(action));
    }
};

TestBlob::TestBlob(): _core(new TestBlobCore()) {
}
TestBlob::TestBlob(const ActionsSequence& sequence): _core(new TestBlobCore(sequence)) {
}

void TestBlob::execute(std::shared_ptr<IAction> action) {
    _core->execute(action);
}
void TestBlob::execute(const ActionsSequence& sequence) {
    _core->execute(sequence);
}
std::vector<uint8_t> TestBlob::getBinary() {
    return _core->getBinary();
}
std::shared_ptr<IAction> TestBlob::getAction(const std::string& name) {
    return _core->getAction(name);
}
void TestBlob::dumpToFile(const std::string& fileName, const std::vector<uint8_t>& binary) {
    TestBlobCore::dumpToFile(fileName, binary);
}

void TestBlobHandle::execute(std::shared_ptr<IAction> action) {
    _core->execute(action);
}
void TestBlobHandle::execute(const ActionsSequence& sequence) {
    _core->execute(sequence);
}
elf::Writer* TestBlobHandle::getWriter() {
    return _core->getWriter();
}
void TestBlobHandle::addResult(const IAction* action, std::shared_ptr<IResult> result) {
    _core->addResult(action->getName(), result);
}
std::shared_ptr<IResult> TestBlobHandle::getResult(const std::string& name) {
    return _core->getResult(name);
}

TestBlobHandle::TestBlobHandle(TestBlobCore* core): _core(core) {
}
