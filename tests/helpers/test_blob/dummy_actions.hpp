//
// Copyright (C) 2026 Intel Corporation.
// SPDX-License-Identifier: Apache-2.0
//

#pragma once

#include "test_blob/actions_base.hpp"
#include "test_blob/interfaces.hpp"

class Dummy : public Action, public ActionWithBuilder<Dummy>, public ActionWithPrinter<Dummy> {
public:
    Dummy(std::string name): Action(std::move(name)) {
    }

private:
    virtual void execute(TestBlobHandle&) override final {
    }
};

class DummyNest :
        public Action,
        public ActionWithNest<DummyNest>,
        public ActionWithBuilder<DummyNest, ActionsSequence>,
        public ActionWithPrinter<DummyNest> {
public:
    DummyNest(std::string name, const ActionsSequence& actions): Action(std::move(name)), ActionWithNest(actions) {
    }

private:
    virtual void execute(TestBlobHandle& handle) override final {
        this->executeNested(handle);
    }
};
