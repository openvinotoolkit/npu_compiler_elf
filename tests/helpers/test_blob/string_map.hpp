//
// Copyright (C) 2026 Intel Corporation.
// SPDX-License-Identifier: Apache-2.0
//

#pragma once

#include <stdexcept>
#include <string>
#include <unordered_map>

template <typename T>
class StringMap {
public:
    void insert(const std::string& name, const T& data) {
        if (hasElement(name)) {
            throw(std::runtime_error("Element with name " + name + " already exists"));
        }
        _map.insert({name, data});
    }
    auto get(const std::string& name) {
        if (!hasElement(name)) {
            throw(std::runtime_error("Element with name " + name + " does not exist"));
        }
        return _map.at(name);
    }
    const auto begin() {
        return _map.begin();
    }
    const auto end() {
        return _map.end();
    }

private:
    std::unordered_map<std::string, T> _map = {};

    auto hasElement(const std::string& name) {
        auto result = _map.find(name) != _map.end() ? true : false;
        return result;
    }
};
