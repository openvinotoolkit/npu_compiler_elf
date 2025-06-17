//
// Copyright (C) 2023-2025 Intel Corporation
// SPDX-License-Identifier: Apache 2.0
//

//

#pragma once

#include <assert.h>
#include <cassert>
#include <stdexcept>
#include <vpux_elf/types/elf_structs.hpp>

namespace elf {

class RuntimeError : public std::runtime_error {
public:
    explicit RuntimeError(const char* what): std::runtime_error(what) {
    }
};

class LogicError : public std::logic_error {
public:
    explicit LogicError(const char* what): std::logic_error(what) {
    }
};

#define VPUX_ELF_DEFINE_EXCEPTION(type, name)         \
    class name : public type {                        \
    public:                                           \
        explicit name(const char* what): type(what) { \
        }                                             \
    }

VPUX_ELF_DEFINE_EXCEPTION(RuntimeError, AccessError);
VPUX_ELF_DEFINE_EXCEPTION(RuntimeError, HeaderError);
VPUX_ELF_DEFINE_EXCEPTION(RuntimeError, SectionError);
VPUX_ELF_DEFINE_EXCEPTION(RuntimeError, RelocError);
VPUX_ELF_DEFINE_EXCEPTION(RuntimeError, AllocError);
VPUX_ELF_DEFINE_EXCEPTION(RuntimeError, CompatibilityError);

VPUX_ELF_DEFINE_EXCEPTION(LogicError, RangeError);
VPUX_ELF_DEFINE_EXCEPTION(LogicError, SequenceError);
VPUX_ELF_DEFINE_EXCEPTION(LogicError, ArgsError);
VPUX_ELF_DEFINE_EXCEPTION(LogicError, ImplausibleState);

#ifdef VPUX_ELF_NOEXCEPT
#define VPUX_ELF_THROW(exception, msg, ...) assert(!(msg))
#else
#define VPUX_ELF_THROW(exception, msg, ...) throw(exception(msg, ##__VA_ARGS__))
#endif

#define VPUX_ELF_THROW_UNLESS(condition, exception, msg, ...)  \
    do {                                                       \
        if (!(condition)) {                                    \
            VPUX_ELF_THROW(exception, (msg), ##__VA_ARGS__); \
        }                                                      \
    } while (0);

#define VPUX_ELF_THROW_WHEN(condition, exception, msg, ...)    \
    do {                                                       \
        if ((condition)) {                                     \
            VPUX_ELF_THROW(exception, (msg), ##__VA_ARGS__); \
        }                                                      \
    } while (0);

}  // namespace elf
