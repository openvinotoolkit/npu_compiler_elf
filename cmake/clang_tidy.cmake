#
# Copyright (C) 2026 Intel Corporation.
# SPDX-License-Identifier: Apache-2.0
#

include(CMakeDependentOption)

option(ENABLE_CLANG_TIDY "Enable clang-tidy static analysis" OFF)
option(REQUIRE_CLANG_TIDY_CI_ENV "If ENABLE_CLANG_TIDY is enabled, require the same (up to major version) C/C++ compilers to be used as in the CI" ON)

message(STATUS "ENABLE_CLANG_TIDY=${ENABLE_CLANG_TIDY}")
message(STATUS "REQUIRE_CLANG_TIDY_CI_ENV=${REQUIRE_CLANG_TIDY_CI_ENV}")

# Configure clang-tidy for static analysis when enabled
if(ENABLE_CLANG_TIDY)
    set(_clang_ci_version 22)

    # Find clang-tidy tooling versions used in CI first. If not found: fall back to the system tools
    find_program(CLANG_TIDY_EXE NAMES clang-tidy-${_clang_ci_version})
    find_program(RUN_CLANG_TIDY_EXE NAMES run-clang-tidy-${_clang_ci_version})
    if(NOT REQUIRE_CLANG_TIDY_CI_ENV AND (NOT CLANG_TIDY_EXE OR NOT RUN_CLANG_TIDY_EXE))
       message(WARNING "To make reproducible analysis it's recommended to use the same clang-tidy executable versions as used in CI (${_clang_ci_version}). Falling back to system clang-tidy.")
       find_program(CLANG_TIDY_EXE NAMES clang-tidy)
       find_program(RUN_CLANG_TIDY_EXE NAMES run-clang-tidy)
    endif()

    if(NOT CLANG_TIDY_EXE OR NOT RUN_CLANG_TIDY_EXE)
        message(FATAL_ERROR "ENABLE_CLANG_TIDY is ON but required clang-tidy tooling was not found (clang-tidy + run-clang-tidy)")
    endif()

    if(REQUIRE_CLANG_TIDY_CI_ENV)
        foreach(LANG IN ITEMS C CXX)
            if (NOT CMAKE_${LANG}_COMPILER_ID STREQUAL "Clang")
                message(FATAL_ERROR
                    "ENABLE_CLANG_TIDY with REQUIRE_CLANG_TIDY_CI_ENV requires Clang for the ${LANG} compiler\nCurrent compiler is ${CMAKE_${LANG}_COMPILER_ID} ${CMAKE_${LANG}_COMPILER_VERSION} (${CMAKE_${LANG}_COMPILER}).\n\
                     Reconfigure with a Clang toolchain, or pass -D REQUIRE_CLANG_TIDY_CI_ENV=OFF.")
            endif()

            # CMAKE_<LANG>_COMPILER_VERSION is major[.minor[.patch[.tweak]]], not
            # just the major, so match the whole 22.x series (>= 22 AND < 23).
            # VERSION_EQUAL against a bare "22" would never match e.g. "22.1.8"
            # (it compares component-wise, padding with zeros: 22.1.8 != 22.0.0).
            math(EXPR _clang_ci_next_major "${_clang_ci_version} + 1")
            if(CMAKE_${LANG}_COMPILER_VERSION VERSION_LESS "${_clang_ci_version}" OR
               CMAKE_${LANG}_COMPILER_VERSION VERSION_GREATER_EQUAL "${_clang_ci_next_major}")
                message(FATAL_ERROR "ENABLE_CLANG_TIDY with REQUIRE_CLANG_TIDY_CI_ENV requires Clang ${_clang_ci_version}.x for reproducible analysis, "
                    "but the ${LANG} compiler is ${CMAKE_${LANG}_COMPILER_ID} ${CMAKE_${LANG}_COMPILER_VERSION} (${CMAKE_${LANG}_COMPILER}). "
                    "Reconfigure with a Clang ${_clang_ci_version} toolchain, or pass -D REQUIRE_CLANG_TIDY_CI_ENV=OFF.")
            endif()
        endforeach()
    endif()

    # Export compile commands to a JSON file for clang-tidy
    set(CMAKE_EXPORT_COMPILE_COMMANDS ON)
    message(STATUS "Compile commands exported to compile_commands.json")
endif()
