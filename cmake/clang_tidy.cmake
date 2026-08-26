#
# Copyright (C) 2026 Intel Corporation.
# SPDX-License-Identifier: Apache-2.0
#

include(CMakeDependentOption)

option(ENABLE_CLANG_TIDY "Enable clang-tidy static analysis" OFF)
option(FORCE_CLANG_TIDY_ENV "Force clang-tidy and compiler versions for result reproducibility (when ENABLE_CLANG_TIDY is ON)" ON)

message(STATUS "ENABLE_CLANG_TIDY=${ENABLE_CLANG_TIDY}")
message(STATUS "FORCE_CLANG_TIDY_ENV=${FORCE_CLANG_TIDY_ENV}")

# Configure clang-tidy for static analysis when enabled
if(ENABLE_CLANG_TIDY)
     # Find clang-tidy tooling versions used in CI first. If not found: fall back to the system tools
     find_program(CLANG_TIDY_EXE NAMES clang-tidy-22)
     find_program(RUN_CLANG_TIDY_EXE NAMES run-clang-tidy-22)
     if(NOT FORCE_CLANG_TIDY_ENV AND (NOT CLANG_TIDY_EXE OR NOT RUN_CLANG_TIDY_EXE))
         message(WARNING "To make reproducible analysis it's recommended to use the same clang-tidy executable versions as used in CI. Falling back to system clang-tidy.")
         find_program(CLANG_TIDY_EXE NAMES clang-tidy-22 clang-tidy)
         find_program(RUN_CLANG_TIDY_EXE NAMES run-clang-tidy-22 run-clang-tidy)
     endif()
     if(NOT CLANG_TIDY_EXE OR NOT RUN_CLANG_TIDY_EXE)
         message(FATAL_ERROR "ENABLE_CLANG_TIDY is ON but required clang-tidy tooling was not found (clang-tidy + run-clang-tidy)")
     endif()

	# Find compiler versions used in CI if FORCE_CLANG_TIDY_ENV is ON
	if (FORCE_CLANG_TIDY_ENV)
		find_program(CLANG_C_COMPILER NAMES clang-22)
		find_program(CLANG_CXX_COMPILER NAMES clang++-22)
		if(NOT CLANG_C_COMPILER OR NOT CLANG_CXX_COMPILER)
			message(FATAL_ERROR "ENABLE_CLANG_TIDY forced compiler versions were not found")
		endif()
		set(CMAKE_C_COMPILER "${CLANG_C_COMPILER}" CACHE FILEPATH "C compiler for clang-tidy analysis" FORCE)
		set(CMAKE_CXX_COMPILER "${CLANG_CXX_COMPILER}" CACHE FILEPATH "CXX compiler for clang-tidy analysis" FORCE)
		message(STATUS "Clang enabled for clang-tidy: C=${CMAKE_C_COMPILER}, CXX=${CMAKE_CXX_COMPILER}")
	endif()

	# Export compile commands to a JSON file for clang-tidy
	set(CMAKE_EXPORT_COMPILE_COMMANDS ON)
	message(STATUS "Compile commands exported to compile_commands.json")
endif()
