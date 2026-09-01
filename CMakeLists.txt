#
# Copyright (C) 2023-2026 Intel Corporation
# SPDX-License-Identifier: Apache-2.0
#

cmake_minimum_required(VERSION 3.15 FATAL_ERROR)

include(./cmake/compiler_linker_options.cmake)
include(./cmake/clang_tidy.cmake)


set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

set(LIB_NAME npu_elf)

project(${LIB_NAME})

include(TestBigEndian)
TEST_BIG_ENDIAN(IS_BIG_ENDIAN)
if(IS_BIG_ENDIAN)
    message(FATAL "ELF Parsing Library supports only little-endian architectures")
endif()

file(GLOB_RECURSE SOURCES CONFIGURE_DEPENDS "*.hpp" "*.cpp")
# Drop anything under the build tree: when the binary dir lives inside the source
# tree, GLOB_RECURSE otherwise sweeps up generated files (e.g. CMake's
# CMakeCXXCompilerId.cpp) and compiles them into the library, where clang-tidy lints them.
list(FILTER SOURCES EXCLUDE REGEX "${CMAKE_CURRENT_BINARY_DIR}/.*")
list(FILTER SOURCES EXCLUDE REGEX "${CMAKE_CURRENT_SOURCE_DIR}/example/.*")
list(FILTER SOURCES EXCLUDE REGEX "${CMAKE_CURRENT_SOURCE_DIR}/tests/.*")
list(FILTER SOURCES EXCLUDE REGEX "${CMAKE_CURRENT_SOURCE_DIR}/npu-loader/.*")
list(FILTER SOURCES EXCLUDE REGEX "${CMAKE_CURRENT_SOURCE_DIR}/allocator_utils/.*")

source_group(TREE ${CMAKE_CURRENT_SOURCE_DIR} FILES ${HEADERS} ${SOURCES})

add_library(${LIB_NAME} STATIC ${SOURCES})

# Use CMake's toolchain-agnostic PIC property instead of a compiler-specific flag (-fPIC).
# This ensures correct behavior on all platforms (GCC, Clang, etc.) without hardcoding flags.
if(NOT MSVC)
    set_target_properties(${LIB_NAME} PROPERTIES POSITION_INDEPENDENT_CODE ON)
endif()

if(MSVC AND BUILD_COMPILER_FOR_DRIVER)
    # For compiler in driver build, npu_elf static lib needs to build with /MT to avoid mismatch with level zero targets.
    # From cmake >= 3.15, the default CMAKE_MSVC_RUNTIME_LIBRARY is /MD, thus causing always overriding /MT with /MD.
    # So here we set the target's MSVC_RUNTIME_LIBRARY to MT to avoid such overriding behavior.
    set_target_properties(${LIB_NAME} PROPERTIES MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")
endif()

target_compile_definitions(${LIB_NAME} PUBLIC HOST_BUILD)

target_include_directories(${LIB_NAME} PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/core/include>
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/loader/include>
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/hpi_component/include/3720>
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/hpi_component/include/4000>
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/hpi_component/include/5000>
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/hpi_component/include/common>)

# Set compiler options
target_compile_options(${LIB_NAME} PRIVATE
    $<$<CONFIG:Release>:${UMD_COMPILER_OPTIONS_RELEASE}>
    $<$<CONFIG:Debug>:${UMD_COMPILER_OPTIONS_DEBUG}>
    $<$<CONFIG:RelWithDebInfo>:${UMD_COMPILER_OPTIONS_RELEASE}>
    # /Zf enables compiler support for faster generation of PDB files when compiled concurrently
    $<$<CXX_COMPILER_ID:MSVC>:/Zf>)

# Set linker options
target_link_options(${LIB_NAME} PRIVATE
    $<$<CONFIG:Release>:${UMD_LINKER_OPTIONS_RELEASE}>
    $<$<CONFIG:Debug>:${UMD_LINKER_OPTIONS_DEBUG}>
    $<$<CONFIG:RelWithDebInfo>:${UMD_LINKER_OPTIONS_RELEASE}>)

# Add external deps
if(EXTERNAL_DEPS)
    target_link_libraries(${LIB_NAME} PUBLIC ${EXTERNAL_DEPS})
    add_subdirectory(loader)
endif(EXTERNAL_DEPS)

if(NOT BUILD_SHARED_LIBS)
    install(TARGETS ${LIB_NAME}
            RUNTIME DESTINATION ${IE_CPACK_RUNTIME_PATH} COMPONENT ${VPUX_PLUGIN_COMPONENT}
            ARCHIVE DESTINATION ${IE_CPACK_ARCHIVE_PATH} COMPONENT ${VPUX_PLUGIN_COMPONENT}
            LIBRARY DESTINATION ${IE_CPACK_LIBRARY_PATH} COMPONENT ${VPUX_PLUGIN_COMPONENT})
endif()

# This cmake code snippet should always be put at the end to make sure it's not updated finally.
if(MSVC AND BUILD_COMPILER_FOR_DRIVER)
    # To avoid the RuntimeLibrary mismatch in #E-109895 and #E-111901
    # Check targets's msvc runtime for 1click pipeline flow which isn't covered in NPU plugin's repo pr-check
    set(MODULE_DIR "build-modules")
    if(NOT ${PROJECT_BINARY_DIR} MATCHES ${MODULE_DIR})
        get_target_property(LIB_MSVC_RUNTIME_LIBRARY ${LIB_NAME} MSVC_RUNTIME_LIBRARY)
        if(NOT LIB_MSVC_RUNTIME_LIBRARY STREQUAL "MultiThreaded$<$<CONFIG:Debug>:Debug>")
            message(FATAL_ERROR "${LIB_NAME} CMAKE_MSVC_RUNTIME_LIBRARY is not MT[d], is ${LIB_MSVC_RUNTIME_LIBRARY}, exiting")
        endif()
    endif()
endif()

target_compile_definitions(${LIB_NAME} PRIVATE $<$<NOT:$<CONFIG:Release>>:NRELEASE>)

target_include_directories(${LIB_NAME} SYSTEM PRIVATE "${PROJECT_SOURCE_DIR}/3rdparty/nnrt")

if(ENABLE_NPU_LOADER)
    include(./cmake/gflags.cmake)
    add_subdirectory(./npu-loader)
endif()

if(ENABLE_ELF_TESTS)
    include(./cmake/gtest.cmake)
    add_subdirectory(./allocator_utils)
    add_subdirectory(./tests)
endif()
