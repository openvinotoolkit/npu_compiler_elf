#
# Copyright (C) 2023-2026 Intel Corporation
# SPDX-License-Identifier: Apache-2.0
#

cmake_minimum_required(VERSION 3.15 FATAL_ERROR)

include( ./cmake/compiler_linker_options.cmake )


set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

set(LIB_NAME npu_elf)

project(${LIB_NAME})

include(cmake/FindFirmwareHeaders.cmake)

include(TestBigEndian)
TEST_BIG_ENDIAN(IS_BIG_ENDIAN)
if(IS_BIG_ENDIAN)
    message(FATAL "ELF Parsing Library supports only little-endian architectures")
endif()

file(GLOB_RECURSE SOURCES CONFIGURE_DEPENDS "*.hpp" "*.cpp")
list(FILTER SOURCES EXCLUDE REGEX "${CMAKE_CURRENT_SOURCE_DIR}/example/.*")
list(FILTER SOURCES EXCLUDE REGEX "${CMAKE_CURRENT_SOURCE_DIR}/tests/.*")
list(FILTER SOURCES EXCLUDE REGEX "${CMAKE_CURRENT_SOURCE_DIR}/npu-loader/.*")
list(FILTER SOURCES EXCLUDE REGEX "${CMAKE_CURRENT_SOURCE_DIR}/allocator_utils/.*")

source_group(TREE ${CMAKE_CURRENT_SOURCE_DIR} FILES ${HEADERS} ${SOURCES})

add_library(${LIB_NAME} STATIC ${SOURCES})

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
    if (UNIX)
        # we need for fPIC flags because `npu_elf` is used for dynamic libraries linkage.
        # it seems that this option is set implicitly somewhere due to compile flags overriding...
        # Since `vpux-elf` is expected to be a standalone submodule, we add this option by a purpose
        set_property(TARGET ${LIB_NAME} PROPERTY POSITION_INDEPENDENT_CODE ON)
    endif()
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

# Local copy of nnrt headers should only be used by testing infrastructure
# Not to be used in production environment!
if(ENABLE_LOCAL_NNRT_API OR ENABLE_ELF_TESTS OR ENABLE_NPU_LOADER)
    set(NNRT_API_HEADER "${PROJECT_SOURCE_DIR}/3rdparty/nnrt_api/api/vpu_nnrt_api.h")
    if(NOT EXISTS "${NNRT_API_HEADER}")
        find_program(PATCH_EXECUTABLE patch)
        if(NOT PATCH_EXECUTABLE)
            message(FATAL_ERROR "ENABLE_ELF_TESTS requires 'patch' utility to restore 3rdparty/nnrt_api")
        endif()

        message(STATUS "ENABLE_ELF_TESTS is ON: restoring 3rdparty/nnrt_api from cmake/patches/nnrt_api.patch")
        execute_process(
            COMMAND "${PATCH_EXECUTABLE}" --forward -p1 -i "${PROJECT_SOURCE_DIR}/cmake/patches/nnrt_api.patch"
            WORKING_DIRECTORY "${PROJECT_SOURCE_DIR}"
            RESULT_VARIABLE NNRT_PATCH_RESULT
            OUTPUT_VARIABLE NNRT_PATCH_OUTPUT
            ERROR_VARIABLE NNRT_PATCH_ERROR)

        target_include_directories(${LIB_NAME} PRIVATE "${PROJECT_SOURCE_DIR}/3rdparty/nnrt_api/")

        # Ensure `make clean` also drops restored test-only headers.
        set_property(DIRECTORY APPEND PROPERTY ADDITIONAL_MAKE_CLEAN_FILES
        "${PROJECT_SOURCE_DIR}/3rdparty")

        if(NOT NNRT_PATCH_RESULT EQUAL 0)
            message(FATAL_ERROR "Failed to apply nnrt_api patch. patch stdout: ${NNRT_PATCH_OUTPUT}; patch stderr: ${NNRT_PATCH_ERROR}")
        endif()
    endif()
endif()

if(ENABLE_NPU_LOADER)
    include( ./cmake/gflags.cmake)
    add_subdirectory(./npu-loader)
endif()

if(ENABLE_ELF_TESTS)
    include( ./cmake/gtest.cmake)

    add_subdirectory(./allocator_utils)
    add_subdirectory(./tests)
endif()
