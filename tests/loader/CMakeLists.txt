#
# Copyright (C) 2025 Intel Corporation.
# SPDX-License-Identifier: Apache-2.0
#

set(TARGET_NAME loader_tests)

add_executable(
    ${TARGET_NAME}
    ./loader_tests.cpp
    ${PROJECT_SOURCE_DIR}/loader/src/vpux_loader.cpp
    ${PROJECT_SOURCE_DIR}/loader/src/device_buffer_container.cpp
    ${PROJECT_SOURCE_DIR}/loader/src/relocations.cpp
    ${PROJECT_SOURCE_DIR}/core/src/writer.cpp
    ${PROJECT_SOURCE_DIR}/core/src/writer/dma_symbol.cpp
    ${PROJECT_SOURCE_DIR}/core/src/writer/dma_symbol_section.cpp
    ${PROJECT_SOURCE_DIR}/core/src/accessor.cpp
    ${PROJECT_SOURCE_DIR}/core/src/writer/empty_section.cpp
    ${PROJECT_SOURCE_DIR}/core/src/writer/relocation_section.cpp
    ${PROJECT_SOURCE_DIR}/core/src/writer/relocation.cpp
    ${PROJECT_SOURCE_DIR}/core/src/writer/section.cpp
    ${PROJECT_SOURCE_DIR}/core/src/writer/string_section.cpp
    ${PROJECT_SOURCE_DIR}/core/src/writer/symbol_section.cpp
    ${PROJECT_SOURCE_DIR}/core/src/writer/symbol.cpp
    ${PROJECT_SOURCE_DIR}/core/src/types/symbol_entry.cpp
    ${PROJECT_SOURCE_DIR}/core/src/types/relocation_entry.cpp
    ${PROJECT_SOURCE_DIR}/loader/src/managed_buffer.cpp
    ${PROJECT_SOURCE_DIR}/core/src/utils/utils.cpp
    ${PROJECT_SOURCE_DIR}/core/src/utils/log.cpp
)

target_include_directories(${TARGET_NAME} PUBLIC
    ${PROJECT_SOURCE_DIR}/core/include/
    ${PROJECT_SOURCE_DIR}/loader/include/
    ${PROJECT_SOURCE_DIR}/3rdparty/nnrt_api/
)

target_link_libraries(
    ${TARGET_NAME}
    GTest::gtest_main
)

gtest_discover_tests(${TARGET_NAME})
