#
# Copyright (C) 2022-2026 Intel Corporation.
# SPDX-License-Identifier: Apache-2.0
#

# Enable ELF logging for the library when building tests so that log-time code
# paths are exercised and regressions (e.g. null deref inside VPUX_ELF_LOG) are
# caught by the test suite.
target_compile_definitions(npu_elf PRIVATE VPUX_ELF_LOG_ENABLED=1)

add_subdirectory(example)
add_subdirectory(accessor)
add_subdirectory(helpers)
add_subdirectory(hpi)
add_subdirectory(loader)
add_subdirectory(managed_buffer)
add_subdirectory(reader)
add_subdirectory(relocations)
add_subdirectory(serial_struct_base)
add_subdirectory(writer)
