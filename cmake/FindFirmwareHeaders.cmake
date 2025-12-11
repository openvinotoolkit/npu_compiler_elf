#
# Copyright (C) 2023-2025 Intel Corporation.
# SPDX-License-Identifier: Apache-2.0
#

if (FIRMWARE_PACKAGE_SEARCH_PATH)
    message(AUTHOR_WARNING "Experimental option is enabled, search headers in: ${FIRMWARE_PACKAGE_SEARCH_PATH}")
    list(APPEND CMAKE_PREFIX_PATH ${FIRMWARE_PACKAGE_SEARCH_PATH})
    find_package(fw_vpu_api_headers REQUIRED)

    list(APPEND EXTERNAL_DEPS fw_vpu_api_headers)
endif()
