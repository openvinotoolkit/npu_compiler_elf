#
# Copyright (C) 2023-2025 Intel Corporation.
# SPDX-License-Identifier: Apache-2.0
#

set(TARGET_NAME VPUXLoader)

if (WIN32)
    set(CMAKE_WINDOWS_EXPORT_ALL_SYMBOLS ON)
endif(WIN32)

set(Loader_Library_SRCS
    src/vpux_loader.cpp
)

add_library(${TARGET_NAME} STATIC ${Loader_Library_SRCS})

target_link_libraries(${TARGET_NAME}
    PUBLIC
        npu_elf
)

target_compile_definitions(npu_elf PUBLIC HOST_BUILD)

#--------------------------------------------------------------------------------------------
# npu_elf lib + loader lib
#--------------------------------------------------------------------------------------------
#
# loader folder | -> include/ | -> vpux_headers/ -> 1 hpp
#               |             | -> vpux_loader/  -> 1 hpp

install(DIRECTORY "include/vpux_headers"
        DESTINATION cid/vpux_elf/loader/include/
        COMPONENT ${CID_COMPONENT})

install(DIRECTORY "include/vpux_loader"
        DESTINATION cid/vpux_elf/loader/include/
        COMPONENT ${CID_COMPONENT})

#
# hpi_component | -> common/ -> 2 hpp
#               | -> 3720/   -> 1 hpp
#               | -> 4000/   -> 1 hpp

install(DIRECTORY "../hpi_component/include/common"
        DESTINATION cid/vpux_elf/loader/include/
        COMPONENT ${CID_COMPONENT})

install(DIRECTORY "../hpi_component/include/3720"
        DESTINATION cid/vpux_elf/loader/include/
        COMPONENT ${CID_COMPONENT})

install(DIRECTORY "../hpi_component/include/4000"
        DESTINATION cid/vpux_elf/loader/include/
        COMPONENT ${CID_COMPONENT})

#
# loader folder | -> src/ | 1 cpp

install(DIRECTORY "../hpi_component/src"
        DESTINATION cid/vpux_elf/loader/src/
        COMPONENT ${CID_COMPONENT})

#
# hpi_component | src | common -> 1 cpp
#               |     |  3720  -> 1 cpp
#               |     |  4000  -> 1 cpp


install(DIRECTORY "../hpi_component/src/common"
        DESTINATION cid/vpux_elf/loader/src/
        COMPONENT ${CID_COMPONENT})

install(DIRECTORY "../hpi_component/src/3720"
        DESTINATION cid/vpux_elf/loader/src/
        COMPONENT ${CID_COMPONENT})

install(DIRECTORY "../hpi_component/src/4000"
        DESTINATION cid/vpux_elf/loader/src/
        COMPONENT ${CID_COMPONENT})

# core folder | -> include/ -> vpux_elf/ | -> types/
#             |                          | -> utils/
#             |                          | -> writer/
#             |                          | -> + 3 hpp

# 3 hpp
install(DIRECTORY "../core/include/vpux_elf"
        DESTINATION cid/vpux_elf/core/include/
        COMPONENT ${CID_COMPONENT})

# types
install(DIRECTORY "../core/include/vpux_elf/types"
        DESTINATION cid/vpux_elf/core/include/vpux_elf/
        COMPONENT ${CID_COMPONENT})

# utils
install(DIRECTORY "../core/include/vpux_elf/utils"
        DESTINATION cid/vpux_elf/core/include/vpux_elf/
        COMPONENT ${CID_COMPONENT})

# writer
install(DIRECTORY "../core/include/vpux_elf/writer"
        DESTINATION cid/vpux_elf/core/include/vpux_elf/
        COMPONENT ${CID_COMPONENT})

# core folder | -> src/ -> | -> types/
#             |            | -> utils/
#             |            | -> writer/
#             |            | -> + 2 cpp

# 2 cpp
install(DIRECTORY "../core/src"
        DESTINATION cid/vpux_elf/core/
        COMPONENT ${CID_COMPONENT})

# types
install(DIRECTORY "../core/src/types"
        DESTINATION cid/vpux_elf/core/src/
        COMPONENT ${CID_COMPONENT})

# utils
install(DIRECTORY "../core/src/utils"
        DESTINATION cid/vpux_elf/core/src/
        COMPONENT ${CID_COMPONENT})

# writer
install(DIRECTORY "../core/src/writer"
        DESTINATION cid/vpux_elf/core/src/
        COMPONENT ${CID_COMPONENT})

# loader lib
install(TARGETS VPUXLoader
        CONFIGURATIONS Release
        LIBRARY DESTINATION cid/vpux_elf/lib/Release COMPONENT ${CID_COMPONENT}
        ARCHIVE DESTINATION cid/vpux_elf/lib/Release COMPONENT ${CID_COMPONENT}
        RUNTIME DESTINATION cid/vpux_elf/lib/Release COMPONENT ${CID_COMPONENT})
install(TARGETS VPUXLoader
        CONFIGURATIONS Debug
        LIBRARY DESTINATION cid/vpux_elf/lib/Debug COMPONENT ${CID_COMPONENT}
        ARCHIVE DESTINATION cid/vpux_elf/lib/Debug COMPONENT ${CID_COMPONENT}
        RUNTIME DESTINATION cid/vpux_elf/lib/Debug COMPONENT ${CID_COMPONENT})
install(TARGETS VPUXLoader
        CONFIGURATIONS RelWithDebInfo
        LIBRARY DESTINATION cid/vpux_elf/lib/RelWithDebInfo COMPONENT ${CID_COMPONENT}
        ARCHIVE DESTINATION cid/vpux_elf/lib/RelWithDebInfo COMPONENT ${CID_COMPONENT}
        RUNTIME DESTINATION cid/vpux_elf/lib/RelWithDebInfo COMPONENT ${CID_COMPONENT})

# elf lib
install(TARGETS npu_elf
        CONFIGURATIONS Release
        LIBRARY DESTINATION cid/vpux_elf/lib/Release COMPONENT ${CID_COMPONENT}
        ARCHIVE DESTINATION cid/vpux_elf/lib/Release COMPONENT ${CID_COMPONENT}
        RUNTIME DESTINATION cid/vpux_elf/lib/Release COMPONENT ${CID_COMPONENT})
install(TARGETS npu_elf
        CONFIGURATIONS Debug
        LIBRARY DESTINATION cid/vpux_elf/lib/Debug COMPONENT ${CID_COMPONENT}
        ARCHIVE DESTINATION cid/vpux_elf/lib/Debug COMPONENT ${CID_COMPONENT}
        RUNTIME DESTINATION cid/vpux_elf/lib/Debug COMPONENT ${CID_COMPONENT})
install(TARGETS npu_elf
        CONFIGURATIONS RelWithDebInfo
        LIBRARY DESTINATION cid/vpux_elf/lib/RelWithDebInfo COMPONENT ${CID_COMPONENT}
        ARCHIVE DESTINATION cid/vpux_elf/lib/RelWithDebInfo COMPONENT ${CID_COMPONENT}
        RUNTIME DESTINATION cid/vpux_elf/lib/RelWithDebInfo COMPONENT ${CID_COMPONENT})
