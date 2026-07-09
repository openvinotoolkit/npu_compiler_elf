#
# Copyright (C) 2026 Intel Corporation.
# SPDX-License-Identifier: Apache-2.0
#

cmake_minimum_required(VERSION 3.24)

set(FETCHCONTENT_QUIET FALSE)
set(GFLAGS_BUILD_TESTING OFF CACHE BOOL "" FORCE)
set(BUILD_SHARED_LIBS    OFF CACHE BOOL "" FORCE)

include(FetchContent)
FetchContent_Declare(
    gflags
    GIT_REPOSITORY https://github.com/gflags/gflags.git
    GIT_TAG        v2.3.0
    GIT_PROGRESS   TRUE
    OVERRIDE_FIND_PACKAGE)

FetchContent_MakeAvailable(gflags)

find_package(gflags REQUIRED)
