//
// Copyright (C) 2023-2025 Intel Corporation
// SPDX-License-Identifier: Apache-2.0
//

//

#pragma once

#ifndef VPUX_ELF_LOG_ENABLED
#define VPUX_ELF_LOG_ENABLED 0
#endif

#ifndef VPUX_ELF_LOG_UNIT_NAME
#define VPUX_ELF_LOG_UNIT_NAME "unnamed"
#endif

namespace elf {
enum class LogLevel : unsigned int {
    LOG_FATAL = 0U,
    LOG_ERROR,
    LOG_WARN,
    LOG_INFO,
    LOG_TRACE,
    LOG_DEBUG,
    LOG_LAST,
};

class Logger {
public:
    explicit Logger(const LogLevel& unitLevel, const char* unitName);
    void logprintf(const LogLevel& level, const char* func, const int line, const char* format, ...);
    static LogLevel getGlobalLevel();
    static void setGlobalLevel(const LogLevel& level);
    LogLevel getUnitLevel(void);
    void setUnitLevel(const LogLevel& level);

private:
    static LogLevel globalLevel;
    LogLevel unitLevel;
    const char* unitName;

    static void updateLevelVar(LogLevel& levelVar, const LogLevel& levelVal);
};

static constexpr char unitName[] = VPUX_ELF_LOG_UNIT_NAME;
static Logger unitLogger(LogLevel::LOG_ERROR, VPUX_ELF_LOG_UNIT_NAME);

#ifndef VPUX_ELF_LOG
#define VPUX_ELF_LOG(lvl, ...)                                                                                         \
    do {                                                                                                               \
        if ((VPUX_ELF_LOG_ENABLED) && (((lvl) <= Logger::getGlobalLevel()) || ((lvl) <= unitLogger.getUnitLevel()))) { \
            unitLogger.logprintf(lvl, __func__, __LINE__, ##__VA_ARGS__);                                              \
        }                                                                                                              \
    } while (0);
#endif

}  // namespace elf
