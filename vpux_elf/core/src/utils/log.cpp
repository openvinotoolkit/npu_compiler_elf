//
// Copyright (C) 2023-2025 Intel Corporation
// SPDX-License-Identifier: Apache-2.0
//

//

#include <inttypes.h>
#include <stdarg.h>
#include <stdio.h>
#include <vpux_elf/utils/log.hpp>

namespace elf {

#define ANSI_COLOR_RED "\x1b[31m"
#define ANSI_COLOR_GREEN "\x1b[32m"
#define ANSI_COLOR_YELLOW "\x1b[33m"
#define ANSI_COLOR_BLUE "\x1b[34m"
#define ANSI_COLOR_MAGENTA "\x1b[35m"
#define ANSI_COLOR_CYAN "\x1b[36m"
#define ANSI_COLOR_RESET "\x1b[0m"

constexpr static const char logHeader[static_cast<unsigned int>(LogLevel::LOG_LAST)][30] = {
        ANSI_COLOR_RED "F:",  ANSI_COLOR_MAGENTA "E:", ANSI_COLOR_YELLOW "W:",
        ANSI_COLOR_CYAN "I:", ANSI_COLOR_BLUE "T:",    ANSI_COLOR_GREEN "D:",
};

LogLevel Logger::globalLevel = LogLevel::LOG_WARN;

Logger::Logger(const LogLevel& unitLevel, const char* unitName): unitLevel(unitLevel), unitName(unitName) {
}

void Logger::logprintf(const LogLevel& level, const char* func, const int line, const char* format, ...) {
    const char headerFormat[] = "%s [%s] %s:%d\t";
    va_list args = {};
    va_start(args, format);

    static_cast<void>(fprintf(stdout, headerFormat, logHeader[static_cast<unsigned int>(level)], unitName, func, line));
    static_cast<void>(vfprintf(stdout, format, args));
    static_cast<void>(fprintf(stdout, "%s\n", ANSI_COLOR_RESET));

    va_end(args);
}

LogLevel Logger::getGlobalLevel() {
    return globalLevel;
}

void Logger::setGlobalLevel(const LogLevel& level) {
    updateLevelVar(globalLevel, level);
}

LogLevel Logger::getUnitLevel(void) {
    return unitLevel;
}

void Logger::setUnitLevel(const LogLevel& level) {
    updateLevelVar(unitLevel, level);
}

void Logger::updateLevelVar(LogLevel& levelVar, const LogLevel& levelVal) {
    if ((&levelVar != &levelVal) && (LogLevel::LOG_LAST > levelVal)) {
        levelVar = levelVal;
    }
}

}  // namespace elf
