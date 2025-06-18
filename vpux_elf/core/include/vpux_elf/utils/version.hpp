//
// Copyright (C) 2024-2025 Intel Corporation
// SPDX-License-Identifier: Apache 2.0
//

//

#pragma once

#include <cstdint>
#include <sstream>
#include <tuple>
#include <vpux_elf/utils/log.hpp>
#include <vpux_elf/utils/error.hpp>

namespace elf {

//
// ELF Library version control struct
//

enum class VersionType {
    UNKNOWN_VERSION = 0,
    ELF_ABI_VERSION = 1,
    MAPPED_INFERENCE_VERSION = 2
};

class Version final {
public:
    constexpr Version(uint32_t v_major, uint32_t v_minor, uint32_t v_patch) : major{v_major}, minor{v_minor}, patch{v_patch}, isValid{true} {};
    explicit Version(const elf::elf_note::VersionNote& versionNote) : major{versionNote.n_desc[1]}, minor{versionNote.n_desc[2]}, patch{versionNote.n_desc[3]}, isValid{true} {};
    Version() = default;

    uint32_t getMajor() const;
    uint32_t getMinor() const;
    uint32_t getPatch() const;

    friend std::ostream& operator<< (std::ostream& stream, const Version& version) {
        stream << version.major << "." << version.minor << "." << version.patch;
        return stream;
    }

    // Comparison operators
    bool operator== (const Version& other) const;
    bool operator!= (const Version& other) const;
    bool operator< (const Version& other) const;
    bool operator> (const Version& other) const;
    bool operator<= (const Version& other) const;
    bool operator>= (const Version& other) const;

    /**
     * Helper static function to check the compatibility between different versions
     *
     * @note
     * Although it has no return, the function THROWS for incompatibilies and warns for unwanted differences.
     * Behaviour:
     *  - if major versions differ => incompatibility => VersioningError is thrown
     *  - if expected minor version < received minor version => incompatibility => VersioningError is thrown
     *  - if expected minor version > received minor version => compatible but not fully matching => logs warning
     *  - otherwise, versions match well
     *
     * @param expectedVersion the expected version in Version format: {v_major.v_minor.v_patch}
     *
     * @param receivedVersion the received version in Version format: {v_major.v_minor.v_patch}
     *
     * @return void
     */
    static void checkVersionCompatibility(const Version& expectedVersion, const Version& recievedVersion, const VersionType versionType = VersionType::UNKNOWN_VERSION);

    bool checkValidity() const;

private:
    uint32_t major = 0;
    uint32_t minor = 0;
    uint32_t patch = 0;

    bool isValid = false;
};

} // namespace elf
