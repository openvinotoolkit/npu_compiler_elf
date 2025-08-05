//
// Copyright (C) 2023-2025 Intel Corporation
// SPDX-License-Identifier: Apache-2.0
//

//

#include <vpux_elf/accessor.hpp>
#include <vpux_elf/reader.hpp>

#include <vpux_elf/types/symbol_entry.hpp>

#include <fstream>
#include <iostream>
#include <vector>

int main(int argc, char* argv[]) {
    if (argc != 2) {
        std::cout << "Example usage is ./simplereader <path-to-elf>" << '\n';
        return 1;
    }

    std::ifstream stream(argv[1], std::ios::binary);
    std::vector<uint8_t> elfBlob((std::istreambuf_iterator<char>(stream)), (std::istreambuf_iterator<char>()));
    stream.close();

    elf::DDRAccessManager<elf::DDRAlwaysEmplace> elfAccess(elfBlob.data(), elfBlob.size());

    elf::Reader<elf::ELF_Bitness::Elf64> reader(&elfAccess);

    std::cout << "Number of sections: " << reader.getSectionsNum() << '\n';
    std::cout << "Number of segments: " << reader.getSegmentsNum() << '\n';

    for (size_t i = 0; i < reader.getSectionsNum(); ++i) {
        auto section = reader.getSection(i);
        const auto sectionHeader = section.getHeader();

        if (sectionHeader->sh_type == elf::SHT_SYMTAB) {
            const auto entriesNum = section.getEntriesNum();
            std::cout << "Found a symbol table " << section.getName() << " with " << entriesNum << " entries" << '\n';

            const auto symbols = section.getData<elf::SymbolEntry>();
            for (size_t j = 0; j < entriesNum; ++j) {
                const auto symbol = symbols[j];
                std::cout << j << ") Symbol's value: " << symbol.st_value << '\n';
            }
        }
    }

    return 0;
}
