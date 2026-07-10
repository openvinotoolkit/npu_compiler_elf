
//
// Copyright (C) 2026 Intel Corporation.
// SPDX-License-Identifier: Apache-2.0
//

#pragma once

#include <sstream>
#include <string>

#include "test_blob/actions_base.hpp"
#include "test_blob/interfaces.hpp"
#include "test_blob/test_blob.hpp"

#include "utils/printing.hpp"
#include "vpux_elf/types/data_types.hpp"
#include "vpux_elf/types/section_header.hpp"
#include "vpux_elf/writer/binary_data_section.hpp"

struct DummyBinObject {
    uint64_t a = 0xAABBCCDDEEFF9900;
    uint64_t b = 0x1122334455667788;
};

struct DummyDMADescriptor {
    uint64_t field_0 = 0x3355AACCDDEE2244;
    uint64_t field_1 = 0x2146574581124656;
};

template <typename T>
struct BinarySectionAttributes {
    elf::Elf_Word _type = {};
    std::vector<T> _data = {};

    std::string getStringified() const {
        std::stringstream stream;
        stream << "type = " << _type << ", dtype = " << Printing::demangle(typeid(T).name())
               << ", elem_count = " << _data.size();
        return stream.str();
    }
};

template <typename SectionDataType>
struct AddBinarySectionAttributes {
    CommonSectionAttributes _commonSectionAttrs = {};
    BinarySectionAttributes<SectionDataType> _binarySectionAttributes{};

    std::string getStringified() const {
        std::stringstream stream;
        stream << _commonSectionAttrs.getStringified() << ", " << _binarySectionAttributes.getStringified();
        return stream.str();
    }
};

template <typename T>
class AddBinarySectionAction final :
        public Action,
        public ActionWithAttributes<AddBinarySectionAttributes<T>>,
        public ActionWithBuilder<AddBinarySectionAction<T>, AddBinarySectionAttributes<T>>,
        public ActionWithPrinter<AddBinarySectionAction<T>> {
public:
    using Vector = std::vector<T>;

    AddBinarySectionAction(std::string name, AddBinarySectionAttributes<T> attrs)
            : Action(std::move(name)), ActionWithAttributes<AddBinarySectionAttributes<T>>(std::move(attrs)) {
    }

private:
    virtual void execute(TestBlobHandle& handle) override {
        auto writer = handle.getWriter();

        auto binarySection =
                writer->addBinaryDataSection<T>(getName(), this->getAttributes()._binarySectionAttributes._type);
        binarySection->setSize(this->getAttributes()._binarySectionAttributes._data.size() * sizeof(T));
        binarySection->setFlags(this->getAttributes()._commonSectionAttrs._flags);
        binarySection->setAddrAlign(this->getAttributes()._commonSectionAttrs._alignment);

        handle.addResult(this, std::make_shared<BinarySectionResult<elf::writer::BinaryDataSection<T>>>(binarySection));
    }
    virtual void finalize(TestBlobHandle& handle) override {
        auto binarySection = dyn_cast_or_throw<BinarySectionResult<elf::writer::BinaryDataSection<T>>*>(
                                     handle.getResult(getName()).get())
                                     ->getBinarySection();

        binarySection->appendData(this->getAttributes()._binarySectionAttributes._data.data(),
                                  this->getAttributes()._binarySectionAttributes._data.size());
    }
};

using AddDummyBinarySection = AddBinarySectionAction<DummyBinObject>;
using AddDummyDMADescriptorBinarySection = AddBinarySectionAction<DummyDMADescriptor>;
using AddRawBinarySection = AddBinarySectionAction<uint8_t>;

struct EmptySectionAttributes {
    elf::Elf_Xword _size = {};

    std::string getStringified() const {
        std::stringstream stream;
        stream << "size = " << _size;
        return stream.str();
    }
};

struct AddEmptySectionAttributes {
    CommonSectionAttributes _commonSectionAttrs = {};
    EmptySectionAttributes _emptySectionAttrs = {};

    std::string getStringified() const {
        std::stringstream stream;
        stream << _commonSectionAttrs.getStringified() << ", " << _emptySectionAttrs.getStringified();
        return stream.str();
    }
};

class AddEmptySectionAction :
        public Action,
        public ActionWithAttributes<AddEmptySectionAttributes>,
        public ActionWithBuilder<AddEmptySectionAction, AddEmptySectionAttributes>,
        public ActionWithPrinter<AddEmptySectionAction> {
public:
    AddEmptySectionAction(std::string name, AddEmptySectionAttributes attrs)
            : Action(std::move(name)), ActionWithAttributes<AddEmptySectionAttributes>(std::move(attrs)) {
    }

private:
    virtual void execute(TestBlobHandle& handle) override {
        auto writer = handle.getWriter();

        auto section = writer->addEmptySection(getName());
        section->setType(elf::SHT_NOBITS);
        section->setSize(this->getAttributes()._emptySectionAttrs._size);
        section->setFlags(this->getAttributes()._commonSectionAttrs._flags);
        section->setAddrAlign(this->getAttributes()._commonSectionAttrs._alignment);

        handle.addResult(this, std::make_shared<BinarySectionResult<elf::writer::EmptySection>>(section));
    }
};

using AddEmptySection = AddEmptySectionAction;
