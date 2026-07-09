//
// Copyright (C) 2026 Intel Corporation.
// SPDX-License-Identifier: Apache-2.0
//

#include <gtest/gtest.h>

#include "test_blob/binary_actions.hpp"
#include "test_blob/dummy_actions.hpp"
#include "test_blob/interfaces.hpp"
#include "test_blob/relocation_actions.hpp"
#include "test_blob/symbol_actions.hpp"
#include "test_blob/test_blob.hpp"

#include "vpux_elf/types/symbol_entry.hpp"
#include "vpux_elf/types/vpu_extensions.hpp"

struct TestBlobTestParams {
    std::string _name;
    ActionsSequence _actions;
};

TEST(TestBlob, BasicELFGeneration) {
    // Create a TestBlob instance
    TestBlob blob;

    // Generate the binary
    auto binary = blob.getBinary();

    // Optionally dump to file for inspection
    //     TestBlob::dumpToFile("output.elf", binary);

    // Perform assertions
    EXPECT_GT(binary.size(), 0);
}

TEST(TestBlob, BasicELFGenerationWithBinarySection) {
    // Create a TestBlob instance
    TestBlob blob;

    // Add a binary section
    blob.execute(AddRawBinarySection::build(
            "my_section",
            AddRawBinarySection::Attributes{{elf::SHF_ALLOC}, {elf::SHT_PROGBITS, {0x01, 0x02, 0x03, 0x04}}}));

    // Generate the binary
    auto binary = blob.getBinary();

    // Optionally dump to file for inspection
    TestBlob::dumpToFile("output.elf", binary);

    // Perform assertions
    EXPECT_GT(binary.size(), 0);
}

TEST(TestBlob, DummyActions) {
    auto sequence = ActionsSequence{{

            DummyNest::build(
                    "nestableNest_0",
                    ActionsSequence{{

                            DummyNest::build("nestableNest_1",
                                             ActionsSequence{{

                                                     DummyNest::build("nestableNest_2", ActionsSequence{}),
                                                     Dummy::build("dummy_0"), Dummy::build("dummy_1")

                                             }}),
                            // Show that without strict nestable type check, we can have heterogenous nested actions
                            Dummy::build("dummy_2"),

                    }}),
            DummyNest::build("nestableNest_3", ActionsSequence{})

    }};

    ASSERT_NO_THROW((TestBlob(sequence)));
}

TEST(TestBlob, NestedVsNonNestedEquivalence) {
    auto testBlob0 = TestBlob(

            ActionsSequence{{

                    AddDMASymbolSection::build(
                            ".symtab_0", AddDMASymbolSection::Attributes{{elf::VPU_SHF_USERINPUT | elf::VPU_SHF_JIT}},
                            ActionsSequence{{

                                    AddDMASymbol::build("symtab_0_sym0", AddDMASymbol::Attributes{},
                                                        AddDMASymbol::Operands{}),
                                    AddDMASymbol::build("symtab_0_sym1", AddDMASymbol::Attributes{},
                                                        AddDMASymbol::Operands{})

                            }})

            }});

    auto testBlob1 = TestBlob();
    testBlob1.execute(

            AddDMASymbolSection::build(".symtab_0",
                                       AddDMASymbolSection::Attributes{elf::VPU_SHF_USERINPUT | elf::VPU_SHF_JIT},
                                       ActionsSequence{})

    );
    testBlob1.execute(

            AddDMASymbol::build("symtab_0_sym0", AddDMASymbol::Attributes{}, AddDMASymbol::Operands{".symtab_0"})

    );
    testBlob1.execute(

            AddDMASymbol::build("symtab_0_sym1", AddDMASymbol::Attributes{}, AddDMASymbol::Operands{".symtab_0"})

    );

    ASSERT_EQ(testBlob0.getBinary(), testBlob1.getBinary());
}

class TestBlobThrow : public testing::TestWithParam<TestBlobTestParams> {};

TEST_P(TestBlobThrow, ) {
    auto params = GetParam();

    ASSERT_THROW(TestBlob(params._actions), std::exception);
}

auto testBlobThrowParams = testing::Values(
        TestBlobTestParams{

                "DuplicateActionName",
                {{

                        AddDummyBinarySection::build(
                                ".binSection_0",
                                AddDummyBinarySection::Attributes{{}, {{}, AddDummyBinarySection::Vector(4)}}),

                        AddRawBinarySection::build(
                                ".binSection_0",
                                AddRawBinarySection::Attributes{{}, {{}, AddRawBinarySection::Vector(4)}})

                }}},

        TestBlobTestParams{

                "SymbolReferencingUndefinedAction",
                {{

                        AddSymbolSection::build(
                                ".symtab_0", AddSymbolSection::Attributes{elf::VPU_SHF_USERINPUT},
                                ActionsSequence{{

                                        AddSymbol::build("symtab_0_sym0", AddSymbol::Attributes{elf::STT_SECTION},
                                                         AddSymbol::Operands{".binSection_0"})

                                }})

                }}},

        TestBlobTestParams{

                "ActionReferencedBeforeDefinition",
                {{

                        AddSymbolSection::build(
                                ".symtab_0", AddSymbolSection::Attributes{elf::VPU_SHF_USERINPUT},
                                ActionsSequence{{

                                        AddSymbol::build("symtab_0_sym0", AddSymbol::Attributes{elf::STT_SECTION},
                                                         AddSymbol::Operands{".binSection_0"})

                                }}),

                        AddDummyBinarySection::build(
                                ".binSection_0",
                                AddDummyBinarySection::Attributes{{}, {{}, AddDummyBinarySection::Vector(3)}})

                }}},

        TestBlobTestParams{

                "DMASymbolInStandardSymbolSection",
                {{

                        AddDummyBinarySection::build(
                                ".binSection_0",
                                AddDummyBinarySection::Attributes{{}, {{}, AddDummyBinarySection::Vector(3)}}),

                        AddSymbolSection::build(
                                ".symtab_0", AddSymbolSection::Attributes{elf::VPU_SHF_USERINPUT},
                                ActionsSequence{{

                                        AddSymbol::build("symtab_0_sym0", AddSymbol::Attributes{elf::STT_SECTION},
                                                         AddSymbol::Operands{".binSection_0"}),

                                        AddDMASymbol::build("symtab_0_sym0", AddDMASymbol::Attributes{},
                                                            AddDMASymbol::Operands{})

                                }})

                }}},

        TestBlobTestParams{

                "StandardSymbolInDMASymbolSection",
                {{

                        AddDummyBinarySection::build(
                                ".binSection_0",
                                AddDummyBinarySection::Attributes{{}, {{}, AddDummyBinarySection::Vector(3)}}),

                        AddDMASymbolSection::build(
                                ".symtab_0", AddDMASymbolSection::Attributes{elf::VPU_SHF_USERINPUT},
                                ActionsSequence{{

                                        AddDMASymbol::build("symtab_0_sym0", AddDMASymbol::Attributes{},
                                                            AddDMASymbol::Operands{}),

                                        AddSymbol::build("symtab_0_sym0", AddSymbol::Attributes{elf::STT_SECTION},
                                                         AddSymbol::Operands{".binSection_0"})

                                }})

                }}},

        TestBlobTestParams{

                "NonNestableActionInActionWithNest",
                {{

                        AddDummyBinarySection::build(
                                ".binSection_0",
                                AddDummyBinarySection::Attributes{{}, {{}, AddDummyBinarySection::Vector(3)}}),

                        AddDMASymbolSection::build(
                                ".symtab_0", AddDMASymbolSection::Attributes{elf::VPU_SHF_USERINPUT},
                                ActionsSequence{{

                                        AddDMASymbolSection::build(
                                                ".symtab_1", AddDMASymbolSection::Attributes{elf::VPU_SHF_USERINPUT},
                                                ActionsSequence{})

                                }})

                }}},

        TestBlobTestParams{

                "StandardRelocSectionUsingDMASymbolSection",
                {{

                        AddDummyBinarySection::build(
                                ".binSection_0",
                                AddDummyBinarySection::Attributes{{}, {{}, AddDummyBinarySection::Vector(4)}}),

                        AddDMASymbolSection::build(
                                ".symtab_0", AddDMASymbolSection::Attributes{elf::VPU_SHF_USERINPUT | elf::VPU_SHF_JIT},
                                ActionsSequence{}),

                        AddRelocationSection::build(".relocSection_0", AddRelocationSection::Attributes{},
                                                    AddRelocationSection::Operands{".symtab_0", ".binSection_0"},
                                                    ActionsSequence{})

                }}},

        TestBlobTestParams{

                "DMARelocSectionUsingStandardSymbolSection",
                {{

                        AddDummyBinarySection::build(
                                ".binSection_0",
                                AddDummyBinarySection::Attributes{{}, {{}, AddDummyBinarySection::Vector(4)}}),

                        AddSymbolSection::build(".symtab_0",
                                                AddSymbolSection::Attributes{elf::VPU_SHF_USERINPUT | elf::VPU_SHF_JIT},
                                                ActionsSequence{}),

                        AddDMARelocationSection::build(".relocSection_0", AddDMARelocationSection::Attributes{},
                                                       AddDMARelocationSection::Operands{".symtab_0", ".binSection_0"},
                                                       ActionsSequence{})

                }}},

        TestBlobTestParams{

                "RelocationUsingWrongSymbolTypeFromWrongSymbolSection",
                {{

                        AddDummyDMADescriptorBinarySection::build(
                                ".binSection_0",
                                AddDummyDMADescriptorBinarySection::Attributes{
                                        {}, {{}, AddDummyDMADescriptorBinarySection::Vector(22)}}),

                        AddSymbolSection::build(
                                ".symtab_0", AddSymbolSection::Attributes{elf::VPU_SHF_USERINPUT},
                                ActionsSequence{{

                                        AddSymbol::build("symtab_0_sym0", AddSymbol::Attributes{elf::STT_SECTION},
                                                         AddSymbol::Operands{".binSection_0"}),

                                        AddSymbol::build("symtab_0_sym1", AddSymbol::Attributes{elf::STT_SECTION},
                                                         AddSymbol::Operands{".binSection_0"}),

                                        AddSymbol::build("symtab_0_sym2", AddSymbol::Attributes{elf::STT_SECTION},
                                                         AddSymbol::Operands{".binSection_0"})

                                }}),

                        AddDMASymbolSection::build(
                                ".symtab_1", AddDMASymbolSection::Attributes{elf::VPU_SHF_USERINPUT},
                                ActionsSequence{{

                                        AddDMASymbol::build("symtab_1_sym0", AddDMASymbol::Attributes{},
                                                            AddDMASymbol::Operands{}),

                                        AddDMASymbol::build("symtab_1_sym1", AddDMASymbol::Attributes{},
                                                            AddDMASymbol::Operands{}),

                                        AddDMASymbol::build("symtab_1_sym2", AddDMASymbol::Attributes{},
                                                            AddDMASymbol::Operands{})}}),

                        AddRelocationSection::build(
                                ".relocSection_0", AddRelocationSection::Attributes{},
                                AddRelocationSection::Operands{".symtab_0", ".binSection_0"},
                                ActionsSequence{{

                                        AddRelocation::build("reloc0", AddRelocation::Attributes{elf::R_VPU_64, 0, 0},
                                                             AddRelocation::Operands{"symtab_0_sym0"}),

                                        /* symtab_1_sym0 belongs to a different symbol table section containing
                                           different symbol types*/
                                        AddRelocation::build("reloc1", AddRelocation::Attributes{elf::R_VPU_64, 0, 0},
                                                             AddRelocation::Operands{"symtab_1_sym0"})

                                }})

                }}},

        TestBlobTestParams{

                "RelocationUsingCorrectSymbolTypeFromWrongSymbolSection",
                {{

                        AddDummyDMADescriptorBinarySection::build(
                                ".binSection_0",
                                AddDummyDMADescriptorBinarySection::Attributes{
                                        {}, {{}, AddDummyDMADescriptorBinarySection::Vector(22)}}),

                        AddSymbolSection::build(
                                ".symtab_0", AddSymbolSection::Attributes{elf::VPU_SHF_USERINPUT},
                                ActionsSequence{{

                                        AddSymbol::build("symtab_0_sym0", AddSymbol::Attributes{elf::STT_SECTION},
                                                         AddSymbol::Operands{".binSection_0"}),

                                        AddSymbol::build("symtab_0_sym1", AddSymbol::Attributes{elf::STT_SECTION},
                                                         AddSymbol::Operands{".binSection_0"}),

                                        AddSymbol::build("symtab_0_sym2", AddSymbol::Attributes{elf::STT_SECTION},
                                                         AddSymbol::Operands{".binSection_0"})

                                }}),

                        AddSymbolSection::build(
                                ".symtab_1", AddSymbolSection::Attributes{elf::VPU_SHF_USERINPUT},
                                ActionsSequence{{

                                        AddSymbol::build("symtab_1_sym0", AddSymbol::Attributes{elf::STT_SECTION},
                                                         AddSymbol::Operands{".binSection_0"}),

                                        AddSymbol::build("symtab_1_sym1", AddSymbol::Attributes{elf::STT_SECTION},
                                                         AddSymbol::Operands{".binSection_0"}),

                                        AddSymbol::build("symtab_1_sym2", AddSymbol::Attributes{elf::STT_SECTION},
                                                         AddSymbol::Operands{".binSection_0"})

                                }}),

                        AddRelocationSection::build(
                                ".relocSection_0", AddRelocationSection::Attributes{},
                                AddRelocationSection::Operands{".symtab_0", ".binSection_0"},
                                ActionsSequence{{

                                        AddRelocation::build("reloc0", AddRelocation::Attributes{elf::R_VPU_64, 0, 0},
                                                             AddRelocation::Operands{"symtab_0_sym0"}),

                                        /* symtab_1_sym0 belongs to a different symbol table */
                                        AddRelocation::build("reloc1", AddRelocation::Attributes{elf::R_VPU_64, 0, 0},
                                                             AddRelocation::Operands{"symtab_1_sym0"})

                                }})

                }}}

);

INSTANTIATE_TEST_SUITE_P(TestBlobThrow, TestBlobThrow, testBlobThrowParams,
                         [](const testing::TestParamInfo<TestBlobTestParams>& info) {
                             return info.param._name;
                         });

class TestBlobNoThrow : public testing::TestWithParam<TestBlobTestParams> {};

TEST_P(TestBlobNoThrow, ) {
    auto params = GetParam();

    ASSERT_NO_THROW(TestBlob(params._actions));
}

auto testBlobNoThrowParams = testing::Values(
        TestBlobTestParams{

                "SimpleBinSection",
                {{

                        AddDummyBinarySection::build(
                                ".binSection_0",
                                AddDummyBinarySection::Attributes{{}, {{}, AddDummyBinarySection::Vector(4)}})

                }}},

        TestBlobTestParams{

                "SimpleEmptyBinSection",
                {{

                        AddDummyBinarySection::build(
                                ".binSection_0",
                                AddDummyBinarySection::Attributes{{}, {{}, AddDummyBinarySection::Vector()}})

                }}},

        TestBlobTestParams{

                "EmptyStandardSymSectionWithoutFlags",
                {{

                        AddSymbolSection::build(".symtab_0", AddSymbolSection::Attributes{}, ActionsSequence{})

                }}},

        TestBlobTestParams{

                "EmptyStandardSymSectionWithFlags",
                {{

                        AddSymbolSection::build(".symtab_0",
                                                AddSymbolSection::Attributes{elf::VPU_SHF_USERINPUT | elf::VPU_SHF_JIT},
                                                ActionsSequence{})

                }}},

        TestBlobTestParams{

                "EmptyDMASymSectionWithoutFlags",
                {{

                        AddDMASymbolSection::build(".symtab_0", AddDMASymbolSection::Attributes{}, ActionsSequence{})

                }}},

        TestBlobTestParams{

                "EmptyDMASymSectionWithFlags",
                {{

                        AddDMASymbolSection::build(
                                ".symtab_0", AddDMASymbolSection::Attributes{elf::VPU_SHF_USERINPUT | elf::VPU_SHF_JIT},
                                ActionsSequence{})

                }}},

        TestBlobTestParams{

                "MultipleEmtpySymSections",
                {{

                        AddSymbolSection::build(".symtab_1", AddSymbolSection::Attributes{elf::VPU_SHF_USERINPUT},
                                                ActionsSequence{}),

                        AddSymbolSection::build(".symtab_2", AddSymbolSection::Attributes{elf::VPU_SHF_USERINPUT},
                                                ActionsSequence{})

                }}},

        TestBlobTestParams{

                "StandardSymbolSectionWithStandardSymbolTargetingBinDataSectionDummyBinObject",
                {{

                        AddDummyBinarySection::build(
                                ".binSection_0",
                                AddDummyBinarySection::Attributes{{}, {{}, AddDummyBinarySection::Vector(3)}}),

                        AddSymbolSection::build(
                                ".symtab_0", AddSymbolSection::Attributes{elf::VPU_SHF_USERINPUT},
                                ActionsSequence{{

                                        AddSymbol::build("symtab_0_sym0", AddSymbol::Attributes{elf::STT_SECTION},
                                                         AddSymbol::Operands{".binSection_0"})

                                }})

                }}},

        TestBlobTestParams{

                "StandardSymbolSectionWithStandardSymbolTargetingBinDataSectionWithDummyDmaDescriptor",
                {{

                        AddDummyDMADescriptorBinarySection::build(
                                ".binSection_0",
                                AddDummyDMADescriptorBinarySection::Attributes{
                                        {}, {{}, AddDummyDMADescriptorBinarySection::Vector(4)}}),

                        AddSymbolSection::build(
                                ".symtab_0", AddSymbolSection::Attributes{elf::VPU_SHF_USERINPUT},
                                ActionsSequence{{

                                        AddSymbol::build("symtab_0_sym0", AddSymbol::Attributes{elf::STT_SECTION},
                                                         AddSymbol::Operands{".binSection_0"})

                                }})

                }}},

        TestBlobTestParams{

                "DMASymbolSectionWithDMASymbol",
                {{

                        AddDMASymbolSection::build(
                                ".symtab_0", AddDMASymbolSection::Attributes{elf::VPU_SHF_USERINPUT | elf::VPU_SHF_JIT},
                                ActionsSequence{{

                                        AddDMASymbol::build("symtab_0_sym0", AddDMASymbol::Attributes{},
                                                            AddDMASymbol::Operands{}),

                                        AddDMASymbol::build("symtab_0_sym1", AddDMASymbol::Attributes{},
                                                            AddDMASymbol::Operands{})

                                }})

                }}},

        TestBlobTestParams{

                "EmptyStandardRelocationSection",
                {{

                        AddDummyBinarySection::build(
                                ".binSection_0",
                                AddDummyBinarySection::Attributes{{}, {{}, AddDummyBinarySection::Vector(4)}}),

                        AddSymbolSection::build(".symtab_0",
                                                AddSymbolSection::Attributes{elf::VPU_SHF_USERINPUT | elf::VPU_SHF_JIT},
                                                ActionsSequence{}),

                        AddRelocationSection::build(".relocSection_0", AddRelocationSection::Attributes{},
                                                    AddRelocationSection::Operands{".symtab_0", ".binSection_0"},
                                                    ActionsSequence{})

                }}},

        TestBlobTestParams{

                "EmptyDMARelocationSection",
                {{

                        AddDummyBinarySection::build(
                                ".binSection_0",
                                AddDummyBinarySection::Attributes{{}, {{}, AddDummyBinarySection::Vector(4)}}),

                        AddDMASymbolSection::build(
                                ".symtab_0", AddDMASymbolSection::Attributes{elf::VPU_SHF_USERINPUT | elf::VPU_SHF_JIT},
                                ActionsSequence{}),

                        AddDMARelocationSection::build(".relocSection_0", AddDMARelocationSection::Attributes{},
                                                       AddDMARelocationSection::Operands{".symtab_0", ".binSection_0"},
                                                       ActionsSequence{}),

                }}},

        TestBlobTestParams{

                "StandardRelocationSectionWithStandardRelocUsingStandardSymbol",
                {{

                        AddDummyDMADescriptorBinarySection::build(
                                ".binSection_0",
                                AddDummyDMADescriptorBinarySection::Attributes{
                                        {}, {{}, AddDummyDMADescriptorBinarySection::Vector(22)}}),

                        AddSymbolSection::build(
                                ".symtab_0", AddSymbolSection::Attributes{elf::VPU_SHF_USERINPUT},
                                ActionsSequence{{

                                        AddSymbol::build("symtab_0_sym0", AddSymbol::Attributes{elf::STT_SECTION},
                                                         AddSymbol::Operands{".binSection_0"}),

                                        AddSymbol::build("symtab_0_sym1", AddSymbol::Attributes{elf::STT_SECTION},
                                                         AddSymbol::Operands{".binSection_0"}),

                                        AddSymbol::build("symtab_0_sym2", AddSymbol::Attributes{elf::STT_SECTION},
                                                         AddSymbol::Operands{".binSection_0"})

                                }}),

                        AddRelocationSection::build(
                                ".relocSection_0", AddRelocationSection::Attributes{},
                                AddRelocationSection::Operands{".symtab_0", ".binSection_0"},
                                ActionsSequence{{

                                        AddRelocation::build("reloc0", AddRelocation::Attributes{elf::R_VPU_64, 0, 0},
                                                             AddRelocation::Operands{"symtab_0_sym0"}),

                                        AddRelocation::build("reloc1", AddRelocation::Attributes{elf::R_VPU_64, 0, 0},
                                                             AddRelocation::Operands{"symtab_0_sym1"})

                                }})

                }}},

        TestBlobTestParams{

                "DMARelocationSectionWithDMARelocUsingDMASymbol",
                {{

                        AddDummyDMADescriptorBinarySection::build(
                                ".binSection_0",
                                AddDummyDMADescriptorBinarySection::Attributes{
                                        {}, {{}, AddDummyDMADescriptorBinarySection::Vector(22)}}),

                        AddDMASymbolSection::build(
                                ".symtab_0", AddDMASymbolSection::Attributes{elf::VPU_SHF_USERINPUT},
                                ActionsSequence{{

                                        AddDMASymbol::build("symtab_0_sym0", AddDMASymbol::Attributes{},
                                                            AddDMASymbol::Operands{}),

                                        AddDMASymbol::build("symtab_0_sym1", AddDMASymbol::Attributes{},
                                                            AddDMASymbol::Operands{}),

                                        AddDMASymbol::build("symtab_0_sym2", AddDMASymbol::Attributes{},
                                                            AddDMASymbol::Operands{})

                                }}),

                        AddDMARelocationSection::build(
                                ".relocSection_0", AddDMARelocationSection::Attributes{},
                                AddDMARelocationSection::Operands{".symtab_0", ".binSection_0"},
                                ActionsSequence{{

                                        AddDMARelocation::build("reloc0",
                                                                AddDMARelocation::Attributes{elf::R_VPU_64, 0, 0},
                                                                AddDMARelocation::Operands{"symtab_0_sym0"}),

                                        AddDMARelocation::build("reloc1",
                                                                AddDMARelocation::Attributes{elf::R_VPU_64, 0, 0},
                                                                AddDMARelocation::Operands{"symtab_0_sym1"})

                                }})

                }}}

);

INSTANTIATE_TEST_SUITE_P(TestBlobNoThrow, TestBlobNoThrow, testBlobNoThrowParams);
