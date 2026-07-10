# TestBlob framework

## Overview

TestBlob is a framework designed to greatly simplify creation of ELF binaries with the goal of facilitating creating tests for the ELF library components (Reader, the Loader and HostParsedInference) which operate during the loading phase of ELF binaries.

The main considerations of the framework are flexibility and extensibility. Its aim is to allow creating ELF binaries for a variety of test scenarios and test code interaction (e.g. how test configuration is stored, used for multiple tests etc.).

The framework makes use of the Writer component of the ELF library. While this may be considered a vulnerability for testing, it has the distinct advantage of avoiding dependencies on 3rd party code.

An ELF binary is generated with the help of a `TestBlob` object. The contents of the ELF binary are controlled through actions with unique names that the `TestBlob` executes before generating the ELF. These actions are instances of classes which implement the `IAction` interface.

Below is a simple example of a GTest test which makes use of TestBlob:

```cpp
#include <gtest/gtest.h>

#include "test_blob/test_blob.hpp"
#include "test_blob/binary_actions.hpp"

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
```


## Components
- **`Interfaces`**: define contracts between different components
- **`TestBlobCore`**: implements action registration, execution and result registration logic
- **`TestBlob`**: TestBlobCore API wrappers to be used by tests
- **`TestBlobHandle`**: TestBlobCore API wrappers to be used by actions
- **`Actions`**: handle configuration data and logic needed to build items for an ELF binary (e.g. a section)
- **`Actions base classes`**: provide implementation for common needs of actions, such as storing various data or offering printing support

### 1. **Interfaces**
We can separate the interfaces into required and optional.

#### **Required**:
Required interfaces must be implemented by certain components.

#### - **`IAction`**:
Required for all action types.

#### **Public API**
```cpp
virtual const std::string& getName() const = 0;
```

#### **Private API (with access for `TestBlobCore`)**
```cpp
virtual void execute(TestBlobHandle& handle) = 0;
virtual void finalize(TestBlobHandle&) = 0;
```

It defines the core contract between actions and TestBlob. Every currently defined action implements this interface and all future actions must implement it as well.
The `execute` and `finalize` methods are private as they are not intended to be called directly from test cases. These flows must go through `TestBlob` to ensure proper registration.
An action needs to implement `execute` and `finalize` as needed to perform the necessary ELF changes.

#### - **`IResult`**:
Required for all result types.

Although this interface is empty, it provides a common interface base class for all results. All current results inherit from it and all future results must do the same.

**It is crucial that all actions store results provided by the ELF writer only using result objects that are handed over to `TestBlobHandle`.** The main reason is that the ELF writer returns raw pointers to ELF objects, which means that storing them in action objects past the lifetime of the TestBlob will result in dangling pointers. By packaging all artifacts pertaining to the ELF writer in result objects and passing them back to TestBlob, it can be ensured that no dangling pointers remain after the destruction of the ELF writer.

**Do not store results in actions!**

Good:
```cpp
template <typename Traits>
class AddSymbolSectionAction ... {
...
public:
    virtual void execute(TestBlobHandle& handle) override {
        auto writer = handle.getWriter();

        auto symbolSection = Traits::buildSymbolSection(writer, getName());
        ...

        // Result is registered back to TestBlob and not stored inside the action object.
        // Actions which will be executed after the current action can reference this result
        // with the same name as the action that created it.
        handle.addResult(this, std::make_shared<typename Traits::ResultType>(symbolSection));

        this->executeNested(handle);
    }
};
```

Bad:
```cpp
template <typename Traits>
class AddSymbolSectionAction ... {
...
private:
    // Member capable of storing the result of the action.
    std::shared_ptr<typename Traits::ResultType> _result = {};

public:
    virtual void execute(TestBlobHandle& handle) override {
        auto writer = handle.getWriter();

        auto symbolSection = Traits::buildSymbolSection(writer, getName());
        ...

        // Result lifetime is now bound to the lifetime of the action.
        _result = std::make_shared<typename Traits::ResultType>(symbolSection);
        handle.addResult(this, _result);

        this->executeNested(handle);
    }

    // Providing access to the internally stored result could lead to dangling pointers usage
    auto getResult() {
        return _result;
    }
};
```
Paired with code like below can spell trouble:
```cpp
auto action = std::make_shared<AddSymbolSectionAction>(....);
{
    TestBlob blob;
    blob.execute(action);
}
// This will likely not end well.
// The result object still exists, because it is managed by a shared_ptr, but it's contents are not longer valid.
SomeFunction(action.get()->getResult());
```

#### **Optional**:
This will only cover the most important optional interfaces. The full interface specification can be found in `interfaces.hpp`.

#### - **`IPrintable`**:
#### **Public API**
```cpp
virtual void print(std::ostream* os, const std::string& indent = {}) const = 0;
```

This interface allows actions to be printed neatly in human readable format. Actions may or may not implement this interface.

#### - **`IActionWithNest`**:
#### **Public API**
```cpp
virtual const ActionsSequence& getActions() const = 0;
```

This interface allows retrieval of the actions that are nested in an action that implements this interface.

#### - **`IActionWithImplicitOperand<typename OperandType>`**:
#### **Public API**
```cpp
virtual void setImplicitOperand(OperandType operand) = 0;
```

This interface allows updating the name of an implicit operand of an action. This interface is used commonly by actions with a nest (i.e. that contain nested actions) to set their own result as an implicit operand for the nested actions.

#### - **`IBinarySectionResult<typename BinaryDataSectionType>`**:
#### **Public API**
```cpp
virtual BinaryDataSectionType* getBinarySection() = 0;
```

This interface allows retrieving a pointer to a binary section of type `BinaryDataSectionType`.


### 2. **TestBlobCore**
#### **Public API** (visible only to `TestBlob` and `TestBlobHandle`):
```cpp
TestBlobCore();
explicit TestBlobCore(const ActionsSequence& sequence);
void execute(std::shared_ptr<IAction> action);
void execute(const ActionsSequence& sequence);
std::vector<uint8_t> getBinary();
elf::Writer* getWriter();
std::shared_ptr<IAction> getAction(const std::string& name);
void addResult(const std::string& name, std::shared_ptr<IResult> result);
std::shared_ptr<IResult> getResult(const std::string& name);
static void dumpToFile(const std::string& fileName, const std::vector<uint8_t>& binary);
```
#### **Private API**:
```cpp
void insertAction(std::shared_ptr<IAction> action);
```

The main purposes of the class are:
 - To register actions uniquely based on their name and facilitate their execution. It allows each uniquely named action to be executed no more than once.
 - To provide storage for the results of actions. It allows each uniquely named action to register no more than one result.

The class executes actions in a 2 phase process. It does so via calls to IAction interface methods implemented by the actions.
 1. **Execute** phase - occurs when calling the `execute` methods of `TestBlobCore` or during construction of `TestBlobCore` with an `ActionsSequence` argument.

When an action is passed for execution, `TestBlobCore` will try to register the action by inserting a pointer to the action in a string map with the action name as the key (name string is fetched via `IAction` `getName`). If an action with the given name has already been registered, an exception is thrown, otherwise, the action `execute` method will be called.

Once execution has been transferred to the action `execute` method, the action can now perform its tasks for this phase (execute phase). Via the `TestBlobHandle`, the action can:
- retrieve a pointer to the ELF writer object managed by TestBlob and use it as needed
- retrieve the result of a previously executed action and use it as needed (for example, fetch a `SymbolSection` and start adding `Symbol` objects)
 
Before completing `execute` call, the action may or may not register a result through `addResult`.
 
When the action calls `addResult` via `TestBlobHandle`, `TestBlobCore` will try to register the result in a string map. For this, it will call `IAction` `getName` to retrieve a name string. Then it will search the results string map for a result with the given name. If a result with the given name already exists, an exception is thrown, otherwise, the pointer to the result is stored in the string map and it will become accessible for actions that will be executed later.

An action may contain nested actions, which it can forward to `TestBlobCore` for execution via the `TestBlobHandle` reference.

 2. **Finalize** phase - triggered by a call to the `getBinary` method of `TestBlobCore`.

In this phase, `TestBlobCore` will iterate through all registered actions and call their `finalize` method. This phase is currently useful only for actions which deal with ELF binary sections, when the contents of the sections need to be provided to the ELF Writer.


### 3. **TestBlob**
#### **Public API**:
```cpp
TestBlob();
explicit TestBlob(const ActionsSequence& sequence);

void execute(std::shared_ptr<IAction> action);
void execute(const ActionsSequence& sequence);
std::vector<uint8_t> getBinary();
std::shared_ptr<IAction> getAction(const std::string& name);
static void dumpToFile(const std::string& fileName, const std::vector<uint8_t>& binary);
```

The class only exposes a subset of the `TestBlobCore` APIs, namely those that are intended to be used by test cases code.

### 4. **TestBlobHandle**
#### **Public API**:
```cpp
void execute(std::shared_ptr<IAction> action);
void execute(const ActionsSequence& sequence);
elf::Writer* getWriter();
void addResult(const IAction* action, std::shared_ptr<IResult> result);
std::shared_ptr<IResult> getResult(const std::string& name);
```
#### **Private API (with access for `TestBlobCore`)**:
```cpp
explicit TestBlobHandle(TestBlobCore* core);
```

The class only exposes a subset of the `TestBlobCore` APIs, namely those that are intended to be used by actions. Certain `TestBlobCore` APIs are hidden to prevent abuse/accidental misuse from within actions. Such obvious abuse would be calling `getBinary` from an action before all actions in the test case have been executed.

### 5. **Actions**
An action is any class that implements the IAction interface and it is used to modify the contents of an ELF.

These are the actions currently defined:
- `AddBinarySectionAction<T>`
```cpp
using AddDummyBinarySection = AddBinarySectionAction<DummyBinObject>;
using AddDummyDMADescriptorBinarySection = AddBinarySectionAction<DummyDMADescriptor>;
using AddRawBinarySection = AddBinarySectionAction<uint8_t>;
```
- `AddEmptySectionAction`
```cpp
using AddEmptySection = AddEmptySectionAction;
```
- `AddSymbolAction<T>`
```cpp
using AddSymbol = AddSymbolAction<SymbolTraits>;
using AddDMASymbol = AddSymbolAction<DMASymbolTraits>;
```
- `AddSymbolSectionAction<T>`
```cpp
using AddSymbolSection = AddSymbolSectionAction<SymbolSectionTraits>;
using AddDMASymbolSection = AddSymbolSectionAction<DMASymbolSectionTraits>;
```
- `AddRelocationAction<T>`
```cpp
using AddRelocation = AddRelocationAction<RelocationTraits>;
using AddDMARelocation = AddRelocationAction<DMARelocationTraits>;
```
- `AddRelocationSectionAction<T>`
```cpp
using AddRelocationSection = AddRelocationSectionAction<RelocationSectionTraits>;
using AddDMARelocationSection = AddRelocationSectionAction<DMARelocationSectionTraits>;
```

What each action does is mostly self-explained by their name. This means that the user must have a basic understanding of the ELF format.

#### Design conventions
Actions work with a few concepts which help make their usage somewhat more standardized and intuitive. These concepts are not enforced by the TestBlob, rather they are adopted as conventions.

Each action may have, in this order, the following:

#### 1. `Attributes`

A single object which represents all the configuration data specific to the action itself (e.g. all configurable parameters of a standard ELF symbol).

```cpp
struct AddSymbolAttributes {
    elf::Elf_Word _type = {};
    elf::Elf_Word _binding = {};
    uint8_t _visibility = {};
    elf::Elf64_Addr _value = {};
    size_t _size = {};
...
}
```

#### 2. `Operands`

A single object that contains all the named and typed results of other actions that the action uses. Currently, all operands objects used by different actions contain one or more objects of `Operand<T>` type.

The result that an operand references must exist at the time when the action executes. It is not possible to reference the result of an action that has not yet been executed (doing so will result in a runtime exception).

```cpp
struct AddSymbolOperands {
    Operand<ISectionResult> _relatedSectionName;
    Operand<ISymbolSectionResult<elf::writer::SymbolSection>> _symbolSectionName;
...
}
```

#### 3. `Nested actions`

A single ActionsSequence object which contains actions nested within. This is useful in collaboration with the implicit operand concept when dealing with certain concepts in ELF, like sections and their contents, where the contents of the section tend to reference the section for configuration.

Usually, actions that add sections contain nested actions to allow populating the resulting section with items in a more easy to read way.

```cpp
AddDMASymbolSection::build(
        ".symtab_0", AddDMASymbolSection::Attributes{{elf::VPU_SHF_USERINPUT | elf::VPU_SHF_JIT}},
        // Nested actions:
        ActionsSequence{{
                // Note the default constructed operands of AddDMASymbol.
                // AddDMASymbol has 1 operand (the parent symbol section), which in this case is left unspecified and will be updated when ".symtab_0" AddDMASymbolSection executes.
                AddDMASymbol::build("symtab_0_sym0", AddDMASymbol::Attributes{},
                                    AddDMASymbol::Operands{}),
                AddDMASymbol::build("symtab_0_sym1", AddDMASymbol::Attributes{},
                                    AddDMASymbol::Operands{})
        }})
        //
```


### 6. **Actions base classes**

These are classes that facilitate implementing a new action by taking care of common needs of actions. They can be found in `actions_base.hpp`.

#### `Action`
```cpp
class Action : public IAction
```

Derives from the IAction interface and default implements the `finalize` method, which is only used by binary actions for now. It also stores the name of the action.

All currently defined actions derive from this class.

####  `ActionWithBuilder`
```cpp
template <typename ActionType, typename... Args>
class ActionWithBuilder
```

Provides to the deriving class a static `build` method which constructs the derived class action and returns a std::shared_ptr<IAction> to the newly constructed action. The template arguments types and order must match the constructor signature of the derived class.

####  `ActionWithNest`
```cpp
template <typename Impl, typename ExpectedNestedType = void, typename OperandType = void>
class ActionWithNest : public IActionWithNest
```

Provides:
 - storage for an `ActionsSequence` object
 - execution and printing support the actions stored in the `ActionsSequence` object

The class may be configured to strictly check nested action types via the `ExpectedNestedType` template parameters. Supplying `void` to it will disable the strict type check and will allow any action to be executed.

For example:
```cpp
class AddSymbolSectionAction :
        public Action,
        ...
        public ActionWithNest<AddSymbolSectionAction<Traits>, typename Traits::ExpectedNestedActionType,
                              Operand<typename Traits::ResultBaseType>>,
        ...
```

For `ExpectedNestedType = Traits::ExpectedNestedActionType = AddSymbol`, the following would be valid:
```cpp
AddSymbolSection::build(
    ".symtab_0", AddSymbolSection::Attributes{elf::VPU_SHF_USERINPUT},
    ActionsSequence{{
            // Only one nested action of type AddSymbol, just as expected
            AddSymbol::build("symtab_0_sym0", AddSymbol::Attributes{elf::STT_SECTION},
                            AddSymbol::Operands{".binSection_0", ".symtab_0"}),
    }})
```
However, the following would result in a runtime exception:
```cpp
AddSymbolSection::build(
    ".symtab_0", AddSymbolSection::Attributes{elf::VPU_SHF_USERINPUT},
    ActionsSequence{{
            // Trying to execute an AddDMASymbol action when AddSymbolSection expects only AddSymbol actions in its nest
            AddDMASymbol::build("symtab_0_sym0", AddDMASymbol::Attributes{},
                                AddDMASymbol::Operands{})
    }})
```

The class also supports, through the `OperandType` template parameter, setting its derived action's result to be used as an implicit operand for the nested actions. This is done via a dynamic_cast to `IActionWithImplicitOperand<OperandType>` on the nested actions. A successful cast means the given action accepts an implicit operand with type `OperandType`. Supplying void to `OperandType` disables the feature.

For the same example as above (AddSymbolSectionAction), for `OperandType = Operand<typename Traits::ResultBaseType> = ISymbolSectionResult<elf::writer::SymbolSection>`, the following would be valid:
```cpp
AddSymbolSection::build(
    ".symtab_0", AddSymbolSection::Attributes{elf::VPU_SHF_USERINPUT},
    ActionsSequence{{
            AddSymbol::build("symtab_0_sym0", AddSymbol::Attributes{elf::STT_SECTION},
                            // AddSymbol::Operands._symbolSection is unspecified.
                            // It will be set AddSymbolSection action after it finishes its execution and before executing AddSymbol.
                            // This is possible because AddSymbol implements IActionWithImplicitOperand<Operand<ISymbolSectionResult<elf::writer::SymbolSection>>>
                            AddSymbol::Operands{".binSection_0"}),
    }})
```
If we were to supply void for OperandType, no implicit operand setting would occur. This means that AddSymbolSection would execute without problems, but AddSymbol would throw an exception from its execute method because a result with name "" does not exist. In this case, in order for the composition to work, AddSymbol::Operands._symbolSection would need to be explicitly specified.
```cpp
AddSymbolSection::build(
    ".symtab_0", AddSymbolSection::Attributes{elf::VPU_SHF_USERINPUT},
    ActionsSequence{{
            AddSymbol::build("symtab_0_sym0", AddSymbol::Attributes{elf::STT_SECTION},
                            // AddSymbol::Operands._symbolSection explcitly specified as ".symtab_0".
                            AddSymbol::Operands{".binSection_0", ".symtab_0"}),
    }})
```


#### `ActionWithAttributes`
```cpp
template <typename AttrsType>
class ActionWithAttributes
```

Provides storage and access for the attributes object of the derived action.

#### `ActionWithOperands`
```cpp
template <typename OperandsType>
class ActionWithOperands
```

Provides storage and access for the operands object of the derived action.

#### `ActionWithOperandsWithImplicitOperand`
```cpp
template <typename OperandsType>
class ActionWithOperandsWithImplicitOperand :
        public ActionWithOperands<OperandsType>,
        public IActionWithImplicitOperand<typename OperandsType::ImplicitOperandType>
```

Derives from `ActionWithOperands` and adds handling for an implicit operand.

An implicit operand is an operand which can be left unspecified (with empty name) by the user when building an action. This unspecified operand will then be set at a later time by another action. The main use case for this feature is when nesting actions which are semantically related to their nest. For example, a relocation action will always have at least one operand which defines its parent relocation section. When creating a blob, it is visually helpful for the user to group all relocation actions in the nest of a single relocation section action.

Example:

```cpp
AddRelocationSection::build(
        ".relocSection_0", AddRelocationSection::Attributes{},
        AddRelocationSection::Operands{".symtab_0", ".binSection_0"},
        ActionsSequence{{
                AddRelocation::build("reloc0", AddRelocation::Attributes{elf::R_VPU_64, 0, 0},
                                     AddRelocation::Operands{"symtab_0_sym0"}),
                AddRelocation::build("reloc1", AddRelocation::Attributes{elf::R_VPU_64, 0, 0},
                                     AddRelocation::Operands{"symtab_0_sym1"})
        }})
```
with `AddRelocation::Operands` being:
```cpp
struct AddRelocationOperands {
    Operand<ISymbolResult<elf::writer::Symbol, elf::writer::SymbolSection>> _symbol = {};
    Operand<IRelocationSectionResult<elf::writer::RelocationSection, elf::writer::SymbolSection>> _relocationSection =
            {};

    using ImplicitOperandType = decltype(_relocationSection);
    ImplicitOperandType& getImplicitOperand() {
        return _relocationSection;
    }
...
}
```
Here, we nest 2 AddRelocation actions inside an AddRelocationSection action and we omit initializing the _relocationSection operand.
The above code is equivalent to:

```cpp
AddRelocationSection::build(".relocSection_0", AddRelocationSection::Attributes{},
                            AddRelocationSection::Operands{".symtab_0", ".binSection_0"},
                            ActionsSequence{{}}),
AddRelocation::build("reloc0", AddRelocation::Attributes{elf::R_VPU_64, 0, 0},
                     AddRelocation::Operands{"symtab_0_sym0", ".relocSection_0"}),
AddRelocation::build("reloc1", AddRelocation::Attributes{elf::R_VPU_64, 0, 0},
                     AddRelocation::Operands{"symtab_0_sym1", ".relocSection_0"})
```


#### `ActionWithPrinter`
```cpp
template <typename ActionType>
class ActionWithPrinter : public IPrintable
```
Provides formatted printing support for actions.

The current format is:

\[`ActionName`: `CXX type`\](`Attributes`)(`Operands`)  
{  
`Nested actions`  
}  

The class has a template parameter called `ActionType`
The class obtains the printing data from an `ActionType` object, w.

`ActionName`
- always printed
- fetched through `getName` method

`CXX type`
- always printed
- is obtained by demangling the CXX typeid of `ActionType`

`Attributes`
- optionally printed if `ActionType` has a public `getAttributes` method and the returned attributes object has a `getStringified` method

`Operands`
- optionally printed if `ActionType` has a public `getOperands` method and the returned operands object has a `getStringified` method

`Nested actions`
- optionally printed if `ActionType` has a public `printNested` method

#### `Results`
This is not a single class, but rather the collection of result classes currently defined. These classes implement the various result interfaces and store artifacts generated by the ELF Writer.

For example:
```cpp
template <typename BinaryDataSectionType>
class BinarySectionResult : public IBinarySectionResult<BinaryDataSectionType> {
public:
    explicit BinarySectionResult(BinaryDataSectionType* binarySection): _binarySection(binarySection) {
    }

    virtual elf::writer::Section* getSection() override final {
        return _binarySection;
    }
    virtual BinaryDataSectionType* getBinarySection() override final {
        return _binarySection;
    }

protected:
    BinaryDataSectionType* _binarySection = {};
};
```


## Writing tests

Keep in mind the following when implementing tests:
 - Make them easy to understand. A developer should be able to quickly determine from the test name and test body what the test is actually checking.
 - Keep them simple, checking only a few things per test. Tests that make too many assertions (e.g. > 5) quickly become difficult to debug when they fail. A developer seeing a failing tests in precommit should be able to figure out reasonably fast what the root cause may be.
 - Reuse as much as possible common action sequence patterns (e.g. a binary section + symbol section + symbols pointing to binary section) and combine actions sequence patterns between them to create more elaborate patterns.
 - Do not call `TestBlob` `getBinary` more than once, as this is not supported by the ELF Writer and code safeguard against such misuse is not currently implemented.
 - Remember to keep action names unique and descriptive. The action names will be used also in the actual ELF binary for those ELF components that support having an associated name (e.g. the name of a section). Support for alternative naming does not exist at the moment, but could be added reasonably easy. When possible, to avoid having to pass string literals around and make a mistake, use the `getName()` of a given action when passing it as operand to other actions.
 - When adding a test, make sure to validate it properly (with a debugger or test prints) to ensure it actually triggers the expected behavior. The higher the order of the component that the test targets (i.e. how many other sub-components the component uses), the more complex the execution path and failure pattern becomes. Just because a call to Loader constructor throws, doesn't mean it throws what you expect or from where you expect. This opens the discussion for more detailed exceptions from the ELF library code, possibly embedding the exception type also the function name and line number from where the exception was thrown.
 - All action attributes and operands are currently aggregate types, which allows flexible initialization of the members without writing much code. Pay attention when initializing them from test cases to ensure all members of interest have the desired values. This aspect may benefit from designated initializers when moving to C++20. Alternatively, a builder pattern may be used to avoid ambiguity at the cost of extra code. 


## Contributing

The framework was designed with extensibility in mind. Because TestBlob operates through interfaces, the actions collection can be extended without limits.

The current actions collection is large enough to generate a very large number of test scenarios, some more relevant than others. Thus, before thinking of adding a new action, think whether it is possible to achieve your test goal with the current actions or with modifications to current actions that do not negatively impact existing tests.

When adding a new action, the following should be done (AddSymbolAction used for examples):
1. determine if your action needs attributes (configuration data) and operands
2. if your action needs attributes, add your attributes type
```cpp
struct AddSymbolAttributes {
    elf::Elf_Word _type = {};
    elf::Elf_Word _binding = {};
    uint8_t _visibility = {};
    elf::Elf64_Addr _value = {};
    size_t _size = {};

    std::string getStringified() const {
        std::stringstream stream;
        stream << "type = " << _type << ", binding = " << _binding
               << ", visibility = " << static_cast<uint32_t>(_visibility) << ", value = " << _value
               << ", size = " << _size;
        return stream.str();
    }
};
```
When defining the members of your attributes type, think about reusing previously defined types that could be reused (see `CommonSectionAttributes`). Also remember to implement the `getStringified` method for printing support.

3. If your action needs operands, add your operands type
```cpp
struct AddSymbolOperands {
    Operand<ISectionResult> _relatedSection;
    Operand<ISymbolSectionResult<elf::writer::SymbolSection>> _symbolSection;

    using ImplicitOperandType = decltype(_symbolSection);
    ImplicitOperandType& getImplicitOperand() {
        return _symbolSection;
    }

    std::string getStringified() const {
        std::stringstream stream;
        stream << "relatedSection = " << _relatedSection._name << ", symbolSection = " << _symbolSection._name;
        return stream.str();
    }
};
```
Use the `Operand` type to enable easier access to the underlying result. If you intend for your operands type to work with `ActionWithOperandsWithImplicitOperand`, you need to define `ImplicitOperandType` and implement `getImplicitOperand`. As for attributes, remember to also implement the `getStringified` method for printing support.

4. Add your action implementation
```cpp
template <typename Traits>
class AddSymbolAction :
        public Action,
        public ActionWithAttributes<typename Traits::AttributesType>,
        public ActionWithOperandsWithImplicitOperand<typename Traits::OperandsType>,
        public ActionWithBuilder<AddSymbolAction<Traits>, typename Traits::AttributesType,
                                 typename Traits::OperandsType>,
        public ActionWithPrinter<AddSymbolAction<Traits>> {
public:
    AddSymbolAction(std::string name, typename Traits::AttributesType attrs, typename Traits::OperandsType operands)
            : Action(std::move(name)),
              ActionWithAttributes<typename Traits::AttributesType>(std::move(attrs)),
              ActionWithOperandsWithImplicitOperand<typename Traits::OperandsType>(std::move(operands)) {
    }

private:
    virtual void execute(TestBlobHandle& handle) override {
        auto symSectionResult = this->getOperands()._symbolSection.get(handle);

        auto symbolSection = symSectionResult->getSymbolSection();
        auto symbol = Traits::buildSymbol(handle, getName(), symbolSection, this->getAttributes(), this->getOperands());

        handle.addResult(this, std::make_shared<typename Traits::ResultType>(symbol, symbolSection));
    }
};
```
Try to leverage as much as possible the existing base classes in order to minimize implementation effort and code duplication. Mark the `IAction` methods (like `execute`) as private. Those methods are not meant to be called and can't be called by test cases, so it makes no sense for them to be visible.
