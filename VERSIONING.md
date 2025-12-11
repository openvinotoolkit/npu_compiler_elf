
# **ELF Versioning System**

## **Implementation**:

The versioning system is composed of the following three components:

- **Version Major** - Functional change that breaks backward compatibility.

- **Version Minor** - Functional change that does not break backward compatibility.

- **Version Patch** - Changes that don't affect compatibility in any way.

Due to the "double" implementation for HPI, with different versions for NPU3720 and NPU4000+, there are 2 versioning systems that track them independently.

## **Version checks**

A given blob with ELF version bMajor.bMinor.bPatch is compatible with ELF library version eMajor.eMinor.ePatch if and only if:

- **bMajor == eMajor**
- **bMinor <= eMinor**

## **Version Update Guidelines**

Accompanying any ELF Library change, the Version must be incremented according to the description above.

### Version Major Update conditions
- Major version increase will reset minor and patch to 0.
- Update of the serialization expectations
    - Examples:
        - Loader has a new hard requirement on the existance of a specific section
        - Updated section content expectations: checks on newly added fields in dynamic structures, modifications of the static structures, etc.

### Version Minor Update conditions
- Minor version increse will reset patch version to 0.
- New NPU-specific extensions that are not a loading requirement
    - e.g. New relocation types, new section types/flags

### Version Patch Update conditions
- Any modifications to the ELF Library that don't fall in the above categories and do not affect compatibility in any way

In addition, the changes might fall in one of the following 3 cathegories:

- changes affecting NPU3720 only -> only HPI3720 version needs updating
- changes affecting NPU4000+ only -> only HPI4000 version needs updating
- changes affecting all architecutres -> both HPI3720 & HPI4000 versions need to be updated

More precisely, the versions that need to be updated are located in the following headers:

- **HPI3720** - [vpux_elf/hpi_component/include/3720/hpi_3720.hpp](vpux_elf/hpi_component/include/3720/hpi_3720.hpp)
- **HPI4000+** - [vpux_elf/hpi_component/include/3720/hpi_3720.hpp](vpux_elf/hpi_component/include/4000/hpi_4000.hpp)
