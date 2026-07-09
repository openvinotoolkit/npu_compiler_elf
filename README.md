# ELF Library
## Components

The ELF Library has 3 main components:
### HPI (HostParsedInference)

- HPI is divided into a public component and a private one, and at the same time, in an arch-specific and arch-agnostic part. 
- It serves as the sole interface for the user of ELF library (drivers, test applications and etc.) and shall be used to orchestrate the ELF Loading process.

### Loader

- Loader is a class that contains most of the implementation details used by HPI to trigger loading process: read and interpreter sections, apply relocations and etc.

### Reader/Writer

- These represent classes designed for easing the ELF R/W and are capable to interpret NPU-specific extensions.

## **ELF Versioning System**

For details on the versioning system, please consult [VERSIONING.md](VERSIONING.md).

