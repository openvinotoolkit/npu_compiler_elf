//
// Copyright (C) 2026 Intel Corporation.
// SPDX-License-Identifier: Apache-2.0
//

#include <chrono>
#include <ctime>
#include <iostream>
#include <string>

#include <vpux_hpi.hpp>
#include "gflags/gflags.h"
#include "npu_loader_version.hpp"

#include "allocator_utils/blob_scanner.hpp"
#include "allocator_utils/hpi_runner.hpp"
#include "allocator_utils/io_container.hpp"

using namespace elf;
using namespace std;
using namespace chrono;

namespace {

DEFINE_string(access, "DDR", "AccessManager type\nOptions:\n\tDDR - DDRAccessManager\n\tFS - FSAccessManager");
DEFINE_string(arch, "NPU3720", "Arch name as defined by ELF library");
DEFINE_string(mode, "simple_load",
              "Run mode\nOptions:\n\tsimple_load - Run a simple load of a single HostParsedInference and get memory "
              "consumption projection and actual memory consumption\n\tsimple_clone - Run a clone after deleting "
              "access to the blob");
DEFINE_bool(v, false, "Enable verbose output");

enum class RunMode {
    SimpleLoad = 0,
    SimpleClone,
};

RunMode StringToRunMode(const std::string& value) {
    const std::unordered_map<std::string, RunMode> mapStringToRunMode = {{"simple_load", RunMode::SimpleLoad},
                                                                         {"simple_clone", RunMode::SimpleClone}};
    auto it = mapStringToRunMode.find(value);
    if (it == mapStringToRunMode.end()) {
        throw std::invalid_argument("Invalid " + std::string(__func__) + " value: " + value);
    }
    return it->second;
}

AccessManagerType StringToAccessType(const std::string& value) {
    const std::unordered_map<std::string, AccessManagerType> mapStringToAccessType = {
            {"DDR", AccessManagerType::DDRAccessManager},
            {"FS", AccessManagerType::FSAccessManager}};
    auto it = mapStringToAccessType.find(value);
    if (it == mapStringToAccessType.end()) {
        throw std::invalid_argument("Invalid " + std::string(__func__) + " value: " + value);
    }
    return it->second;
}

bool ValidateMode(const char* flagname, const std::string& value) {
    try {
        StringToRunMode(value);
    } catch (const std::invalid_argument& e) {
        std::cerr << "Invalid --" << flagname << ": " << value << ". Valid: simple_load, simple_clone\n";
        return false;
    }
    return true;
}
bool ValidateAccess(const char* flagname, const std::string& value) {
    try {
        StringToAccessType(value);
    } catch (const std::invalid_argument& e) {
        std::cerr << "Invalid --" << flagname << ": " << value << ". Valid: DDR, FS\n";
        return false;
    }
    return true;
}
DEFINE_validator(mode, &ValidateMode);
DEFINE_validator(access, &ValidateAccess);
}  // namespace

template <typename HPIRunnerDerived>
void run(HPIRunner<HPIRunnerDerived>&& runner) {
    runner.run();
}

static std::string appArgBlobPathAndName = "model.blob";
static AccessManagerType appArgAccessManagerType;
std::string appArgArchName;

struct SimpleLoadRunner : public HPIRunner<SimpleLoadRunner> {
    SimpleLoadRunner(): HPIRunner(appArgArchName, appArgBlobPathAndName, appArgAccessManagerType) {
    }

    void runImpl() {
        // Get a memory consumption projection from the blob
        BlobScanner blobScanner(_accessManager.get(), getDefaultProcessorMap());
        blobScanner.printResult();

        std::cout << std::endl;
        std::cout << "Loading HPI..." << std::endl;

        auto start = high_resolution_clock::now();

        HostParsedInference hpi(_hpiBufferManager.get(), _accessManager.get(), _hpiConfig);
        hpi.load();

        auto end = high_resolution_clock::now();
        std::cout << "HPI loaded in " << duration_cast<milliseconds>(end - start).count() << " ms\n" << std::endl;

        IOBuffersContainer ioContainer(_ioBufferManager, hpi.getInputBuffers(), hpi.getOutputBuffers(),
                                       hpi.getProfBuffers());

        hpi.applyInputOutput(ioContainer.getInputBuffers(), ioContainer.getOutputBuffers(),
                             ioContainer.getProfilingBuffers());

        std::cout << "Projected NPU memory for HPI: "
                  << (blobScanner.getRequirementsByAllocationType().getTotalRequired() + hpi.getHPISize()) << " bytes"
                  << std::endl;
        std::cout << "Total NPU buffers tracked by HPI object: " << hpi.getAllocatedBuffers().size() << "\n"
                  << std::endl;

        _hpiBufferManager->printAllocationStats();
    }
};

class SimpleCloneRunner : public HPIRunner<SimpleCloneRunner> {
public:
    SimpleCloneRunner(): HPIRunner(appArgArchName, appArgBlobPathAndName, appArgAccessManagerType) {
    }

    void runImpl() {
        std::cout << "Loading first HPI..." << std::endl;
        HostParsedInference hpi(_hpiBufferManager.get(), _accessManager.get(), _hpiConfig);
        hpi.load();
        std::cout << "First HPI loaded\n" << std::endl;

        // Delete AccessManager
        _accessManager = nullptr;

        // IO bindings must be possible after blob release
        IOBuffersContainer ioContainer(_ioBufferManager, hpi.getInputBuffers(), hpi.getOutputBuffers(),
                                       hpi.getProfBuffers());
        hpi.applyInputOutput(ioContainer.getInputBuffers(), ioContainer.getOutputBuffers(),
                             ioContainer.getProfilingBuffers());

        _hpiBufferManager->printAllocationStats();
        std::cout << "Loading second HPI..." << std::endl;

        // Cloning must still work after AccessManager was deleted
        HostParsedInference hpiClone(hpi);

        std::cout << "Second HPI loaded\n" << std::endl;

        _hpiBufferManager->printAllocationStats();
        hpiClone.getMetadata();
    }
};

void CustomHelp(std::string programName = "npu-loader") {
    std::cout << R"(USAGE: )" << programName << R"( [options] <Input blob full path + name>

OPTIONS:

  --access=<value> - AccessManager type
    =DDR           -   DDRAccessManager
    =FS            -   FSAccessManager
  --arch=<string>  - Arch name as defined by ELF library (default: NPU3720)
  --mode=<value>   - Run mode
    =simple_load   -   Run a simple load of a single HostParsedInference and get memory consumption projection and actual memory consumption
    =simple_clone  -   Run a clone after deleting access to the blob
  -v               - Enable/Disable verbosity

Generic Options:

  --help           - Display available options (--help-hidden for more)
  --version        - Display the version of this program)"
              << std::endl;
}
int main(int argc, char* argv[]) {
    // Gflags generated help message is not user friendly, so we provide our own and exit before gflags can print its
    // own message
    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];
        if (arg == "--help" || arg == "-h" || arg == "-help") {
            CustomHelp(argv[0]);
            return 0;  // Exit early so gflags never prints its list
        }
    }
    gflags::SetUsageMessage("USAGE: npu-loader [options] <Input blob full path + name>");
    gflags::SetVersionString(npu_loader_version);

    gflags::ParseCommandLineFlags(&argc, &argv, /*remove_flags=*/true);
    if (FLAGS_v) {
        Logger::setGlobalLevel(LogLevel::LOG_DEBUG);
    }

    if (argc < 2) {
        std::cerr << "Error: Missing required positional argument <Input blob full path + name>\n";
        std::cerr << "Usage: " << argv[0] << " [options] <Input blob full path + name>\n";
        return 1;
    }

    appArgBlobPathAndName = argv[1];

    appArgAccessManagerType = StringToAccessType(FLAGS_access);
    appArgArchName = std::string(FLAGS_arch);

    RunMode appArgRunMode = StringToRunMode(FLAGS_mode);
    switch (appArgRunMode) {
    case RunMode::SimpleLoad: {
        run(SimpleLoadRunner());
        break;
    }
    case RunMode::SimpleClone: {
        run(SimpleCloneRunner());
        break;
    }
    default: {
        // Default should be unreachable since LLVM CL should sanitize the arg
        throw(std::runtime_error("Unknown test type"));
    }
    }

    gflags::ShutDownCommandLineFlags();
    return 0;
}
