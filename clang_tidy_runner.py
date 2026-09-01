#
# Copyright (C) 2026 Intel Corporation
# SPDX-License-Identifier: Apache-2.0
#

import subprocess
import sys
import os
import argparse


def run_clang_tidy(*, build_dir, parallel_instances, apply_fixes, version_suffix):
    """Run clang-tidy with specified configuration."""
    repo_dir = os.path.dirname(os.path.abspath(__file__))

    # clang-tidy configuration and analysis paths
    clang_tidy_config = os.path.join(repo_dir, ".clang-tidy")

    # clang-tidy binaries with version suffix
    run_clang_tidy_binary = f"run-clang-tidy{version_suffix}"
    clang_tidy_binary = f"clang-tidy{version_suffix}"
    clang_apply_replacements_binary = f"clang-apply-replacements{version_suffix}"

    # Collect files for analysis (C/C++ source and header files)
    files_for_analysis = []
    excluded_repo_dirs = {"3rdparty"}
    build_dir_abs = os.path.abspath(build_dir)
    for root, dirs, files in os.walk(repo_dir):
        # Exclude 3rdparty and build directories
        dirs[:] = [
            d
            for d in dirs
            if d not in excluded_repo_dirs
            and os.path.abspath(os.path.join(root, d)) != build_dir_abs
        ]
        for file in files:
            if file.endswith((".cpp", ".c", ".hpp", ".h")):
                files_for_analysis.append(os.path.join(root, file))

    # Determine whether to apply fixes (run-clang-tidy uses -fix)
    # Construct the command line
    cmd = [
        run_clang_tidy_binary,
        "-p",
        build_dir,
        "-config-file",
        clang_tidy_config,
        "-clang-tidy-binary",
        clang_tidy_binary,
        "-clang-apply-replacements-binary",
        clang_apply_replacements_binary,
    ]
    if apply_fixes:
        cmd.append("-fix")
    cmd += ["-j", str(parallel_instances)]
    cmd.extend(files_for_analysis)
    print(f"Running command: {' '.join(cmd)}")

    # Run the command
    try:
        result = subprocess.run(cmd)
        return result.returncode

    except Exception as e:
        print(f"Error running clang-tidy: {e}", file=sys.stderr)
        return 1


def parse_args():
    parser = argparse.ArgumentParser(
        description="Run clang-tidy with project configuration."
    )
    parser.add_argument(
        "--build-dir",
        required=True,
        help="Path to build directory used by clang-tidy",
    )
    parser.add_argument(
        "--parallel-instances",
        type=int,
        default=12,
        help="Number of parallel clang-tidy instances (default: 12)",
    )
    parser.add_argument(
        "--fix",
        action=argparse.BooleanOptionalAction,
        default=False,
        help="Apply fixes with clang-tidy (use --no-fix to disable)",
    )
    parser.add_argument(
        "--clang-tidy-version-suffix",
        default="-22",
        help="Version suffix for clang-tidy binaries (default: -22). Use empty string for unversioned binaries.",
    )
    return parser.parse_args()


if __name__ == "__main__":
    args = parse_args()
    sys.exit(
        run_clang_tidy(
            build_dir=args.build_dir,
            parallel_instances=args.parallel_instances,
            apply_fixes=args.fix,
            version_suffix=args.clang_tidy_version_suffix,
        )
    )
