# Copyright (C) 2023-2025 Intel Corporation
# SPDX-License-Identifier: Apache-2.0
from os import listdir
from os.path import isfile, join, abspath, dirname, realpath

if __name__ == "__main__":
    dir_path = dirname(realpath(__file__))
    lib_path = join(dir_path,"MVCNN")
    srcs = listdir(lib_path)
    import_lines = []
    for f in srcs:
        if "__" not in f:   # Don't want private files
            inc = "import MVCNN."+f[0:f.rindex(".py")] + "\n"
            import_lines.append(inc)

    f = open(lib_path+"/__init__.py", "w")
    for i in import_lines:
        f.write(i)
    f.close()
