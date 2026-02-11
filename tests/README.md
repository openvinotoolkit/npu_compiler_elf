# ELF Library Testing

ELF library tests rely on Google Tests infrastructure.

## Building library with tests enabled

Build with command on the root directory:
    ```
       cmake -DENABLE_ELF_TESTS=ON -S . -B build
    ```
It will create a new directory named `build`.

[-S](https://cmake.org/cmake/help/latest/manual/ccmake.1.html#cmdoption-ccmake-S)
</br>
[-B](https://cmake.org/cmake/help/latest/manual/ccmake.1.html#cmdoption-ccmake-B)

## Running tests

Testing infrastructure enables `ctest`.

All tests can run as:
    ```
        cd build && ctest
    ```

To filter tests use [-R](https://cmake.org/cmake/help/latest/manual/ctest.1.html#cmdoption-ctest-R) flag on ctest:
    ```
        cd build && ctest -R TestExample
    ```

To run a single suite of tests:
    ```
        cd build/tests/example && ./test_gtest
    ```

To speed up tests, [-j/--parallel n_cores](https://cmake.org/cmake/help/latest/manual/ctest.1.html#cmdoption-ctest-j) can be used.

## Adding a new test

To add a new test please see [example](./example). Mainly each test has to have a [CMakeLists.txt](./example/CMakeLists.txt) and a source file (e.g [test_gtest.cpp](./example/test_gtest.cpp)).
