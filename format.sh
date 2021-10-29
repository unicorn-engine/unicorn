#!/bin/bash

find . -maxdepth 1 "(" -name "*.c" -or -name "*.h" ")" -exec clang-format -i -style=file "{}" ";"
find ./msvc -maxdepth 1 "(" -name "*.c" -or -name "*.h" ")" -exec clang-format -i -style=file "{}" ";"
find ./include -maxdepth 2 "(" -name "*.c" -or -name "*.h" ")" -exec clang-format -i -style=file "{}" ";"
find ./tests/unit -maxdepth 1 "(" -name "*.c" -or -name "*.h" ")" -exec clang-format -i -style=file "{}" ";"
find ./samples -maxdepth 1 "(" -name "*.c" -or -name "*.h" ")" -exec clang-format -i -style=file "{}" ";"
find ./qemu "(" -name "unicorn.c" -or -name "unicorn.h" ")" -exec clang-format -i -style=file "{}" ";"
