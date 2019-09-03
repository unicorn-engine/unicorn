:: Unicorn Emulator Engine
:: Build Unicorn libs on Windows with CMake & Nmake
:: By Huitao Chen, 2019

@echo off

set flags="-DCMAKE_BUILD_TYPE=Release"

cmake %flags% -G "NMake Makefiles" ..
nmake
