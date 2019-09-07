:: Unicorn Emulator Engine
:: Build Unicorn libs on Windows with CMake & Nmake
:: Usage: nmake.bat [x86 arm aarch64 m68k mips sparc], default build all.
:: By Huitao Chen, 2019

@echo off

set flags="-DCMAKE_BUILD_TYPE=Release"

set allparams=

:loop
set str=%1
if "%str%"=="" (
    goto end
)
set allparams=%allparams% %str%
shift /0
goto loop

:end
if "%allparams%"=="" (
    goto eof
)
:: remove left, right blank
:intercept_left
if "%allparams:~0,1%"==" " set "allparams=%allparams:~1%" & goto intercept_left

:intercept_right
if "%allparams:~-1%"==" " set "allparams=%allparams:~0,-1%" & goto intercept_right

:eof

if "%allparams%"=="" (
cmake "%flags%" -G "NMake Makefiles" ..
) else (
cmake "%flags%" "-DUNICORN_ARCH=%allparams%" -G "NMake Makefiles" ..
)

nmake
