@echo off
setlocal ENABLEDELAYEDEXPANSION

if not "%1"=="x86" if not "%1"=="x64" (
    echo Usage: windows_export.bat (x86 ^| x64^)
    exit /b 1
)

:: This script invokes the Visual Studio linker to construct a static library file that can be used outside of Mingw.
:: The unicorn.def file that it references below is produced by the Mingw compiler via a linker flag.
:: The arch (x86 or x64) we are working on should be passed via the first argument to this script.

:: Look up the Visual Studio install path via the registry
:: http://stackoverflow.com/questions/445167/how-can-i-get-the-value-of-a-registry-key-from-within-a-batch-script
:: There's no way to get the current installed VS version other than enumerating a version whitelist
:: If anyone ever tells you that Windows is a reasonable operating system, they are wrong

echo Searching for installed visual studio version...
for %%V in (
HKEY_LOCAL_MACHINE\SOFTWARE\Wow6432Node\Microsoft\VisualStudio\12.0
HKEY_LOCAL_MACHINE\SOFTWARE\Wow6432Node\Microsoft\VisualStudio\14.0
HKEY_LOCAL_MACHINE\SOFTWARE\Wow6432Node\Microsoft\VisualStudio\15.0
HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\VisualStudio\12.0
HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\VisualStudio\14.0
HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\VisualStudio\15.0
) do (
    echo ...trying registry key %%V
    for /F "usebackq tokens=3*" %%A IN (`REG QUERY %%V /v InstallDir 2^>NUL`) DO (
        set appdir=%%A %%B
    )
    if not "!appdir!"=="" goto :break
)
:break

if "%appdir%"=="" (
    echo Could not find an installed visual studio version. Abandoning windows static lib export operation.
) else (
    :: Add the Visual Studio binaries to our path and run the linker
    call "%appdir%..\..\VC\vcvarsall.bat" %1
    call lib /machine:%1 /def:unicorn.def
)

exit /b 0
