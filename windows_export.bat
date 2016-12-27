@echo on

:: This script invokes the visual studio linker to construct a static library file that can be used outside of mingw.
:: The unicorn.def file that it references below is produced by the mingw compiler via a linker flag.
:: The arch (x86 or x64) we are working on should be passed via the first argument to this script.

:: Look up the Visual Studio install path via the registry
:: http://stackoverflow.com/questions/445167/how-can-i-get-the-value-of-a-registry-key-from-within-a-batch-script
:: If anyone ever tells you that windows is a reasonable operating system, they are wrong
FOR /F "usebackq tokens=3*" %%A IN (`REG QUERY "HKEY_LOCAL_MACHINE\SOFTWARE\Wow6432Node\Microsoft\VisualStudio\12.0" /v InstallDir`) DO (
    set appdir=%%A %%B
)

:: Add the visual studio binaries to our path and run the linker
call "%appdir%..\..\VC\vcvarsall.bat" %1
call lib /machine:%1 /def:unicorn.def
