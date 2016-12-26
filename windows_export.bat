@echo on

:: If anyone ever tells you that windows is a reasonable operating system, they are wrong

FOR /F "usebackq tokens=3*" %%A IN (`REG QUERY "HKEY_LOCAL_MACHINE\SOFTWARE\Wow6432Node\Microsoft\VisualStudio\12.0" /v InstallDir`) DO (
    set appdir=%%A %%B
)

call "%appdir%..\..\VC\vcvarsall.bat" %1
call lib /machine:%1 /def:unicorn.def
