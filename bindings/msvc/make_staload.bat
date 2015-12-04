call "C:\Program Files (x86)\Microsoft Visual Studio 11.0\VC\bin\vcvars32.bat"
lib /DEF:unicorn.def /OUT:unicorn_staload.lib /MACHINE:X86
lib /DEF:unicorn.def /OUT:unicorn_staload64.lib /MACHINE:X64
