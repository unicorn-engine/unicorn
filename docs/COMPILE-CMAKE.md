This documentation explains how to compile Unicorn with CMake on Windows or
*nix.

----

Requirements:
    Windows: MicroSoft Visual Studio(>=2013).
    *nix: GNU gcc. Python CLI to generate dynamic source files.

Get CMake for free from http://www.cmake.org.


[1] Tailor Unicorn to your need.

  Out of archtitectures supported by Unicorn, if you just need several selected archs,
  set the 'UNICORN_ARCH' in CMake. e.g.:

      cmake -DUNICORN_ARCH="x86 mips" ..

  By default, all architectures(x86 arm aarch64 m68k mips sparc) are compiled in.

  Besides, Unicorn also allows some more customization via following macros.

  - UNICORN_STATIC_MSVCRT: change this to OFF to use dynamic MSVCRT lib, Only on Windows.

[2] CMake allows you to generate different generators to build Unicorn. Below is
    some examples on how to build Unicorn on Windows with CMake.

- You can let CMake select a generator for you. Do:
  
      mkdir build
      cd build
      cmake ..
      
    This last command is also where you can pass additional CMake configuration flags
    using `-D<key>=<value>`. Then to build use:
    
      cmake --build . --config Release
      

- To build Unicorn using Nmake of Windows SDK, do:

      mkdir build
      cd build
      ..\nmake.bat

  After this, find the samples test*.exe, unicorn.lib & unicorn.dll
  in the same directory.



- To build Unicorn using Visual Studio, choose the generator accordingly to the
  version of Visual Studio on your machine. For example, with Visual Studio 2013, do:

      mkdir build
      cd build
      cmake -G "Visual Studio 12" ..

  After this, find unicorn.sln in the same directory. Open it with Visual Studio
  and build the solution including libraries & all test as usual.



[3] You can make sure the prior steps successfully worked by launching one of the
  sample binary (sample_*.exe).

[4] You can also enable just one specific architecture by passing the architecture name
  to either the cmake.sh or nmake.bat scripts. e.g.:
  
    ../cmake.sh x86

  Will just target the x86 architecture. The list of available architectures is:
 X86 ARM AARCH64 M68K MIPS SPARC.
  
[5] You can also create an installation image with cmake, by using the 'install' target.
  Use:

    cmake --build . --config Release --target install

  This will normally install an image in a default location (NOT SUPPORT Windows),
  so it's good to explicitly set this location when configuring CMake. Use: `-DCMAKE_INSTALL_PREFIX=image`
  for instance, to put the installation in the 'image' subdirectory of the build directory.
  Default value of 'CMAKE_INSTALL_PREFIX' on *nix is '/usr/local'.
