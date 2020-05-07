This documentation explains how to compile Unicorn with CMake on Windows or
*nix.

----

Requirements:

- Windows: MicroSoft Visual Studio(>=2013).
- *nix: GNU gcc or clang to generate dynamic source files.

Get CMake for free from http://www.cmake.org.


[1] To build Unicorn using Nmake of Windows SDK, do:

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


[2] You can make sure the prior steps successfully worked by launching one of the
  sample binary (sample_*.exe).


[3] You can also enable just one specific architecture by passing the architecture name
  to either the cmake.sh or nmake.bat scripts. e.g.:

    ..\nmake.bat x86

  Will just target the x86 architecture. The list of available architectures are:
 X86 ARM AARCH64 M68K MIPS SPARC.


[4] You can also create an installation image with cmake, by using the 'install' target.
  Use:

    cmake --build . --config Release --target install

  This will normally install an image in a default location (on MacOS and Linux, but this is not supported
  on Windows). So in case you want to change the install location, set this when configuring CMake.
  Use: `-DCMAKE_INSTALL_PREFIX=path` for instance, to put the installation in the 'path' subdirectory of
  the build directory.
  The default value of 'CMAKE_INSTALL_PREFIX' on *nix is '/usr/local'.
