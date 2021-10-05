This HOWTO introduces how to build Unicorn2 natively on Linux/Mac/Windows or cross-build to Windows from Linux host.

## Native build on Linux/macOS

This builds Unicorn2 on Linux/macOS. Note that this also applies to Apple Silicon M1 users.

- Install `cmake` and `pkg-config` with your favorite package manager:

Ubuntu:

``` bash
$ sudo apt install cmake pkg-config
```

macOS:

```bash
$ brew install cmake pkg-config
```

- Build with the following commands.

```bash
$ mkdir build; cd build
$ cmake .. -DCMAKE_BUILD_TYPE=Release
$ make
```

### Native build on Windows, with MSVC

This builds Unicorn2 on Windows, using Microsoft MSVC compiler.

- Require `cmake` & `Microsoft Visual Studio`.

- From Visual Studio Command Prompt, build with the following commands.

```bash
mkdir build; cd build
cmake .. -G "NMake Makefiles" -DCMAKE_BUILD_TYPE=Release
nmake
```

Note, other generators like `Ninja` and `Visual Studio 16 2019` would also work.

```
mkdir build; cd build
cmake .. -G "Visual Studio 16 2019" -A "win32" -DCMAKE_BUILD_TYPE=Release
msbuild unicorn.sln -p:Plaform=Win32 -p:Configuration=Release
```

### Cross build from Linux host to Windows, with Mingw

This cross-builds Unicorn2 from **Linux host** to Windows, using `Mingw` compiler.

- Install required package.

```
$ sudo apt install mingw-w64-x86-64-dev
```

- Build Unicorn and samples with the following commands.

```
$ mkdir build; cd build
$ cmake .. -DCMAKE_TOOLCHAIN_FILE=../mingw64-w64.cmake
$ make
```

### Native build on Windows host, with MSYS2/Mingw

This builds Unicorn2 on **Windows host**, using **MSYS2/Mingw** compiler.

This requires MSYS2 to be installed on the Windows machine. You need to download & install MSYS2 from https://www.msys2.org.

Then from MSYS2 console, install packages below:

```
pacman -S mingw-w64-x86_64-toolchain mingw-w64-x86_64-cmake
```

- Build Unicorn and samples with the following commands.

```
mkdir build; cd build
/mingw64/bin/cmake .. -G "MSYS Makefiles" -DCMAKE_C_COMPILER=/mingw64/bin/gcc.exe -DCMAKE_MAKE_PROGRAM=/mingw64/bin/mingw32-make.exe -DCMAKE_AR=/mingw64/bin/ar.exe -DUNICORN_ARCH=x86
mingw32-make
```

Note that the way to build on MSYS changes as time goes, please keep in mind that always use the cmake shipped with mingw64 and choose MSYS Makefiles.

### Cross build from Linux host to other architectures

This cross-builds Unicorn2 from **Linux host** to other architectures, using a cross compiler.

- Install cross compiler package. For example, cross-compile to ARM requires the below command.

```
$ sudo apt install gcc-arm-linux-gnueabihf
```

- Build Unicorn and samples with the following commands. The compiler name differs according to your targets.

```
$ mkdir build; cd build
$ cmake .. -DCMAKE_C_COMPILER=gcc-arm-linux-gnueabihf
$ make
```
