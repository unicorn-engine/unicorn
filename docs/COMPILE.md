This HOWTO introduces how to build Unicorn2 natively on Linux/Mac/Windows or cross-build to Windows from Linux host.

Note: By default, CMake will build both the shared and static libraries while only static libraries are built if unicorn is used as a Cmake subdirectory. In most cases, you don't need to care about which kind of library to build. ONLY use `BUILD_SHARED_LIBS=no`if you know what you are doing.

## Native build on Linux/macOS

This builds Unicorn2 on Linux/macOS. Note that this also applies to Apple Silicon M1 users.

- Install `cmake` and `pkg-config` with your favorite package manager:

Ubuntu:

``` bash
sudo apt install cmake pkg-config
```

macOS:

```bash
brew install cmake pkg-config
```

- Build with the following commands.

```bash
mkdir build; cd build
cmake .. -DCMAKE_BUILD_TYPE=Release
make
```

## Native build on Windows, with MSVC

This builds Unicorn2 on Windows, using Microsoft MSVC compiler.

- Require `cmake` & `Microsoft Visual Studio` (>=16.8).

- From Visual Studio Command Prompt, build with the following commands.

```bash
mkdir build; cd build
cmake .. -G "NMake Makefiles" -DCMAKE_BUILD_TYPE=Release
nmake
```

Note, other generators like `Ninja` and `Visual Studio 16 2019` would also work.

```bash
mkdir build; cd build
cmake .. -G "Visual Studio 16 2019" -A "win32" -DCMAKE_BUILD_TYPE=Release
msbuild unicorn.sln -p:Plaform=Win32 -p:Configuration=Release
```

## Cross build with NDK

To cross-build and run Unicorn2 on the Android platform, firstly you need to download [NDK](https://developer.android.com/ndk/downloads).

For newer NDK, please make sure your cmake version is above 3.19.

Then generate the project like:

```bash
mkdir build; cd build;
cmake .. -DCMAKE_TOOLCHAIN_FILE=$NDK/build/cmake/android.toolchain.cmake -DANDROID_ABI=$ABI -DANDROID_NATIVE_API_LEVEL=$MINSDKVERSION
make
```

You may get the possible values from this [page](https://developer.android.com/ndk/guides/cmake).

Unicorn2 support cross-build for `armeabi-v7a`, `arm64-v8a`, `x86` and `x86_64`.

Note the build is only tested and guaranteed to work under Linux and macOS, however, other systems may still work.

## Cross build from Linux host to Windows, with Mingw

This cross-builds Unicorn2 from **Linux host** to Windows, using `Mingw` compiler.

- Install required package.

```bash
sudo apt install mingw-w64-x86-64-dev
```

- Build Unicorn and samples with the following commands.

```bash
mkdir build; cd build
cmake .. -DCMAKE_TOOLCHAIN_FILE=../mingw64-w64.cmake
make
```

## Native build on Windows host, with MSYS2/Mingw

This builds Unicorn2 on **Windows host**, using **MSYS2/Mingw** compiler.

This requires MSYS2 to be installed on the Windows machine. You need to download & install MSYS2 from https://www.msys2.org.

Then from MSYS2 console, install packages below:

```bash
pacman -S mingw-w64-x86_64-toolchain mingw-w64-x86_64-cmake mingw-w64-x86_64-ninja
```

- Build Unicorn and samples with the following commands.

```bash
export PATH=/mingw64/bin:$PATH
mkdir build; cd build
/mingw64/bin/cmake .. -G "Ninja"
ninja -C .
```

Note that the way to build on MSYS changes as time goes, please keep in mind that always use the cmake shipped with mingw64.

## Cross build from Linux host to other architectures

This cross-builds Unicorn2 from **Linux host** to other architectures, using a cross compiler.

- Install cross compiler package. For example, cross-compile to ARM requires the below command.

```bash
sudo apt install gcc-arm-linux-gnueabihf
```

- Build Unicorn and samples with the following commands. The compiler name differs according to your targets.

```bash
mkdir build; cd build
cmake .. -DCMAKE_C_COMPILER=gcc-arm-linux-gnueabihf
make
```

## Building from vcpkg

The Unicorn port in vcpkg is kept up to date by Microsoft team members and community contributors. The url of vcpkg is: https://github.com/Microsoft/vcpkg . You can download and install unicorn using the vcpkg dependency manager:

```bash
git clone https://github.com/Microsoft/vcpkg.git
cd vcpkg
./bootstrap-vcpkg.sh  # ./bootstrap-vcpkg.bat for Windows
./vcpkg integrate install
./vcpkg install unicorn
```

If the version is out of date, please [create an issue or pull request](https://github.com/Microsoft/vcpkg) on the vcpkg repository.
