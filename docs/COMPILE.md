This HOWTO introduces how to build Unicorn2 natively on Linux/Mac/Windows,
or cross-build to Windows from Linux host.

---
### Native build on Linux/MacOS

This builds Unicorn2 on Linux/MacOS. The output is `libunicorn.so` or `libunicorn.dylib`, respectively.

- Require `cmake` & `pkg-config` packages (besides `gcc`/`clang` compiler):

```
$ sudo apt install cmake pkg-config
```

- Build with the following commands.

```
$ mkdir build; cd build
$ ../cmake.sh
```

Then run the sample `sample_riscv` with:

```
$ ./sample_riscv
```

---
### Native build on Windows, with MSVC

This builds Unicorn2 on Windows, using Microsoft MSVC compiler. The output is `unicorn.dll`.

- Require `cmake` & `Microsoft Visual Studio`.

- From Visual Studio Command Prompt, build with the following commands.

```
mkdir build; cd build
../nmake.sh
```

Then run the sample `sample_riscv` with:

```
sample_riscv.exe
```

---

### Cross build from Linux host to Windows, with Mingw

This cross-builds Unicorn2 from **Linux host** to Windows, using `Mingw` compiler. The output is `libunicorn.dll`

- Install required package.

```
$ sudo apt install mingw-w64-x86-64-dev
```

- Build Unicorn and samples with the following commands.

```
$ mkdir build; cd build
$ ../cmake.sh mingw
```

The resulted `sample_riscv.exe` can be run with `libunicorn.dll`, and some dependecies DLLs
already provided in `bin/` directory.

To prepare for `sample_riscv.exe`, do:

```
cp libunicorn.dll ../bin
cp sample_riscv.exe ../bin
```

Then inside the `bin/` directory, you can run `sample_riscv.exe` (from `CMD.exe` prompt, for example)


---

### Native build on Windows host, with MSYS2/Mingw

This builds Unicorn2 on **Windows host**, using **MSYS2/Mingw** compiler. The output is `libunicorn.dll`

This requires MSYS2 to be installed on Windows machine. You need to download & install MSYS2 from https://www.msys2.org.

Then from MSYS2 console, install required packages:

```
pacman -S mingw-w64-x86_64-toolchain mingw-w64-x86_64-cmake
```

- Build Unicorn and samples with the following commands.

```
mkdir build; cd build
../cmake.sh msys
```

The resulted `sample_riscv.exe` can be run with `libunicorn.dll`, and some dependecies DLLs
already provided in `bin/` directory.

To prepare for `sample_riscv.exe`, do:

```
cp libunicorn.dll ../bin
cp sample_riscv.exe ../bin
```

Then inside the `bin/` directory, you can run `sample_riscv.exe` (from `CMD.exe` prompt, for example)


---

### Cross build from Linux host to other arch

This cross-builds Unicorn2 from **Linux host** to other arch, using cross compiler. The output is `libunicorn.so`

- Install cross compiler package. For example, cross compile to ARM require below command.

```
$ sudo apt install gcc-arm-linux-gnueabihf
```

- Build Unicorn and samples with the following commands (note that you need to specify compiler with CC).

```
$ mkdir build; cd build
$ CC=arm-linux-gnueabihf-gcc ../cmake.sh
```
