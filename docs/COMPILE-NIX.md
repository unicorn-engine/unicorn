This documentation explains how to compile, install & run Unicorn on MacOSX,
Linux, BSD, Solaris, Android & iOS.

To compile for Microsoft Windows, see [COMPILE-WINDOWS.md](COMPILE-WINDOWS.md)

----

[1] Tailor Unicorn to your need.

Out of 6 archtitectures supported by Unicorn (Arm, Arm64, M68K, Mips, Sparc,
& X86), if you just need several selected archs, choose which ones you want
to compile in by editing "config.mk" before going to next steps.

By default, all 6 architectures are compiled. If this is what you want, skip
to the section 2.

The other way of customize Unicorn without having to edit config.mk is to
pass the desired options on the commandline to ./make.sh. Currently,
Unicorn supports 4 options, as follows.

  - UNICORN_ARCHS: specify list of architectures to compiled in.
  - UNICORN_STATIC: build static library.
  - UNICORN_SHARED: build dynamic (shared) library.
  - UNICORN_QEMU_FLAGS: specify extra flags for qemu's configure script

To avoid editing config.mk for these customization, we can pass their values to
make.sh, as follows.

        $ UNICORN_ARCHS="arm aarch64 x86" ./make.sh

NOTE: on commandline, put these values in front of ./make.sh, not after it.

For each option, refer to docs/README for more details.



[2] Compile and install from source on *nix

To build Unicorn on *nix (such as MacOSX, Linux, *BSD, Solaris):

- To compile for current platform, run:

        $ ./make.sh

  On Mac OS, to build non-universal binaries that includes only 64-bit code,
  replace above command with:

        $ ./make.sh macos-universal-no

- Unicorn requires Python 2.x to compile. If Python 2.x is not the default
    Python interpreter, ensure that the appropriate option is set:

        $ UNICORN_QEMU_FLAGS="--python=/path/to/python2" ./make.sh

- To cross-compile Unicorn on 64-bit Linux to target 32-bit binary,
  cross-compile to 32-bit with:

        $ ./make.sh linux32

  After compiling, install Unicorn with:

        $ sudo ./make.sh install

  For OpenBSD, where sudo is unavailable, run:

        $ su; ./make.sh install
        
  On FreeBSD, system's `make` is different from GNU make, so you need to install it.
  
        # pkg install gmake
        $ gmake

  Users are then required to enter root password to copy Unicorn into machine
  system directories.

  Afterwards, run ./samples/sample_all.sh to test the sample emulations.


  NOTE: The core framework installed by "./make.sh install" consist of
  following files:

        /usr/include/unicorn/unicorn.h
        /usr/include/unicorn/x86.h
        /usr/include/unicorn/arm.h
        /usr/include/unicorn/arm64.h
        /usr/include/unicorn/mips.h
        /usr/include/unicorn/ppc.h
        /usr/include/unicorn/sparc.h
        /usr/include/unicorn/m68k.h
        /usr/lib/libunicorn.so (for Linux/*nix), or /usr/lib/libunicorn.dylib (OSX)
        /usr/lib/libunicorn.a



[3] Cross-compile for iOS from Mac OSX.

To cross-compile for iOS (iPhone/iPad/iPod), Mac OSX with XCode installed is required.

- To cross-compile for ArmV7 (iPod 4, iPad 1/2/3, iPhone4, iPhone4S), run:

        $ ./make.sh ios_armv7

- To cross-compile for ArmV7s (iPad 4, iPhone 5C, iPad mini), run:

        $ ./make.sh ios_armv7s

- To cross-compile for Arm64 (iPhone 5S, iPad mini Retina, iPad Air), run:

        $ ./make.sh ios_arm64

- To cross-compile for all iDevices (armv7 + armv7s + arm64), run:

        $ ./make.sh ios

Resulted files libunicorn.dylib, libunicorn.a & tests/test* can then
be used on iOS devices.



[4] Cross-compile for Android

To cross-compile for Android (smartphone/tablet), Android NDK is required.
NOTE: Only ARM and ARM64 are currently supported.

        $ NDK=/android/android-ndk-r10e ./make.sh cross-android arm
or
        $ NDK=/android/android-ndk-r10e ./make.sh cross-android arm64

Resulted files libunicorn.so, libunicorn.a & tests/test* can then
be used on Android devices.



[5] By default, "cc" (default C compiler on the system) is used as compiler.

- To use "clang" compiler instead, run the command below:

        $ ./make.sh clang

- To use "gcc" compiler instead, run:

        $ ./make.sh gcc



[6] To uninstall Unicorn, run the command below:

        $ sudo ./make.sh uninstall



[7] Language bindings

Look for the bindings under directory bindings/, and refer to README file
of corresponding languages.



[8] Unit tests

Automated unit tests use the cmocka unit testing framework (https://cmocka.org/).
It can be installed in most Linux distros using the package manager, e.g.
`sudo yum install libcmocka libcmocka-devel`, or you can easily build and install it from source.

You can run the tests by running `make test` in the project directory.
