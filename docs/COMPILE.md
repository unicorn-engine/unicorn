To compile Unicorn on Mac OS X, Linux, BSD, Solaris and all kind of nix OS,
see [COMPILE-NIX.md](COMPILE-NIX.md)

To compile Unicorn on Windows, see [COMPILE-WINDOWS.md](COMPILE-WINDOWS.md)

To compile Unicorn with CMake on Windows or *nix, see
[COMPILE-CMAKE.md](COMPILE-CMAKE.md)

Then learn more on how to code your own tools with our samples.

 - For C sample code, see code in directory samples/sample*.c
 - For Python sample code, see code in directory bindings/python/sample*.py
 - For samples of other bindings, look into directories bindings/<language>/

#Building unicorn - Using vcpkg

You can download and install unicorn using the [vcpkg](https://github.com/Microsoft/vcpkg) dependency manager:

    git clone https://github.com/Microsoft/vcpkg.git
    cd vcpkg
    ./bootstrap-vcpkg.sh
    ./vcpkg integrate install
    ./vcpkg install unicorn

The unicorn port in vcpkg is kept up to date by Microsoft team members and community contributors. If the version is out of date, please [create an issue or pull request](https://github.com/Microsoft/vcpkg) on the vcpkg repository.