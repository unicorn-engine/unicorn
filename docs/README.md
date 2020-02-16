Documention of Unicorn engine.

* How to compile & install Unicorn.

	http://unicorn-engine.org/docs/

* Tutorial on programming with C & Python languages.

	http://unicorn-engine.org/docs/tutorial.html

* Compare Unicorn & QEMU

	http://unicorn-engine.org/docs/beyond_qemu.html

* Micro Uncorn-Engine API Documentation in Chinese

	https://github.com/kabeor/Micro-Unicorn-Engine-API-Documentation

#Building unicorn - Using vcpkg

You can download and install unicorn using the [vcpkg](https://github.com/Microsoft/vcpkg) dependency manager:

    git clone https://github.com/Microsoft/vcpkg.git
    cd vcpkg
    ./bootstrap-vcpkg.sh
    ./vcpkg integrate install
    ./vcpkg install unicorn

The unicorn port in vcpkg is kept up to date by Microsoft team members and community contributors. If the version is out of date, please [create an issue or pull request](https://github.com/Microsoft/vcpkg) on the vcpkg repository.
