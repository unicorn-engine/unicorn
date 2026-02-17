Unicorn Engine
==============

[![pypi downloads](https://pepy.tech/badge/unicorn)](https://pepy.tech/project/unicorn)
[![Fuzzing Status](https://oss-fuzz-build-logs.storage.googleapis.com/badges/unicorn.svg)](https://bugs.chromium.org/p/oss-fuzz/issues/list?sort=-opened&can=1&q=proj:unicorn)

**LOOKING FOR CONTRIBUTORS!** See [this](https://github.com/unicorn-engine/unicorn/issues/2237).
==============

<p align="center">
<img width="250" src="docs/unicorn-logo.png">
</p>

Unicorn is a lightweight, multi-platform, multi-architecture CPU emulator framework, based on [QEMU](http://qemu.org).

Unicorn offers some unparalleled features:

- Multi-architecture: ARM, ARM64 (ARMv8), M68K, MIPS, PowerPC, RISCV, SPARC, S390X, TriCore, LoongArch64 and X86 (16, 32, 64-bit)
- Clean/simple/lightweight/intuitive architecture-neutral API
- Implemented in pure C language, with bindings for Crystal, Clojure, Visual Basic, Perl, Rust, Ruby, Python, Java, .NET, Go, Delphi/Free Pascal, Haskell, Pharo, Lua and Zig.
- Native support for Windows & *nix (with Mac OSX, Linux, Android, *BSD & Solaris confirmed)
- High performance via Just-In-Time compilation
- Support for fine-grained instrumentation at various levels
- Thread-safety by design
- Distributed under free software license GPLv2

Further information is available at http://www.unicorn-engine.org


License
-------

This project is released under the [GPL license](COPYING).


Compilation & Docs
------------------

See [docs/COMPILE.md](docs/COMPILE.md) file for how to compile and install Unicorn.

More documentation is available in [docs/README.md](docs/README.md).

For common questions, read [docs/FAQ.md](docs/FAQ.md) before raising an issue.

Contact
-------

[Contact us](http://www.unicorn-engine.org/contact/) via mailing list, email or twitter for any questions.


Join [our group](https://t.me/+lnNl0fPpyCYzZmVh) for instant feedback.

Contribute
----------

If you want to contribute, please pick up something from our [Github issues](https://github.com/unicorn-engine/unicorn/issues).

We also maintain a list of more challenged problems in [milestones](https://github.com/unicorn-engine/unicorn/milestones) for our regular release.

Please send pull request to our [dev branch](https://github.com/unicorn-engine/unicorn/tree/dev).

[CREDITS.TXT](CREDITS.TXT) records important contributors of our project.
