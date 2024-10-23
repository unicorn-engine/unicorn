# Unicorn

Unicorn is a lightweight, multi-platform, multi-architecture CPU emulator framework
based on [QEMU](http://qemu.org).

Unicorn offers some unparalleled features:

- Multi-architecture: ARM, ARM64 (ARMv8), M68K, MIPS, PowerPC, RISCV, SPARC, S390X, TriCore and X86 (16, 32, 64-bit)
- Clean/simple/lightweight/intuitive architecture-neutral API
- Implemented in pure C language, with bindings for Crystal, Clojure, Visual Basic, Perl, Rust, Ruby, Python, Java, .NET, Go, Delphi/Free Pascal, Haskell, Pharo, and Lua.
- Native support for Windows & *nix (with Mac OSX, Linux, *BSD & Solaris confirmed)
- High performance via Just-In-Time compilation
- Support for fine-grained instrumentation at various levels
- Thread-safety by design
- Distributed under free software license GPLv2

Further information is available at http://www.unicorn-engine.org

# Python Bindings for Unicorn

Originally written by Nguyen Anh Quynh, polished and redesigned by elicn, maintained by all community contributors.

## Install

Install a prebuilt wheel from PyPI:

```bash
python3 -m pip install unicorn
```

In case you would like to develop the bindings:

```bash
DEBUG=1 THREADS=4 python3 -m pip install --user -e .
# Workaround for Pylance
DEBUG=1 THREADS=4 python3 -m pip install --user -e . --config-settings editable_mode=strict
```

or install it by building it by yourself:

```bash
THREADS=4 python3 -m pip install --user .
```

Explanations for arguments:

- `THREADS=4` will use 4 threads for building.
- `DEBUG=1` will build debug version of unicorn.
- `--user` will install the bindings to your user directory instead of requiring root permission.
- `-e` infers the editable mode, which gives your instant feedback instead of re-compiling every time.

Note that you should setup a valid building environment according to docs/COMPILE.md but not necessarily build it because `setup.py` will do this for you. 

## Python2 compatibility

By default, Unicorn python bindings works with Python3.7 and above, as it offers more powerful features which improves developing efficiency compared to Python2. However, Unicorn will only keep compatible with all features Unicorn1 offers regarding Python2 because it has reached end-of-life for more than 3 years at the time of writing this README. While offering all features for both Python2 & Python3 is desirable and doable, it inevitably costs too much efforts to maintain and few users really rely on this. Therefore, we assume that if users still stick to Python2, previous Unicorn1 features should be enough. If you really want some new features Unicorn2 offers, please check and pull request to `unicorn/unicorn_py2`. We are happy to review and accept!
Even though the build of wheel packages requires Python3, it's still possible to re-tag the wheel produced from Python3 with `py2` tag and then run `python2 -m pip install <retagged-wheel-py>`. For detailed commands please refer to our workflow files.
