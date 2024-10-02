# Unicorn-engine-Zig

[Zig](https://ziglang.org/) bindings for the [Unicorn](http://www.unicorn-engine.org/) emulator with utility functions.

*Unicorn* is a lightweight multi-platform, multi-architecture CPU emulator framework
based on [QEMU](http://www.qemu.org/).

## How to use

Using the [Zig Build System](https://ziglang.org/learn/build-system/), you can include
the following into your local `build.zig.zon`

``` zig
.{
    .dependencies = .{
        .unicorn = .{
            .url = "https://github.com/unicorn-engine/unicorn/archive/<ref SHA>.tar.gz",
            .hash = "<hash>",
        }
    },
}
```

Note that currently the only module exported publicly is `unicorn-sys`
