# Unicorn-engine

Rust bindings for the [Unicorn](http://www.unicorn-engine.org/) emulator with utility functions.

Checkout Unicorn2 source code at [dev branch](https://github.com/unicorn-engine/unicorn/tree/dev).

```rust
use unicorn_engine::{Arch, Mode, Prot, SECOND_SCALE, Unicorn, RegisterARM};

fn main() {
    let arm_code32: Vec<u8> = vec![0x17, 0x00, 0x40, 0xe2]; // sub r0, #23

    let mut emu = Unicorn::new(Arch::ARM, Mode::LITTLE_ENDIAN).expect("failed to initialize Unicorn instance");
    emu.mem_map(0x1000, 0x4000, Prot::ALL).expect("failed to map code page");
    emu.mem_write(0x1000, &arm_code32).expect("failed to write instructions");

    emu.reg_write(RegisterARM::R0, 123).expect("failed write R0");
    emu.reg_write(RegisterARM::R5, 1337).expect("failed write R5");

    emu.emu_start(0x1000, (0x1000 + arm_code32.len()) as u64, 10 * SECOND_SCALE, 1000).expect("failed to start emulation");
    assert_eq!(emu.reg_read(RegisterARM::R0).unwrap(), 100);
    assert_eq!(emu.reg_read(RegisterARM::R5).unwrap(), 1337);
}
```

Further sample code can be found in [tests](./src/tests).

## Usage

Add this to your `Cargo.toml`:

```
[dependencies]
unicorn-engine = "2.1.1"
```

## Acknowledgements

These bindings were once based on Sébastien Duquette's (@ekse) [unicorn-rs](https://github.com/unicorn-rs/unicorn-rs).
We picked up the project, as it is no longer maintained.
Thanks to all contributors.
