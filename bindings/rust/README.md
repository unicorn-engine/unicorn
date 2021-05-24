# unicorn-rs

Rust bindings for the [Unicorn](http://www.unicorn-engine.org/) emulator with utility functions.

An extended version for fuzzing with AFL++ support can be found in https://github.com/aflplusplus/unicornafl.

```rust
use unicorn::RegisterARM;
use unicorn::unicorn_const::{Arch, Mode, Permission, SECOND_SCALE};

fn main() {
    let arm_code32: Vec<u8> = vec![0x17, 0x00, 0x40, 0xe2]; // sub r0, #23

    let mut unicorn = unicorn::Unicorn::new(Arch::ARM, Mode::LITTLE_ENDIAN).expect("failed to initialize Unicorn instance");
    let mut emu = unicorn.borrow();
    emu.mem_map(0x1000, 0x4000, Permission::ALL).expect("failed to map code page");
    emu.mem_write(0x1000, &arm_code32).expect("failed to write instructions");

    emu.reg_write(RegisterARM::R0 as i32, 123).expect("failed write R0");
    emu.reg_write(RegisterARM::R5 as i32, 1337).expect("failed write R5");

    let _ = emu.emu_start(0x1000, (0x1000 + arm_code32.len()) as u64, 10 * SECOND_SCALE, 1000);
    assert_eq!(emu.reg_read(RegisterARM::R0 as i32), Ok(100));
    assert_eq!(emu.reg_read(RegisterARM::R5 as i32), Ok(1337));
}
```
Further sample code can be found in ```tests/unicorn.rs```.

## Installation

This project has been tested on Linux, OS X and Windows. 

To use unicorn-rs, simply add it as a dependency to the Cargo.toml of your program.

```
[dependencies]
unicorn = { path = "/path/to/bindings/rust", version="1.0.0" }
```

## Acknowledgements

These bindings are based on Sébastien Duquette's (@ekse) [unicorn-rs](https://github.com/unicorn-rs/unicorn-rs).
We picked up the project, as it is no longer maintained.
Thanks to all contributers.

