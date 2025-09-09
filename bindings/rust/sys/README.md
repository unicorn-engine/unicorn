# Unicorn-engine-sys

Low-level Rust bindings for the [Unicorn](http://www.unicorn-engine.org/) emulator. This crate only exposes the C API of Unicorn.

Checkout Unicorn2 source code at [dev branch](https://github.com/unicorn-engine/unicorn/tree/dev).

```rust
use unicorn_engine_sys::{
    Arch, Mode, uc_close, uc_emu_start, uc_engine, uc_mem_map, uc_mem_write, uc_open,
    uc_reg_read, uc_reg_write,
};

fn main() {
    let mut uc_engine: *mut uc_engine = std::ptr::null_mut();
    let err = unsafe { uc_open(Arch::ARM, Mode::ARM, &raw mut uc_engine) };
    assert_eq!(err, uc_error::OK, "Failed to open Unicorn engine");

    let code: [u8; 4] = [0x17, 0x00, 0x40, 0xe2]; // sub r0, #23
    let err = unsafe { uc_mem_map(uc_engine, CODE_START, 0x1000, Prot::ALL.0) };
    assert_eq!(err, uc_error::OK, "Failed to map memory");

    let err = unsafe { uc_mem_write(uc_engine, CODE_START, code.as_ptr().cast(), code.len()) };
    assert_eq!(err, uc_error::OK, "Failed to write memory");

    let mut r0: u64 = 123;
    let err = unsafe { uc_reg_write(uc_engine, RegisterARM::R0 as i32, (&raw mut r0).cast()) };
    assert_eq!(err, uc_error::OK, "Failed to write R0");

    let mut r5: u64 = 1337;
    let err = unsafe { uc_reg_write(uc_engine, RegisterARM::R5 as i32, (&raw mut r5).cast()) };
    assert_eq!(err, uc_error::OK, "Failed to write R5");

    let err = unsafe { uc_emu_start(uc_engine, CODE_START, CODE_START + code.len() as u64, 0, 0) };
    assert_eq!(err, uc_error::OK, "Failed to start emulation");

    r0 = 0;
    let err = unsafe { uc_reg_read(uc_engine, RegisterARM::R0 as i32, (&raw mut r0).cast()) };
    assert_eq!(err, uc_error::OK, "Failed to read R0");

    r5 = 0;
    let err = unsafe { uc_reg_read(uc_engine, RegisterARM::R5 as i32, (&raw mut r5).cast()) };
    assert_eq!(err, uc_error::OK, "Failed to read R5");

    assert_eq!(r0, 100);
    assert_eq!(r5, 1337);

    // Clean up
    unsafe { uc_close(uc_engine) };
}
```

Further sample code can be found in [tests](./src/tests).

## Usage

Add this to your `Cargo.toml`:

```
[dependencies]
unicorn-engine-sys = "2.1.4"
```
