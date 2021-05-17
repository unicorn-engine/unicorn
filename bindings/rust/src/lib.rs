//! Bindings for the Unicorn emulator.
//!
//!
//!
//! # Example use
//!
//! ```rust
//!
//! use unicorn::RegisterARM;
//! use unicorn::unicorn_const::{Arch, Mode, Permission, SECOND_SCALE};
//!
//! fn main() {
//!     let arm_code32: Vec<u8> = vec![0x17, 0x00, 0x40, 0xe2]; // sub r0, #23
//!
//!     let mut unicorn = unicorn::Unicorn::new(Arch::ARM, Mode::LITTLE_ENDIAN).expect("failed to initialize Unicorn instance");
//!     let mut emu = unicorn.borrow();
//!     emu.mem_map(0x1000, 0x4000, Permission::ALL).expect("failed to map code page");
//!     emu.mem_write(0x1000, &arm_code32).expect("failed to write instructions");
//!
//!     emu.reg_write(RegisterARM::R0 as i32, 123).expect("failed write R0");
//!     emu.reg_write(RegisterARM::R5 as i32, 1337).expect("failed write R5");
//!
//!     let _ = emu.emu_start(0x1000, (0x1000 + arm_code32.len()) as u64, 10 * SECOND_SCALE, 1000);
//!     assert_eq!(emu.reg_read(RegisterARM::R0 as i32), Ok(100));
//!     assert_eq!(emu.reg_read(RegisterARM::R5 as i32), Ok(1337));
//! }
//! ```
//!

mod ffi;
pub mod unicorn_const;

mod arm;
mod arm64;
mod m68k;
mod mips;
mod ppc;
mod sparc;
mod x86;
pub use crate::{arm::*, arm64::*, m68k::*, mips::*, ppc::*, sparc::*, x86::*};

use ffi::uc_handle;
use std::collections::HashMap;
use std::ffi::c_void;
use std::marker::PhantomPinned;
use std::pin::Pin;
use unicorn_const::*;

#[derive(Debug)]
pub struct Context {
    context: ffi::uc_context,
}

impl Context {
    pub fn new() -> Self {
        Context { context: 0 }
    }
    pub fn is_initialized(&self) -> bool {
        self.context != 0
    }
}

impl Drop for Context {
    fn drop(&mut self) {
        unsafe { ffi::uc_context_free(self.context) };
    }
}

#[derive(Debug)]
/// A Unicorn emulator instance.
pub struct Unicorn {
    inner: Pin<Box<UnicornInner>>,
}

#[derive(Debug)]
/// Handle used to safely access exposed functions and data of a Unicorn instance.
pub struct UnicornHandle<'a> {
    inner: Pin<&'a mut UnicornInner>,
}

/// Internal Management struct
pub struct UnicornInner {
    pub uc: uc_handle,
    pub arch: Arch,
    pub code_hooks: HashMap<*mut libc::c_void, Box<ffi::CodeHook>>,
    pub block_hooks: HashMap<*mut libc::c_void, Box<ffi::BlockHook>>,
    pub mem_hooks: HashMap<*mut libc::c_void, Box<ffi::MemHook>>,
    pub intr_hooks: HashMap<*mut libc::c_void, Box<ffi::InterruptHook>>,
    pub insn_in_hooks: HashMap<*mut libc::c_void, Box<ffi::InstructionInHook>>,
    pub insn_out_hooks: HashMap<*mut libc::c_void, Box<ffi::InstructionOutHook>>,
    pub insn_sys_hooks: HashMap<*mut libc::c_void, Box<ffi::InstructionSysHook>>,
    _pin: PhantomPinned,
}

impl Unicorn {
    /// Create a new instance of the unicorn engine for the specified architecture
    /// and hardware mode.
    pub fn new(arch: Arch, mode: Mode) -> Result<Unicorn, uc_error> {
        let mut handle = std::ptr::null_mut();
        let err = unsafe { ffi::uc_open(arch, mode, &mut handle) };
        if err == uc_error::OK {
            Ok(Unicorn {
                inner: Box::pin(UnicornInner {
                    uc: handle,
                    arch: arch,
                    code_hooks: HashMap::new(),
                    block_hooks: HashMap::new(),
                    mem_hooks: HashMap::new(),
                    intr_hooks: HashMap::new(),
                    insn_in_hooks: HashMap::new(),
                    insn_out_hooks: HashMap::new(),
                    insn_sys_hooks: HashMap::new(),
                    _pin: std::marker::PhantomPinned,
                }),
            })
        } else {
            Err(err)
        }
    }

    pub fn borrow<'a>(&'a mut self) -> UnicornHandle<'a> {
        UnicornHandle {
            inner: self.inner.as_mut(),
        }
    }
}

impl Drop for Unicorn {
    fn drop(&mut self) {
        unsafe { ffi::uc_close(self.inner.uc) };
    }
}

impl std::fmt::Debug for UnicornInner {
    fn fmt(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(formatter, "Unicorn {{ uc: {:p} }}", self.uc)
    }
}

impl<'a> UnicornHandle<'a> {

    /// Return the architecture of the current emulator.
    pub fn get_arch(&self) -> Arch {
        self.inner.arch
    }

    /// Returns a vector with the memory regions that are mapped in the emulator.
    pub fn mem_regions(&self) -> Result<Vec<MemRegion>, uc_error> {
        let mut nb_regions: u32 = 0;
        let mut p_regions: *const MemRegion = std::ptr::null_mut();
        let err = unsafe { ffi::uc_mem_regions(self.inner.uc, &mut p_regions, &mut nb_regions) };
        if err == uc_error::OK {
            let mut regions = Vec::new();
            for i in 0..nb_regions {
                regions.push(unsafe { std::mem::transmute_copy(&*p_regions.offset(i as isize)) });
            }
            unsafe { libc::free(p_regions as _) };
            Ok(regions)
        } else {
            Err(err)
        }
    }

    /// Read a range of bytes from memory at the specified address.
    pub fn mem_read(&self, address: u64, buf: &mut [u8]) -> Result<(), uc_error> {
        let err = unsafe { ffi::uc_mem_read(self.inner.uc, address, buf.as_mut_ptr(), buf.len()) };
        if err == uc_error::OK {
            Ok(())
        } else {
            Err(err)
        }
    }

    /// Return a range of bytes from memory at the specified address as vector.
    pub fn mem_read_as_vec(&self, address: u64, size: usize) -> Result<Vec<u8>, uc_error> {
        let mut buf = vec![0; size];
        let err = unsafe { ffi::uc_mem_read(self.inner.uc, address, buf.as_mut_ptr(), size) };
        if err == uc_error::OK {
            Ok(buf)
        } else {
            Err(err)
        }
    }

    pub fn mem_write(&mut self, address: u64, bytes: &[u8]) -> Result<(), uc_error> {
        let err = unsafe { ffi::uc_mem_write(self.inner.uc, address, bytes.as_ptr(), bytes.len()) };
        if err == uc_error::OK {
            Ok(())
        } else {
            Err(err)
        }
    }

    /// Map an existing memory region in the emulator at the specified address.
    ///
    /// This function is marked unsafe because it is the responsibility of the caller to
    /// ensure that `size` matches the size of the passed buffer, an invalid `size` value will
    /// likely cause a crash in unicorn.
    ///
    /// `address` must be aligned to 4kb or this will return `Error::ARG`.
    ///
    /// `size` must be a multiple of 4kb or this will return `Error::ARG`.
    ///
    /// `ptr` is a pointer to the provided memory region that will be used by the emulator.
    pub fn mem_map_ptr(
        &mut self,
        address: u64,
        size: usize,
        perms: Permission,
        ptr: *mut c_void,
    ) -> Result<(), uc_error> {
        let err = unsafe { ffi::uc_mem_map_ptr(self.inner.uc, address, size, perms.bits(), ptr) };
        if err == uc_error::OK {
            Ok(())
        } else {
            Err(err)
        }
    }

    /// Map a memory region in the emulator at the specified address.
    ///
    /// `address` must be aligned to 4kb or this will return `Error::ARG`.
    /// `size` must be a multiple of 4kb or this will return `Error::ARG`.
    pub fn mem_map(
        &mut self,
        address: u64,
        size: libc::size_t,
        perms: Permission,
    ) -> Result<(), uc_error> {
        let err = unsafe { ffi::uc_mem_map(self.inner.uc, address, size, perms.bits()) };
        if err == uc_error::OK {
            Ok(())
        } else {
            Err(err)
        }
    }

    /// Unmap a memory region.
    ///
    /// `address` must be aligned to 4kb or this will return `Error::ARG`.
    /// `size` must be a multiple of 4kb or this will return `Error::ARG`.
    pub fn mem_unmap(&mut self, address: u64, size: libc::size_t) -> Result<(), uc_error> {
        let err = unsafe { ffi::uc_mem_unmap(self.inner.uc, address, size) };
        if err == uc_error::OK {
            Ok(())
        } else {
            Err(err)
        }
    }

    /// Set the memory permissions for an existing memory region.
    ///
    /// `address` must be aligned to 4kb or this will return `Error::ARG`.
    /// `size` must be a multiple of 4kb or this will return `Error::ARG`.
    pub fn mem_protect(
        &mut self,
        address: u64,
        size: libc::size_t,
        perms: Permission,
    ) -> Result<(), uc_error> {
        let err = unsafe { ffi::uc_mem_protect(self.inner.uc, address, size, perms.bits()) };
        if err == uc_error::OK {
            Ok(())
        } else {
            Err(err)
        }
    }

    /// Write an unsigned value from a register.
    pub fn reg_write<T: Into<i32>>(&mut self, regid: T, value: u64) -> Result<(), uc_error> {
        let err =
            unsafe { ffi::uc_reg_write(self.inner.uc, regid.into(), &value as *const _ as _) };
        if err == uc_error::OK {
            Ok(())
        } else {
            Err(err)
        }
    }

    /// Write variable sized values into registers.
    ///
    /// The user has to make sure that the buffer length matches the register size.
    /// This adds support for registers >64 bit (GDTR/IDTR, XMM, YMM, ZMM (x86); Q, V (arm64)).
    pub fn reg_write_long<T: Into<i32>>(&self, regid: T, value: Box<[u8]>) -> Result<(), uc_error> {
        let err = unsafe { ffi::uc_reg_write(self.inner.uc, regid.into(), value.as_ptr() as _) };
        if err == uc_error::OK {
            Ok(())
        } else {
            Err(err)
        }
    }

    /// Read an unsigned value from a register.
    ///
    /// Not to be used with registers larger than 64 bit.
    pub fn reg_read<T: Into<i32>>(&self, regid: T) -> Result<u64, uc_error> {
        let mut value: u64 = 0;
        let err =
            unsafe { ffi::uc_reg_read(self.inner.uc, regid.into(), &mut value as *mut u64 as _) };
        if err == uc_error::OK {
            Ok(value)
        } else {
            Err(err)
        }
    }

    /// Read 128, 256 or 512 bit register value into heap allocated byte array.
    ///
    /// This adds safe support for registers >64 bit (GDTR/IDTR, XMM, YMM, ZMM (x86); Q, V (arm64)).
    pub fn reg_read_long<T: Into<i32>>(&self, regid: T) -> Result<Box<[u8]>, uc_error> {
        let err: uc_error;
        let boxed: Box<[u8]>;
        let mut value: Vec<u8>;
        let curr_reg_id = regid.into();
        let curr_arch = self.get_arch();

        if curr_arch == Arch::X86 {
            if curr_reg_id >= x86::RegisterX86::XMM0 as i32
                && curr_reg_id <= x86::RegisterX86::XMM31 as i32
            {
                value = vec![0; 16];
            } else if curr_reg_id >= x86::RegisterX86::YMM0 as i32
                && curr_reg_id <= x86::RegisterX86::YMM31 as i32
            {
                value = vec![0; 32];
            } else if curr_reg_id >= x86::RegisterX86::ZMM0 as i32
                && curr_reg_id <= x86::RegisterX86::ZMM31 as i32
            {
                value = vec![0; 64];
            } else if curr_reg_id == x86::RegisterX86::GDTR as i32
                || curr_reg_id == x86::RegisterX86::IDTR as i32
            {
                value = vec![0; 10]; // 64 bit base address in IA-32e mode
            } else {
                return Err(uc_error::ARG);
            }
        } else if curr_arch == Arch::ARM64 {
            if (curr_reg_id >= arm64::RegisterARM64::Q0 as i32
                && curr_reg_id <= arm64::RegisterARM64::Q31 as i32)
                || (curr_reg_id >= arm64::RegisterARM64::V0 as i32
                    && curr_reg_id <= arm64::RegisterARM64::V31 as i32)
            {
                value = vec![0; 16];
            } else {
                return Err(uc_error::ARG);
            }
        } else {
            return Err(uc_error::ARCH);
        }

        err = unsafe { ffi::uc_reg_read(self.inner.uc, curr_reg_id, value.as_mut_ptr() as _) };

        if err == uc_error::OK {
            boxed = value.into_boxed_slice();
            Ok(boxed)
        } else {
            Err(err)
        }
    }

    /// Read a signed 32-bit value from a register.
    pub fn reg_read_i32<T: Into<i32>>(&self, regid: T) -> Result<i32, uc_error> {
        let mut value: i32 = 0;
        let err =
            unsafe { ffi::uc_reg_read(self.inner.uc, regid.into(), &mut value as *mut i32 as _) };
        if err == uc_error::OK {
            Ok(value)
        } else {
            Err(err)
        }
    }

    /// Add a code hook.
    pub fn add_code_hook<F: 'static>(
        &mut self,
        begin: u64,
        end: u64,
        callback: F,
    ) -> Result<ffi::uc_hook, uc_error>
    where
        F: FnMut(UnicornHandle, u64, u32),
    {
        let mut hook_ptr = std::ptr::null_mut();
        let mut user_data = Box::new(ffi::CodeHook {
            unicorn: unsafe { self.inner.as_mut().get_unchecked_mut() } as _,
            callback: Box::new(callback),
        });

        let err = unsafe {
            ffi::uc_hook_add(
                self.inner.uc,
                &mut hook_ptr,
                HookType::CODE,
                ffi::code_hook_proxy as _,
                user_data.as_mut() as *mut _ as _,
                begin,
                end,
            )
        };
        if err == uc_error::OK {
            unsafe { self.inner.as_mut().get_unchecked_mut() }
                .code_hooks
                .insert(hook_ptr, user_data);
            Ok(hook_ptr)
        } else {
            Err(err)
        }
    }

    /// Add a block hook.
    pub fn add_block_hook<F: 'static>(&mut self, callback: F) -> Result<ffi::uc_hook, uc_error>
    where
        F: FnMut(UnicornHandle, u64, u32),
    {
        let mut hook_ptr = std::ptr::null_mut();
        let mut user_data = Box::new(ffi::BlockHook {
            unicorn: unsafe { self.inner.as_mut().get_unchecked_mut() } as _,
            callback: Box::new(callback),
        });

        let err = unsafe {
            ffi::uc_hook_add(
                self.inner.uc,
                &mut hook_ptr,
                HookType::BLOCK,
                ffi::block_hook_proxy as _,
                user_data.as_mut() as *mut _ as _,
                1,
                0,
            )
        };
        if err == uc_error::OK {
            unsafe { self.inner.as_mut().get_unchecked_mut() }
                .block_hooks
                .insert(hook_ptr, user_data);
            Ok(hook_ptr)
        } else {
            Err(err)
        }
    }

    /// Add a memory hook.
    pub fn add_mem_hook<F: 'static>(
        &mut self,
        hook_type: HookType,
        begin: u64,
        end: u64,
        callback: F,
    ) -> Result<ffi::uc_hook, uc_error>
    where
        F: FnMut(UnicornHandle, MemType, u64, usize, i64),
    {
        if !(HookType::MEM_ALL | HookType::MEM_READ_AFTER).contains(hook_type) {
            return Err(uc_error::ARG);
        }

        let mut hook_ptr = std::ptr::null_mut();
        let mut user_data = Box::new(ffi::MemHook {
            unicorn: unsafe { self.inner.as_mut().get_unchecked_mut() } as _,
            callback: Box::new(callback),
        });

        let err = unsafe {
            ffi::uc_hook_add(
                self.inner.uc,
                &mut hook_ptr,
                hook_type,
                ffi::mem_hook_proxy as _,
                user_data.as_mut() as *mut _ as _,
                begin,
                end,
            )
        };
        if err == uc_error::OK {
            unsafe { self.inner.as_mut().get_unchecked_mut() }
                .mem_hooks
                .insert(hook_ptr, user_data);
            Ok(hook_ptr)
        } else {
            Err(err)
        }
    }

    /// Add an interrupt hook.
    pub fn add_intr_hook<F: 'static>(&mut self, callback: F) -> Result<ffi::uc_hook, uc_error>
    where
        F: FnMut(UnicornHandle, u32),
    {
        let mut hook_ptr = std::ptr::null_mut();
        let mut user_data = Box::new(ffi::InterruptHook {
            unicorn: unsafe { self.inner.as_mut().get_unchecked_mut() } as _,
            callback: Box::new(callback),
        });

        let err = unsafe {
            ffi::uc_hook_add(
                self.inner.uc,
                &mut hook_ptr,
                HookType::INTR,
                ffi::intr_hook_proxy as _,
                user_data.as_mut() as *mut _ as _,
                0,
                0,
            )
        };
        if err == uc_error::OK {
            unsafe { self.inner.as_mut().get_unchecked_mut() }
                .intr_hooks
                .insert(hook_ptr, user_data);
            Ok(hook_ptr)
        } else {
            Err(err)
        }
    }

    /// Add hook for x86 IN instruction.
    pub fn add_insn_in_hook<F: 'static>(&mut self, callback: F) -> Result<ffi::uc_hook, uc_error>
    where
        F: FnMut(UnicornHandle, u32, usize),
    {
        let mut hook_ptr = std::ptr::null_mut();
        let mut user_data = Box::new(ffi::InstructionInHook {
            unicorn: unsafe { self.inner.as_mut().get_unchecked_mut() } as _,
            callback: Box::new(callback),
        });

        let err = unsafe {
            ffi::uc_hook_add(
                self.inner.uc,
                &mut hook_ptr,
                HookType::INSN,
                ffi::insn_in_hook_proxy as _,
                user_data.as_mut() as *mut _ as _,
                0,
                0,
                x86::InsnX86::IN,
            )
        };
        if err == uc_error::OK {
            unsafe { self.inner.as_mut().get_unchecked_mut() }
                .insn_in_hooks
                .insert(hook_ptr, user_data);
            Ok(hook_ptr)
        } else {
            Err(err)
        }
    }

    /// Add hook for x86 OUT instruction.
    pub fn add_insn_out_hook<F: 'static>(&mut self, callback: F) -> Result<ffi::uc_hook, uc_error>
    where
        F: FnMut(UnicornHandle, u32, usize, u32),
    {
        let mut hook_ptr = std::ptr::null_mut();
        let mut user_data = Box::new(ffi::InstructionOutHook {
            unicorn: unsafe { self.inner.as_mut().get_unchecked_mut() } as _,
            callback: Box::new(callback),
        });

        let err = unsafe {
            ffi::uc_hook_add(
                self.inner.uc,
                &mut hook_ptr,
                HookType::INSN,
                ffi::insn_out_hook_proxy as _,
                user_data.as_mut() as *mut _ as _,
                0,
                0,
                x86::InsnX86::OUT,
            )
        };
        if err == uc_error::OK {
            unsafe { self.inner.as_mut().get_unchecked_mut() }
                .insn_out_hooks
                .insert(hook_ptr, user_data);
            Ok(hook_ptr)
        } else {
            Err(err)
        }
    }

    /// Add hook for x86 SYSCALL or SYSENTER.
    pub fn add_insn_sys_hook<F: 'static>(
        &mut self,
        insn_type: x86::InsnSysX86,
        begin: u64,
        end: u64,
        callback: F,
    ) -> Result<ffi::uc_hook, uc_error>
    where
        F: FnMut(UnicornHandle),
    {
        let mut hook_ptr = std::ptr::null_mut();
        let mut user_data = Box::new(ffi::InstructionSysHook {
            unicorn: unsafe { self.inner.as_mut().get_unchecked_mut() } as _,
            callback: Box::new(callback),
        });

        let err = unsafe {
            ffi::uc_hook_add(
                self.inner.uc,
                &mut hook_ptr,
                HookType::INSN,
                ffi::insn_sys_hook_proxy as _,
                user_data.as_mut() as *mut _ as _,
                begin,
                end,
                insn_type,
            )
        };
        if err == uc_error::OK {
            unsafe { self.inner.as_mut().get_unchecked_mut() }
                .insn_sys_hooks
                .insert(hook_ptr, user_data);
            Ok(hook_ptr)
        } else {
            Err(err)
        }
    }

    /// Remove a hook.
    ///
    /// `hook` is the value returned by `add_*_hook` functions.
    pub fn remove_hook(&mut self, hook: ffi::uc_hook) -> Result<(), uc_error> {
        let handle = unsafe { self.inner.as_mut().get_unchecked_mut() };
        let err: uc_error;
        let mut in_one_hashmap = false;

        if handle.code_hooks.contains_key(&hook) {
            in_one_hashmap = true;
            handle.code_hooks.remove(&hook);
        }

        if handle.mem_hooks.contains_key(&hook) {
            in_one_hashmap = true;
            handle.mem_hooks.remove(&hook);
        }

        if handle.block_hooks.contains_key(&hook) {
            in_one_hashmap = true;
            handle.block_hooks.remove(&hook);
        }

        if handle.intr_hooks.contains_key(&hook) {
            in_one_hashmap = true;
            handle.intr_hooks.remove(&hook);
        }

        if handle.insn_in_hooks.contains_key(&hook) {
            in_one_hashmap = true;
            handle.insn_in_hooks.remove(&hook);
        }

        if handle.insn_out_hooks.contains_key(&hook) {
            in_one_hashmap = true;
            handle.insn_out_hooks.remove(&hook);
        }

        if handle.insn_sys_hooks.contains_key(&hook) {
            in_one_hashmap = true;
            handle.insn_sys_hooks.remove(&hook);
        }

        if in_one_hashmap {
            err = unsafe { ffi::uc_hook_del(handle.uc, hook) };
        } else {
            err = uc_error::HOOK;
        }

        if err == uc_error::OK {
            Ok(())
        } else {
            Err(err)
        }
    }

    /// Allocate and return an empty Unicorn context.
    ///
    /// To be populated via context_save.
    pub fn context_alloc(&self) -> Result<Context, uc_error> {
        let mut empty_context: ffi::uc_context = Default::default();
        let err = unsafe { ffi::uc_context_alloc(self.inner.uc, &mut empty_context) };
        if err == uc_error::OK {
            Ok(Context {
                context: empty_context,
            })
        } else {
            Err(err)
        }
    }

    /// Save current Unicorn context to previously allocated Context struct.
    pub fn context_save(&self, context: &mut Context) -> Result<(), uc_error> {
        let err = unsafe { ffi::uc_context_save(self.inner.uc, context.context) };
        if err == uc_error::OK {
            Ok(())
        } else {
            Err(err)
        }
    }

    /// Allocate and return a Context struct initialized with the current CPU context.
    ///
    /// This can be used for fast rollbacks with context_restore.
    /// In case of many non-concurrent context saves, use context_alloc and *_save
    /// individually to avoid unnecessary allocations.
    pub fn context_init(&self) -> Result<Context, uc_error> {
        let mut new_context: ffi::uc_context = Default::default();
        let err = unsafe { ffi::uc_context_alloc(self.inner.uc, &mut new_context) };
        if err != uc_error::OK {
            return Err(err);
        }
        let err = unsafe { ffi::uc_context_save(self.inner.uc, new_context) };
        if err == uc_error::OK {
            Ok(Context {
                context: new_context,
            })
        } else {
            unsafe { ffi::uc_context_free(new_context) };
            Err(err)
        }
    }

    /// Restore a previously saved Unicorn context.
    ///
    /// Perform a quick rollback of the CPU context, including registers and some
    /// internal metadata. Contexts may not be shared across engine instances with
    /// differing arches or modes. Memory has to be restored manually, if needed.
    pub fn context_restore(&self, context: &Context) -> Result<(), uc_error> {
        let err = unsafe { ffi::uc_context_restore(self.inner.uc, context.context) };
        if err == uc_error::OK {
            Ok(())
        } else {
            Err(err)
        }
    }

    /// Emulate machine code for a specified duration.
    ///
    /// `begin` is the address where to start the emulation. The emulation stops if `until`
    /// is hit. `timeout` specifies a duration in microseconds after which the emulation is
    /// stopped (infinite execution if set to 0). `count` is the maximum number of instructions
    /// to emulate (emulate all the available instructions if set to 0).
    pub fn emu_start(
        &mut self,
        begin: u64,
        until: u64,
        timeout: u64,
        count: usize,
    ) -> Result<(), uc_error> {
        let err = unsafe { ffi::uc_emu_start(self.inner.uc, begin, until, timeout, count as _) };
        if err == uc_error::OK {
            Ok(())
        } else {
            Err(err)
        }
    }

    /// Stop the emulation.
    ///
    /// This is usually called from callback function in hooks.
    /// NOTE: For now, this will stop the execution only after the current block.
    pub fn emu_stop(&mut self) -> Result<(), uc_error> {
        let err = unsafe { ffi::uc_emu_stop(self.inner.uc) };
        if err == uc_error::OK {
            Ok(())
        } else {
            Err(err)
        }
    }

    /// Query the internal status of the engine.
    ///
    /// supported: MODE, PAGE_SIZE, ARCH
    pub fn query(&self, query: Query) -> Result<usize, uc_error> {
        let mut result: libc::size_t = Default::default();
        let err = unsafe { ffi::uc_query(self.inner.uc, query, &mut result) };
        if err == uc_error::OK {
            Ok(result)
        } else {
            Err(err)
        }
    }
}
