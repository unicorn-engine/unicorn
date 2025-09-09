//! Bindings for the Unicorn emulator.
//!
//!
//!
//! # Example use
//!
//! ```rust
//! use unicorn_engine::{
//!     RegisterARM,
//!     unicorn_const::{Arch, Mode, Prot, SECOND_SCALE},
//! };
//!
//! fn emulate() {
//!     let arm_code32 = [0x17, 0x00, 0x40, 0xe2]; // sub r0, #23
//!
//!     let mut emu = unicorn_engine::Unicorn::new(Arch::ARM, Mode::LITTLE_ENDIAN)
//!         .expect("failed to initialize Unicorn instance");
//!     emu.mem_map(0x1000, 0x4000, Prot::ALL)
//!         .expect("failed to map code page");
//!     emu.mem_write(0x1000, &arm_code32)
//!         .expect("failed to write instructions");
//!
//!     emu.reg_write(RegisterARM::R0, 123)
//!         .expect("failed to write to R0");
//!     emu.reg_write(RegisterARM::R5, 1337)
//!         .expect("failed to write to R5");
//!
//!     emu.emu_start(
//!         0x1000,
//!         (0x1000 + arm_code32.len()) as u64,
//!         10 * SECOND_SCALE,
//!         1000,
//!     )
//!     .unwrap();
//!     assert_eq!(emu.reg_read(RegisterARM::R0), Ok(100));
//!     assert_eq!(emu.reg_read(RegisterARM::R5), Ok(1337));
//! }
//! ```

#![no_std]

#[macro_use]
extern crate alloc;

use alloc::{boxed::Box, rc::Rc, vec::Vec};
use core::{cell::UnsafeCell, ffi::c_void, ptr};

#[macro_use]
pub mod unicorn_const;
pub use unicorn_const::*;
pub mod hook; // lets consumers call hooks

#[cfg(test)]
mod tests;

#[derive(Debug)]
pub struct Context {
    context: *mut uc_context,
}

impl Context {
    #[must_use]
    pub const fn is_initialized(&self) -> bool {
        !self.context.is_null()
    }

    pub fn reg_read<T: Into<i32>>(&self, regid: T) -> Result<u64, uc_error> {
        let mut value = 0;
        unsafe { uc_context_reg_read(self.context, regid.into(), (&raw mut value).cast()) }
            .and(Ok(value))
    }

    pub fn reg_write<T: Into<i32>>(&mut self, regid: T, value: u64) -> Result<(), uc_error> {
        unsafe { uc_context_reg_write(self.context, regid.into(), (&raw const value).cast()) }
            .into()
    }
}

impl Drop for Context {
    fn drop(&mut self) {
        if self.is_initialized() {
            unsafe {
                uc_context_free(self.context);
            }
        }
        self.context = ptr::null_mut();
    }
}

pub struct MmioCallbackScope<'a> {
    pub regions: Vec<(u64, u64)>,
    pub read_callback: Option<Box<dyn hook::IsUcHook<'a> + 'a>>,
    pub write_callback: Option<Box<dyn hook::IsUcHook<'a> + 'a>>,
}

impl MmioCallbackScope<'_> {
    fn has_regions(&self) -> bool {
        !self.regions.is_empty()
    }

    fn unmap(&mut self, begin: u64, size: u64) {
        let end: u64 = begin + size as u64;
        self.regions = self
            .regions
            .iter()
            .flat_map(|(b, s)| {
                let e = b + *s as u64;
                if begin > *b {
                    if begin >= e {
                        // The unmapped region is completely after this region
                        vec![(*b, *s)]
                    } else if end >= e {
                        // The unmapped region overlaps with the end of this region
                        vec![(*b, (begin - *b) as u64)]
                    } else {
                        // The unmapped region is in the middle of this region
                        let second_b = end + 1;
                        vec![(*b, (begin - *b) as u64), (second_b, (e - second_b) as u64)]
                    }
                } else if end > *b {
                    if end >= e {
                        // The unmapped region completely contains this region
                        vec![]
                    } else {
                        // The unmapped region overlaps with the start of this region
                        vec![(end, (e - end) as u64)]
                    }
                } else {
                    // The unmapped region is completely before this region
                    vec![(*b, *s)]
                }
            })
            .collect();
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct UcHookId(uc_hook);

pub struct UnicornInner<'a, D> {
    pub handle: *mut uc_engine,
    pub ffi: bool,
    pub arch: Arch,
    /// to keep ownership over the hook for this uc instance's lifetime
    pub hooks: Vec<(UcHookId, Box<dyn hook::IsUcHook<'a> + 'a>)>,
    /// To keep ownership over the mmio callbacks for this uc instance's lifetime
    pub mmio_callbacks: Vec<MmioCallbackScope<'a>>,
    pub data: D,
}

impl<D> Drop for UnicornInner<'_, D> {
    fn drop(&mut self) {
        if !self.ffi && !self.handle.is_null() {
            unsafe { uc_close(self.handle) };
        }
        self.handle = ptr::null_mut();
    }
}

/// A Unicorn emulator instance.
///
/// You could clone this instance cheaply, since it has an `Rc` inside.
pub struct Unicorn<'a, D: 'a> {
    inner: Rc<UnsafeCell<UnicornInner<'a, D>>>,
}

impl<'a> Unicorn<'a, ()> {
    /// Create a new instance of the unicorn engine for the specified architecture
    /// and hardware mode.
    pub fn new(arch: Arch, mode: Mode) -> Result<Unicorn<'a, ()>, uc_error> {
        Self::new_with_data(arch, mode, ())
    }

    /// # Safety
    /// The function has to be called with a valid [`uc_engine`] pointer
    /// that was previously allocated by a call to [`uc_open`].
    /// Calling the function with a non null pointer value that
    /// does not point to a unicorn instance will cause undefined
    /// behavior.
    pub unsafe fn from_handle(handle: *mut uc_engine) -> Result<Unicorn<'a, ()>, uc_error> {
        unsafe { Self::from_handle_with_data(handle, ()) }
    }
}

impl<'a, D> Unicorn<'a, D>
where
    D: 'a,
{
    /// Create a new instance of the unicorn engine for the specified architecture
    /// and hardware mode.
    pub fn new_with_data(arch: Arch, mode: Mode, data: D) -> Result<Unicorn<'a, D>, uc_error> {
        let mut handle = ptr::null_mut();
        unsafe { uc_open(arch, mode, &mut handle) }.and_then(|| {
            Ok(Unicorn {
                inner: Rc::new(UnsafeCell::from(UnicornInner {
                    handle,
                    ffi: false,
                    arch,
                    data,
                    hooks: vec![],
                    mmio_callbacks: vec![],
                })),
            })
        })
    }

    /// # Safety
    /// The function has to be called with a valid [`uc_engine`] pointer
    /// that was previously allocated by a call to [`uc_open`].
    /// Calling the function with a non null pointer value that
    /// does not point to a unicorn instance will cause undefined
    /// behavior.
    pub unsafe fn from_handle_with_data(
        handle: *mut uc_engine,
        data: D,
    ) -> Result<Unicorn<'a, D>, uc_error> {
        if handle.is_null() {
            return Err(uc_error::HANDLE);
        }
        let mut arch = 0;
        let err = unsafe { uc_query(handle, Query::ARCH, &mut arch) };
        if err != uc_error::OK {
            return Err(err);
        }
        Ok(Unicorn {
            inner: Rc::new(UnsafeCell::from(UnicornInner {
                handle,
                ffi: true,
                arch: arch.try_into()?,
                data,
                hooks: vec![],
                mmio_callbacks: vec![],
            })),
        })
    }
}

impl<D> core::fmt::Debug for Unicorn<'_, D> {
    fn fmt(&self, formatter: &mut core::fmt::Formatter) -> core::fmt::Result {
        write!(formatter, "Unicorn {{ uc: {:p} }}", self.get_handle())
    }
}

impl<D> Clone for Unicorn<'_, D> {
    fn clone(&self) -> Self {
        Self {
            inner: Rc::clone(&self.inner),
        }
    }
}

impl<'a, D> Unicorn<'a, D> {
    fn inner(&self) -> &UnicornInner<'a, D> {
        unsafe { self.inner.get().as_ref().unwrap() }
    }

    fn inner_mut(&mut self) -> &mut UnicornInner<'a, D> {
        unsafe { self.inner.get().as_mut().unwrap() }
    }

    /// Return whatever data was passed during initialization.
    ///
    /// For an example, have a look at `utils::init_emu_with_heap` where
    /// a struct is passed which is used for a custom allocator.
    #[must_use]
    pub fn get_data(&self) -> &D {
        &self.inner().data
    }

    /// Return a mutable reference to whatever data was passed during initialization.
    #[must_use]
    pub fn get_data_mut(&mut self) -> &mut D {
        &mut self.inner_mut().data
    }

    /// Return the architecture of the current emulator.
    #[must_use]
    pub fn get_arch(&self) -> Arch {
        self.inner().arch
    }

    /// Return the handle of the current emulator.
    #[must_use]
    pub fn get_handle(&self) -> *mut uc_engine {
        self.inner().handle
    }

    /// Returns a vector with the memory regions that are mapped in the emulator.
    pub fn mem_regions(&self) -> Result<Vec<MemRegion>, uc_error> {
        let mut nb_regions = 0;
        let mut p_regions = ptr::null_mut();
        unsafe { uc_mem_regions(self.get_handle(), &raw mut p_regions, &mut nb_regions) }.and_then(
            || {
                let mut regions = Vec::new();
                for i in 0..nb_regions {
                    regions.push(unsafe { core::mem::transmute_copy(&*p_regions.add(i as usize)) });
                }
                unsafe { uc_free(p_regions.cast()) };
                Ok(regions)
            },
        )
    }

    /// Read a range of bytes from memory at the specified emulated physical address.
    pub fn mem_read(&self, address: u64, buf: &mut [u8]) -> Result<(), uc_error> {
        unsafe {
            uc_mem_read(
                self.get_handle(),
                address,
                buf.as_mut_ptr().cast(),
                buf.len().try_into().unwrap(),
            )
        }
        .into()
    }

    /// Return a range of bytes from memory at the specified emulated physical address as vector.
    pub fn mem_read_as_vec(&self, address: u64, size: usize) -> Result<Vec<u8>, uc_error> {
        let mut buf = vec![0; size];
        unsafe {
            uc_mem_read(
                self.get_handle(),
                address,
                buf.as_mut_ptr().cast(),
                size.try_into().unwrap(),
            )
        }
        .and(Ok(buf))
    }

    /// Read a range of bytes from memory at the specified emulated virtual address.
    pub fn vmem_read(&self, address: u64, prot: Prot, buf: &mut [u8]) -> Result<(), uc_error> {
        unsafe {
            uc_vmem_read(
                self.get_handle(),
                address,
                prot,
                buf.as_mut_ptr() as _,
                buf.len(),
            )
        }
        .into()
    }

    /// Return a range of bytes from memory at the specified emulated virtual address as vector.
    pub fn vmem_read_as_vec(
        &self,
        address: u64,
        prot: Prot,
        size: usize,
    ) -> Result<Vec<u8>, uc_error> {
        let mut buf = vec![0; size];
        unsafe {
            uc_vmem_read(
                self.get_handle(),
                address,
                prot,
                buf.as_mut_ptr() as _,
                buf.len(),
            )
        }
        .and(Ok(buf))
    }

    /// Write the data in `bytes` to the emulated physical address `address`
    pub fn mem_write(&mut self, address: u64, bytes: &[u8]) -> Result<(), uc_error> {
        unsafe {
            uc_mem_write(
                self.get_handle(),
                address,
                bytes.as_ptr().cast(),
                bytes.len().try_into().unwrap(),
            )
        }
        .into()
    }

    /// translate virtual to physical address
    pub fn vmem_translate(&mut self, address: u64, prot: Prot) -> Result<u64, uc_error> {
        let mut physical: u64 = 0;
        let err = unsafe { uc_vmem_translate(self.get_handle(), address, prot, &mut physical) };
        if err != uc_error::OK {
            return Err(err);
        }
        return Ok(physical);
    }

    /// Map an existing memory region in the emulator at the specified address.
    ///
    /// # Safety
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
    pub unsafe fn mem_map_ptr(
        &mut self,
        address: u64,
        size: u64,
        perms: Prot,
        ptr: *mut c_void,
    ) -> Result<(), uc_error> {
        unsafe { uc_mem_map_ptr(self.get_handle(), address, size, perms.0 as _, ptr).into() }
    }

    /// Map a memory region in the emulator at the specified address.
    ///
    /// `address` must be aligned to 4kb or this will return `Error::ARG`.
    /// `size` must be a multiple of 4kb or this will return `Error::ARG`.
    pub fn mem_map(&mut self, address: u64, size: u64, perms: Prot) -> Result<(), uc_error> {
        unsafe { uc_mem_map(self.get_handle(), address, size, perms.0 as _) }.into()
    }

    /// Map in am MMIO region backed by callbacks.
    ///
    /// `address` must be aligned to 4kb or this will return `Error::ARG`.
    /// `size` must be a multiple of 4kb or this will return `Error::ARG`.
    pub fn mmio_map<R, W>(
        &mut self,
        address: u64,
        size: u64,
        read_callback: Option<R>,
        write_callback: Option<W>,
    ) -> Result<(), uc_error>
    where
        R: FnMut(&mut Unicorn<'_, D>, u64, usize) -> u64 + 'a,
        W: FnMut(&mut Unicorn<'_, D>, u64, usize, u64) + 'a,
    {
        let mut read_data = read_callback.map(|c| {
            Box::new(hook::UcHook {
                callback: c,
                uc: Rc::downgrade(&self.inner),
            })
        });
        let mut write_data = write_callback.map(|c| {
            Box::new(hook::UcHook {
                callback: c,
                uc: Rc::downgrade(&self.inner),
            })
        });

        let (read_cb, user_data_read) = read_data.as_mut().map_or((None, ptr::null_mut()), |d| {
            (
                Some(hook::mmio_read_callback_proxy::<D, R> as _),
                core::ptr::from_mut(d.as_mut()).cast(),
            )
        });

        let (write_cb, user_data_write) =
            write_data.as_mut().map_or((None, ptr::null_mut()), |d| {
                (
                    Some(hook::mmio_write_callback_proxy::<D, W> as _),
                    core::ptr::from_mut(d.as_mut()).cast(),
                )
            });

        unsafe {
            uc_mmio_map(
                self.get_handle(),
                address,
                size,
                read_cb,
                user_data_read,
                write_cb,
                user_data_write,
            )
        }
        .and_then(|| {
            let u64_size: u64 = size.try_into().unwrap();
            let rd = read_data.map(|c| c as Box<dyn hook::IsUcHook>);
            let wd = write_data.map(|c| c as Box<dyn hook::IsUcHook>);
            self.inner_mut().mmio_callbacks.push(MmioCallbackScope {
                regions: vec![(address, u64_size)],
                read_callback: rd,
                write_callback: wd,
            });

            Ok(())
        })
    }

    /// Map in a read-only MMIO region backed by a callback.
    ///
    /// `address` must be aligned to 4kb or this will return `Error::ARG`.
    /// `size` must be a multiple of 4kb or this will return `Error::ARG`.
    pub fn mmio_map_ro<F>(&mut self, address: u64, size: u64, callback: F) -> Result<(), uc_error>
    where
        F: FnMut(&mut Unicorn<D>, u64, usize) -> u64 + 'a,
    {
        self.mmio_map(
            address,
            size,
            Some(callback),
            None::<fn(&mut Unicorn<D>, u64, usize, u64)>,
        )
    }

    /// Map in a write-only MMIO region backed by a callback.
    ///
    /// `address` must be aligned to 4kb or this will return `Error::ARG`.
    /// `size` must be a multiple of 4kb or this will return `Error::ARG`.
    pub fn mmio_map_wo<F>(&mut self, address: u64, size: u64, callback: F) -> Result<(), uc_error>
    where
        F: FnMut(&mut Unicorn<D>, u64, usize, u64) + 'a,
    {
        self.mmio_map(
            address,
            size,
            None::<fn(&mut Unicorn<D>, u64, usize) -> u64>,
            Some(callback),
        )
    }

    /// Unmap a memory region.
    ///
    /// `address` must be aligned to 4kb or this will return `Error::ARG`.
    /// `size` must be a multiple of 4kb or this will return `Error::ARG`.
    pub fn mem_unmap(&mut self, address: u64, size: u64) -> Result<(), uc_error> {
        let err = unsafe { uc_mem_unmap(self.get_handle(), address, size) };
        self.mmio_unmap(address, size);
        err.into()
    }

    fn mmio_unmap(&mut self, address: u64, size: u64) {
        for scope in &mut self.inner_mut().mmio_callbacks {
            scope.unmap(address, size);
        }
        self.inner_mut()
            .mmio_callbacks
            .retain(MmioCallbackScope::has_regions);
    }

    /// Set the memory permissions for an existing memory region.
    ///
    /// `address` must be aligned to 4kb or this will return `Error::ARG`.
    /// `size` must be a multiple of 4kb or this will return `Error::ARG`.
    pub fn mem_protect(&mut self, address: u64, size: u64, perms: Prot) -> Result<(), uc_error> {
        unsafe { uc_mem_protect(self.get_handle(), address, size, perms.0 as _) }.into()
    }

    /// Write an unsigned value from a register.
    pub fn reg_write<T: Into<i32>>(&mut self, regid: T, value: u64) -> Result<(), uc_error> {
        unsafe { uc_reg_write(self.get_handle(), regid.into(), (&raw const value).cast()) }.into()
    }

    /// Write values into batch of registers
    pub fn reg_write_batch<T>(
        &self,
        regids: &[T],
        values: &[u64],
        count: i32,
    ) -> Result<(), uc_error>
    where
        T: Copy + Into<i32>,
    {
        let mut values_ptrs = vec![core::ptr::null::<u64>(); count as usize];
        let mut regids = regids
            .iter()
            .map(|regid| (*regid).into())
            .collect::<Vec<i32>>();
        for i in 0..values.len() {
            values_ptrs[i] = &raw const values[i];
        }
        unsafe {
            uc_reg_write_batch(
                self.get_handle(),
                regids.as_mut_ptr(),
                values_ptrs.as_ptr().cast::<*mut c_void>(),
                count,
            )
        }
        .into()
    }

    /// Write variable sized values into registers.
    ///
    /// The user has to make sure that the buffer length matches the register size.
    /// This adds support for registers >64 bit (GDTR/IDTR, XMM, YMM, ZMM (x86); Q, V (arm64)).
    pub fn reg_write_long<T: Into<i32>>(&self, regid: T, value: &[u8]) -> Result<(), uc_error> {
        unsafe { uc_reg_write(self.get_handle(), regid.into(), value.as_ptr().cast()) }.into()
    }

    /// Read an unsigned value from a register.
    ///
    /// Not to be used with registers larger than 64 bit.
    pub fn reg_read<T: Into<i32>>(&self, regid: T) -> Result<u64, uc_error> {
        let mut value = 0;
        unsafe { uc_reg_read(self.get_handle(), regid.into(), (&raw mut value).cast()) }
            .and(Ok(value))
    }

    /// Read batch of registers
    ///
    /// Not to be used with registers larger than 64 bit
    pub fn reg_read_batch<T>(&self, regids: &mut [T], count: i32) -> Result<Vec<u64>, uc_error>
    where
        T: Copy + Into<i32>,
    {
        unsafe {
            let mut addrs_vec = vec![0u64; count as usize];
            let addrs = addrs_vec.as_mut_slice();
            let mut regids = regids
                .iter()
                .map(|regid| (*regid).into())
                .collect::<Vec<i32>>();
            for i in 0..count {
                addrs[i as usize] = &raw mut addrs[i as usize] as u64;
            }
            let res = uc_reg_read_batch(
                self.get_handle(),
                regids.as_mut_ptr(),
                addrs.as_mut_ptr().cast::<*mut c_void>(),
                count,
            );
            match res {
                uc_error::OK => Ok(addrs_vec),
                _ => Err(res),
            }
        }
    }

    /// Read 128, 256 or 512 bit register value into heap allocated byte array.
    ///
    /// This adds safe support for registers >64 bit (GDTR/IDTR, XMM, YMM, ZMM, ST (x86); Q, V
    /// (arm64)).
    pub fn reg_read_long<T: Into<i32>>(&self, regid: T) -> Result<Box<[u8]>, uc_error> {
        let curr_reg_id = regid.into();
        let curr_arch = self.get_arch();

        let value_size = match curr_arch {
            #[cfg(feature = "arch_x86")]
            Arch::X86 => Self::value_size_x86(curr_reg_id)?,
            #[cfg(feature = "arch_arm")]
            Arch::ARM64 => Self::value_size_arm64(curr_reg_id)?,
            _ => Err(uc_error::ARCH)?,
        };
        let mut value = vec![0; value_size];
        unsafe { uc_reg_read(self.get_handle(), curr_reg_id, value.as_mut_ptr().cast()) }
            .and_then(|| Ok(value.into_boxed_slice()))
    }

    /// Read ARM Coprocessor register
    pub fn reg_read_arm_coproc(&self, reg: &mut RegisterARMCP) -> Result<(), uc_error> {
        let curr_arch = self.get_arch();
        match curr_arch {
            #[cfg(feature = "arch_arm")]
            Arch::ARM => {}
            _ => return Err(uc_error::ARCH),
        }

        unsafe {
            uc_reg_read(
                self.get_handle(),
                RegisterARM::CP_REG.into(),
                core::ptr::from_mut(reg).cast(),
            )
        }
        .into()
    }

    /// Write ARM Coprocessor register
    pub fn reg_write_arm_coproc(&mut self, reg: &RegisterARMCP) -> Result<(), uc_error> {
        let curr_arch = self.get_arch();
        match curr_arch {
            #[cfg(feature = "arch_arm")]
            Arch::ARM => {}
            _ => return Err(uc_error::ARCH),
        }

        unsafe {
            uc_reg_write(
                self.get_handle(),
                RegisterARM::CP_REG.into(),
                core::ptr::from_ref(reg).cast(),
            )
        }
        .into()
    }

    /// Read ARM64 Coprocessor register
    pub fn reg_read_arm64_coproc(&self, reg: &mut RegisterARM64CP) -> Result<(), uc_error> {
        let curr_arch = self.get_arch();
        match curr_arch {
            #[cfg(feature = "arch_aarch64")]
            Arch::ARM64 => {}
            _ => return Err(uc_error::ARCH),
        }

        unsafe {
            uc_reg_read(
                self.get_handle(),
                RegisterARM64::CP_REG.into(),
                core::ptr::from_mut(reg).cast(),
            )
        }
        .and(Ok(()))
    }

    /// Write ARM64 Coprocessor register
    pub fn reg_write_arm64_coproc(&mut self, reg: &RegisterARM64CP) -> Result<(), uc_error> {
        let curr_arch = self.get_arch();
        match curr_arch {
            #[cfg(feature = "arch_aarch64")]
            Arch::ARM64 => {}
            _ => return Err(uc_error::ARCH),
        }

        unsafe {
            uc_reg_write(
                self.get_handle(),
                RegisterARM64::CP_REG.into(),
                core::ptr::from_ref(reg).cast(),
            )
        }
        .and(Ok(()))
    }

    #[cfg(feature = "arch_arm")]
    fn value_size_arm64(curr_reg_id: i32) -> Result<usize, uc_error> {
        match curr_reg_id {
            r if (RegisterARM64::Q0 as i32..=RegisterARM64::Q31 as i32).contains(&r)
                || (RegisterARM64::V0 as i32..=RegisterARM64::V31 as i32).contains(&r) =>
            {
                Ok(16)
            }
            _ => Err(uc_error::ARG),
        }
    }

    #[cfg(feature = "arch_x86")]
    fn value_size_x86(curr_reg_id: i32) -> Result<usize, uc_error> {
        match curr_reg_id {
            r if (RegisterX86::XMM0 as i32..=RegisterX86::XMM31 as i32).contains(&r) => Ok(16),
            r if (RegisterX86::YMM0 as i32..=RegisterX86::YMM31 as i32).contains(&r) => Ok(32),
            r if (RegisterX86::ZMM0 as i32..=RegisterX86::ZMM31 as i32).contains(&r) => Ok(64),
            r if r == RegisterX86::GDTR as i32
                || r == RegisterX86::IDTR as i32
                || (RegisterX86::ST0 as i32..=RegisterX86::ST7 as i32).contains(&r) =>
            {
                Ok(10)
            }
            _ => Err(uc_error::ARG),
        }
    }

    /// Read a signed 32-bit value from a register.
    pub fn reg_read_i32<T: Into<i32>>(&self, regid: T) -> Result<i32, uc_error> {
        let mut value = 0;
        unsafe { uc_reg_read(self.get_handle(), regid.into(), (&raw mut value).cast()) }
            .and(Ok(value))
    }

    /// Add a code hook.
    pub fn add_code_hook<F>(
        &mut self,
        begin: u64,
        end: u64,
        callback: F,
    ) -> Result<UcHookId, uc_error>
    where
        F: FnMut(&mut Unicorn<D>, u64, u32) + 'a,
    {
        let mut hook_id = 0;
        let mut user_data = Box::new(hook::UcHook {
            callback,
            uc: Rc::downgrade(&self.inner),
        });

        unsafe {
            uc_hook_add(
                self.get_handle(),
                (&raw mut hook_id).cast(),
                HookType::CODE.0 as i32,
                hook::code_hook_proxy::<D, F> as _,
                core::ptr::from_mut(user_data.as_mut()).cast(),
                begin,
                end,
            )
        }
        .and_then(|| {
            let hook_id = UcHookId(hook_id);
            self.inner_mut().hooks.push((hook_id, user_data));
            Ok(hook_id)
        })
    }

    /// Add a block hook.
    pub fn add_block_hook<F>(
        &mut self,
        begin: u64,
        end: u64,
        callback: F,
    ) -> Result<UcHookId, uc_error>
    where
        F: FnMut(&mut Unicorn<D>, u64, u32) + 'a,
    {
        let mut hook_id = 0;
        let mut user_data = Box::new(hook::UcHook {
            callback,
            uc: Rc::downgrade(&self.inner),
        });

        unsafe {
            uc_hook_add(
                self.get_handle(),
                (&raw mut hook_id).cast(),
                HookType::BLOCK.0 as i32,
                hook::block_hook_proxy::<D, F> as _,
                core::ptr::from_mut(user_data.as_mut()).cast(),
                begin,
                end,
            )
        }
        .and_then(|| {
            let hook_id = UcHookId(hook_id);
            self.inner_mut().hooks.push((hook_id, user_data));
            Ok(hook_id)
        })
    }

    /// Add a memory hook.
    pub fn add_mem_hook<F>(
        &mut self,
        hook_type: HookType,
        begin: u64,
        end: u64,
        callback: F,
    ) -> Result<UcHookId, uc_error>
    where
        F: FnMut(&mut Unicorn<D>, MemType, u64, usize, i64) -> bool + 'a,
    {
        if hook_type & (HookType::MEM_ALL | HookType::MEM_READ_AFTER) != hook_type {
            return Err(uc_error::ARG);
        }

        let mut hook_id = 0;
        let mut user_data = Box::new(hook::UcHook {
            callback,
            uc: Rc::downgrade(&self.inner),
        });

        unsafe {
            uc_hook_add(
                self.get_handle(),
                (&raw mut hook_id).cast(),
                hook_type.0 as i32,
                hook::mem_hook_proxy::<D, F> as _,
                core::ptr::from_mut(user_data.as_mut()).cast(),
                begin,
                end,
            )
        }
        .and_then(|| {
            let hook_id = UcHookId(hook_id);
            self.inner_mut().hooks.push((hook_id, user_data));
            Ok(hook_id)
        })
    }

    /// Add an interrupt hook.
    pub fn add_intr_hook<F>(&mut self, callback: F) -> Result<UcHookId, uc_error>
    where
        F: FnMut(&mut Unicorn<D>, u32) + 'a,
    {
        let mut hook_id = 0;
        let mut user_data = Box::new(hook::UcHook {
            callback,
            uc: Rc::downgrade(&self.inner),
        });

        unsafe {
            uc_hook_add(
                self.get_handle(),
                (&raw mut hook_id).cast(),
                HookType::INTR.0 as i32,
                hook::intr_hook_proxy::<D, F> as _,
                core::ptr::from_mut(user_data.as_mut()).cast(),
                0,
                0,
            )
        }
        .and_then(|| {
            let hook_id = UcHookId(hook_id);
            self.inner_mut().hooks.push((hook_id, user_data));
            Ok(hook_id)
        })
    }

    /// Add hook for invalid instructions
    pub fn add_insn_invalid_hook<F>(&mut self, callback: F) -> Result<UcHookId, uc_error>
    where
        F: FnMut(&mut Unicorn<D>) -> bool + 'a,
    {
        let mut hook_id = 0;
        let mut user_data = Box::new(hook::UcHook {
            callback,
            uc: Rc::downgrade(&self.inner),
        });

        unsafe {
            uc_hook_add(
                self.get_handle(),
                (&raw mut hook_id).cast(),
                HookType::INSN_INVALID.0 as i32,
                hook::insn_invalid_hook_proxy::<D, F> as _,
                core::ptr::from_mut(user_data.as_mut()).cast(),
                0,
                0,
            )
        }
        .and_then(|| {
            let hook_id = UcHookId(hook_id);
            self.inner_mut().hooks.push((hook_id, user_data));
            Ok(hook_id)
        })
    }

    /// Add hook for x86 IN instruction.
    #[cfg(feature = "arch_x86")]
    pub fn add_insn_in_hook<F>(&mut self, callback: F) -> Result<UcHookId, uc_error>
    where
        F: FnMut(&mut Unicorn<D>, u32, usize) -> u32 + 'a,
    {
        let mut hook_id = 0;
        let mut user_data = Box::new(hook::UcHook {
            callback,
            uc: Rc::downgrade(&self.inner),
        });

        unsafe {
            uc_hook_add(
                self.get_handle(),
                (&raw mut hook_id).cast(),
                HookType::INSN.0 as i32,
                hook::insn_in_hook_proxy::<D, F> as _,
                core::ptr::from_mut(user_data.as_mut()).cast(),
                0,
                0,
                X86Insn::IN,
            )
        }
        .and_then(|| {
            let hook_id = UcHookId(hook_id);
            self.inner_mut().hooks.push((hook_id, user_data));
            Ok(hook_id)
        })
    }

    /// Add hook for x86 OUT instruction.
    #[cfg(feature = "arch_x86")]
    pub fn add_insn_out_hook<F>(&mut self, callback: F) -> Result<UcHookId, uc_error>
    where
        F: FnMut(&mut Unicorn<D>, u32, usize, u32) + 'a,
    {
        let mut hook_id = 0;
        let mut user_data = Box::new(hook::UcHook {
            callback,
            uc: Rc::downgrade(&self.inner),
        });

        unsafe {
            uc_hook_add(
                self.get_handle(),
                (&raw mut hook_id).cast(),
                HookType::INSN.0 as i32,
                hook::insn_out_hook_proxy::<D, F> as _,
                core::ptr::from_mut(user_data.as_mut()).cast(),
                0,
                0,
                X86Insn::OUT,
            )
        }
        .and_then(|| {
            let hook_id = UcHookId(hook_id);
            self.inner_mut().hooks.push((hook_id, user_data));
            Ok(hook_id)
        })
    }

    /// Add hook for x86 SYSCALL or SYSENTER.
    #[cfg(feature = "arch_x86")]
    pub fn add_insn_sys_hook<F>(
        &mut self,
        insn_type: X86Insn,
        begin: u64,
        end: u64,
        callback: F,
    ) -> Result<UcHookId, uc_error>
    where
        F: FnMut(&mut Unicorn<D>) + 'a,
    {
        let mut hook_id = 0;
        let mut user_data = Box::new(hook::UcHook {
            callback,
            uc: Rc::downgrade(&self.inner),
        });

        unsafe {
            uc_hook_add(
                self.get_handle(),
                (&raw mut hook_id).cast(),
                HookType::INSN.0 as i32,
                hook::insn_sys_hook_proxy::<D, F> as _,
                core::ptr::from_mut(user_data.as_mut()).cast(),
                begin,
                end,
                insn_type,
            )
        }
        .and_then(|| {
            let hook_id = UcHookId(hook_id);
            self.inner_mut().hooks.push((hook_id, user_data));
            Ok(hook_id)
        })
    }

    /// Add hook for ARM MRS/MSR/SYS/SYSL instructions.
    ///
    /// If the callback returns true, the read/write to system registers would be skipped (even
    /// though that may cause exceptions!). Note one callback per instruction is allowed.
    #[cfg(feature = "arch_aarch64")]
    pub fn add_insn_sys_hook_arm64<F>(
        &mut self,
        insn_type: Arm64Insn,
        begin: u64,
        end: u64,
        callback: F,
    ) -> Result<UcHookId, uc_error>
    where
        F: FnMut(&mut Unicorn<D>, RegisterARM64, &RegisterARM64CP) -> bool + 'a,
    {
        let mut hook_id = 0;
        let mut user_data = Box::new(hook::UcHook {
            callback,
            uc: Rc::downgrade(&self.inner),
        });

        unsafe {
            uc_hook_add(
                self.get_handle(),
                (&raw mut hook_id).cast(),
                HookType::INSN.0 as i32,
                hook::insn_sys_hook_proxy_arm64::<D, F> as _,
                core::ptr::from_mut(user_data.as_mut()).cast(),
                begin,
                end,
                insn_type,
            )
        }
        .and_then(|| {
            let hook_id = UcHookId(hook_id);
            self.inner_mut().hooks.push((hook_id, user_data));
            Ok(hook_id)
        })
    }

    pub fn add_tlb_hook<F>(
        &mut self,
        begin: u64,
        end: u64,
        callback: F,
    ) -> Result<UcHookId, uc_error>
    where
        F: FnMut(&mut Unicorn<D>, u64, MemType) -> Option<TlbEntry> + 'a,
    {
        let mut hook_id = 0;
        let mut user_data = Box::new(hook::UcHook {
            callback,
            uc: Rc::downgrade(&self.inner),
        });

        unsafe {
            uc_hook_add(
                self.get_handle(),
                (&raw mut hook_id).cast(),
                HookType::TLB_FILL.0 as i32,
                hook::tlb_lookup_hook_proxy::<D, F> as _,
                core::ptr::from_mut(user_data.as_mut()).cast(),
                begin,
                end,
            )
        }
        .and_then(|| {
            let hook_id = UcHookId(hook_id);
            self.inner_mut().hooks.push((hook_id, user_data));
            Ok(hook_id)
        })
    }

    pub fn add_tcg_hook<F>(
        &mut self,
        code: TcgOpCode,
        flag: TcgOpFlag,
        begin: u64,
        end: u64,
        callback: F,
    ) -> Result<UcHookId, uc_error>
    where
        F: FnMut(&mut Unicorn<D>, u64, u64, u64, usize) + 'a,
    {
        let mut hook_id = 0;
        let mut user_data = Box::new(hook::UcHook {
            callback,
            uc: Rc::downgrade(&self.inner),
        });

        unsafe {
            uc_hook_add(
                self.get_handle(),
                (&raw mut hook_id).cast(),
                HookType::TCG_OPCODE.0 as i32,
                hook::tcg_proxy::<D, F> as _,
                core::ptr::from_mut(user_data.as_mut()).cast(),
                begin,
                end,
                code as i32,
                flag.0 as i32,
            )
            .and_then(|| {
                let hook_id = UcHookId(hook_id);
                self.inner_mut().hooks.push((hook_id, user_data));
                Ok(hook_id)
            })
        }
    }

    /// Add hook for edge generated event.
    ///
    /// Callback parameters: (uc, cur_tb, prev_tb)
    pub fn add_edge_gen_hook<F>(
        &mut self,
        begin: u64,
        end: u64,
        callback: F,
    ) -> Result<UcHookId, uc_error>
    where
        F: FnMut(&mut Unicorn<D>, &mut TranslationBlock, &mut TranslationBlock) + 'a,
    {
        let mut hook_id = 0;
        let mut user_data = Box::new(hook::UcHook {
            callback,
            uc: Rc::downgrade(&self.inner),
        });

        unsafe {
            uc_hook_add(
                self.get_handle(),
                (&raw mut hook_id).cast(),
                HookType::EDGE_GENERATED.0 as i32,
                hook::edge_gen_hook_proxy::<D, F> as _,
                core::ptr::from_mut(user_data.as_mut()).cast(),
                begin,
                end,
            )
        }
        .and_then(|| {
            let hook_id = UcHookId(hook_id);
            self.inner_mut().hooks.push((hook_id, user_data));
            Ok(hook_id)
        })
    }

    /// Remove a hook.
    ///
    /// `hook_id` is the value returned by `add_*_hook` functions.
    pub fn remove_hook(&mut self, hook_id: UcHookId) -> Result<(), uc_error> {
        // drop the hook
        let inner = self.inner_mut();
        inner.hooks.retain(|(id, _)| id != &hook_id);

        unsafe { uc_hook_del(inner.handle, hook_id.0) }.into()
    }

    /// Allocate and return an empty Unicorn context.
    ///
    /// To be populated via `context_save`.
    pub fn context_alloc(&self) -> Result<Context, uc_error> {
        let mut empty_context = ptr::null_mut();
        unsafe { uc_context_alloc(self.get_handle(), &raw mut empty_context) }.and(Ok(Context {
            context: empty_context,
        }))
    }

    /// Save current Unicorn context to previously allocated Context struct.
    pub fn context_save(&self, context: &mut Context) -> Result<(), uc_error> {
        unsafe { uc_context_save(self.get_handle(), context.context) }.into()
    }

    /// Allocate and return a Context struct initialized with the current CPU context.
    ///
    /// This can be used for fast rollbacks with `context_restore`.
    /// In case of many non-concurrent context saves, use `context_alloc` and *_save
    /// individually to avoid unnecessary allocations.
    pub fn context_init(&self) -> Result<Context, uc_error> {
        let mut new_context = ptr::null_mut();
        unsafe {
            uc_context_alloc(self.get_handle(), &raw mut new_context).and_then(|| {
                uc_context_save(self.get_handle(), new_context)
                    .and(Ok(Context {
                        context: new_context,
                    }))
                    .inspect_err(|_| {
                        uc_context_free(new_context);
                    })
            })
        }
    }

    /// Restore a previously saved Unicorn context.
    ///
    /// Perform a quick rollback of the CPU context, including registers and some
    /// internal metadata. Contexts may not be shared across engine instances with
    /// differing arches or modes. Memory has to be restored manually, if needed.
    pub fn context_restore(&self, context: &Context) -> Result<(), uc_error> {
        unsafe { uc_context_restore(self.get_handle(), context.context) }.into()
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
        unsafe { uc_emu_start(self.get_handle(), begin, until, timeout, count as _) }.into()
    }

    /// Stop the emulation.
    ///
    /// This is usually called from callback function in hooks.
    /// NOTE: For now, this will stop the execution only after the current block.
    pub fn emu_stop(&mut self) -> Result<(), uc_error> {
        unsafe { uc_emu_stop(self.get_handle()).into() }
    }

    /// Query the internal status of the engine.
    ///
    /// supported: `MODE`, `PAGE_SIZE`, `ARCH`
    pub fn query(&self, query: Query) -> Result<usize, uc_error> {
        let mut result = 0;
        unsafe { uc_query(self.get_handle(), query, &mut result) }.and(Ok(result))
    }

    /// Get the `i32` register value for the program counter for the specified architecture.
    ///
    /// If an architecture is not compiled in, this function will return `uc_error::ARCH`.
    const fn arch_to_pc_register(arch: Arch, mode: Mode) -> Result<i32, uc_error> {
        match arch {
            #[cfg(feature = "arch_x86")]
            Arch::X86 => match mode {
                Mode::MODE_16 => Ok(RegisterX86::IP as _),
                Mode::MODE_32 => Ok(RegisterX86::EIP as _),
                Mode::MODE_64 => Ok(RegisterX86::RIP as _),
                _ => Err(uc_error::ARCH),
            },
            #[cfg(feature = "arch_arm")]
            Arch::ARM => Ok(RegisterARM::PC as i32),
            #[cfg(feature = "arch_arm")]
            Arch::ARM64 => Ok(RegisterARM64::PC as i32),
            #[cfg(feature = "arch_mips")]
            Arch::MIPS => Ok(RegisterMIPS::PC as i32),
            #[cfg(feature = "arch_sparc")]
            Arch::SPARC => Ok(RegisterSPARC::PC as i32),
            #[cfg(feature = "arch_m68k")]
            Arch::M68K => Ok(RegisterM68K::PC as i32),
            #[cfg(feature = "arch_ppc")]
            Arch::PPC => Ok(RegisterPPC::PC as i32),
            #[cfg(feature = "arch_riscv")]
            Arch::RISCV => Ok(RegisterRISCV::PC as i32),
            #[cfg(feature = "arch_s390x")]
            Arch::S390X => Ok(RegisterS390X::PC as i32),
            #[cfg(feature = "arch_tricore")]
            Arch::TRICORE => Ok(RegisterTRICORE::PC as i32),
            // returns `uc_error::ARCH` for `Arch::MAX`, and any
            // other architecture that are not compiled in
            _ => Err(uc_error::ARCH),
        }
    }

    /// Gets the current program counter for this `unicorn` instance.
    pub fn pc_read(&self) -> Result<u64, uc_error> {
        let arch = self.get_arch();
        let mode = self.ctl_get_mode()?;

        self.reg_read(Self::arch_to_pc_register(arch, mode)?)
    }

    /// Sets the program counter for this `unicorn` instance.
    pub fn set_pc(&mut self, value: u64) -> Result<(), uc_error> {
        let arch = self.get_arch();
        let mode = self.ctl_get_mode()?;

        self.reg_write(Self::arch_to_pc_register(arch, mode)?, value)
    }

    pub fn ctl_get_mode(&self) -> Result<Mode, uc_error> {
        let mut result = 0;
        unsafe {
            uc_ctl(
                self.get_handle(),
                UC_CTL_READ!(ControlType::UC_MODE),
                &mut result,
            )
        }
        .and_then(|| Ok(Mode::try_from(result)))?
    }

    pub fn ctl_get_page_size(&self) -> Result<u32, uc_error> {
        let mut result = 0;
        unsafe {
            uc_ctl(
                self.get_handle(),
                UC_CTL_READ!(ControlType::UC_PAGE_SIZE),
                &mut result,
            )
        }
        .and_then(|| Ok(result))
    }

    pub fn ctl_set_page_size(&mut self, page_size: u32) -> Result<(), uc_error> {
        unsafe {
            uc_ctl(
                self.get_handle(),
                UC_CTL_WRITE!(ControlType::UC_PAGE_SIZE),
                page_size,
            )
        }
        .into()
    }

    pub fn ctl_get_arch(&self) -> Result<Arch, uc_error> {
        let mut result = 0;
        unsafe {
            uc_ctl(
                self.get_handle(),
                UC_CTL_READ!(ControlType::UC_ARCH),
                &mut result,
            )
        }
        .and_then(|| Arch::try_from(result as usize))
    }

    pub fn ctl_get_timeout(&self) -> Result<u64, uc_error> {
        let mut result = 0;
        unsafe {
            uc_ctl(
                self.get_handle(),
                UC_CTL_READ!(ControlType::UC_TIMEOUT),
                &mut result,
            )
        }
        .and(Ok(result))
    }

    pub fn ctl_exits_enable(&mut self) -> Result<(), uc_error> {
        unsafe {
            uc_ctl(
                self.get_handle(),
                UC_CTL_WRITE!(ControlType::UC_USE_EXITS),
                1,
            )
        }
        .into()
    }

    pub fn ctl_exits_disable(&mut self) -> Result<(), uc_error> {
        unsafe {
            uc_ctl(
                self.get_handle(),
                UC_CTL_WRITE!(ControlType::UC_USE_EXITS),
                0,
            )
        }
        .into()
    }

    pub fn ctl_get_exits_count(&self) -> Result<usize, uc_error> {
        let mut result = 0;
        unsafe {
            uc_ctl(
                self.get_handle(),
                UC_CTL_READ!(ControlType::UC_EXITS_CNT),
                &mut result,
            )
        }
        .and(Ok(result))
    }

    pub fn ctl_get_exits(&self) -> Result<Vec<u64>, uc_error> {
        let exits_count = self.ctl_get_exits_count()?;
        let mut exits = Vec::with_capacity(exits_count);
        unsafe {
            uc_ctl(
                self.get_handle(),
                UC_CTL_READ!(ControlType::UC_EXITS),
                exits.as_mut_ptr(),
                exits_count,
            )
        }
        .and_then(|| unsafe {
            exits.set_len(exits_count);
            Ok(exits)
        })
    }

    pub fn ctl_set_exits(&mut self, exits: &[u64]) -> Result<(), uc_error> {
        unsafe {
            uc_ctl(
                self.get_handle(),
                UC_CTL_WRITE!(ControlType::UC_EXITS),
                exits.as_ptr(),
                exits.len(),
            )
        }
        .into()
    }

    pub fn ctl_get_cpu_model(&self) -> Result<i32, uc_error> {
        let mut result = 0;
        unsafe {
            uc_ctl(
                self.get_handle(),
                UC_CTL_READ!(ControlType::CPU_MODEL),
                &mut result,
            )
        }
        .and(Ok(result))
    }

    pub fn ctl_set_cpu_model(&mut self, cpu_model: i32) -> Result<(), uc_error> {
        unsafe {
            uc_ctl(
                self.get_handle(),
                UC_CTL_WRITE!(ControlType::CPU_MODEL),
                cpu_model,
            )
        }
        .into()
    }

    pub fn ctl_remove_cache(&mut self, address: u64, end: u64) -> Result<(), uc_error> {
        unsafe {
            uc_ctl(
                self.get_handle(),
                UC_CTL_WRITE!(ControlType::TB_REMOVE_CACHE),
                address,
                end,
            )
        }
        .into()
    }

    pub fn ctl_request_cache(
        &self,
        address: u64,
        tb: Option<&mut TranslationBlock>,
    ) -> Result<(), uc_error> {
        let tb_ptr = tb.map_or(ptr::null_mut(), core::ptr::from_mut);
        unsafe {
            uc_ctl(
                self.get_handle(),
                UC_CTL_READ_WRITE!(ControlType::TB_REQUEST_CACHE),
                address,
                tb_ptr,
            )
        }
        .into()
    }

    pub fn ctl_flush_tb(&mut self) -> Result<(), uc_error> {
        unsafe { uc_ctl(self.get_handle(), UC_CTL_WRITE!(ControlType::TB_FLUSH)) }.into()
    }

    pub fn ctl_flush_tlb(&mut self) -> Result<(), uc_error> {
        unsafe { uc_ctl(self.get_handle(), UC_CTL_WRITE!(ControlType::TLB_FLUSH)) }.into()
    }

    pub fn ctl_set_context_mode(&mut self, mode: ContextMode) -> Result<(), uc_error> {
        unsafe {
            uc_ctl(
                self.get_handle(),
                UC_CTL_WRITE!(ControlType::CONTEXT_MODE),
                mode,
            )
        }
        .into()
    }

    pub fn ctl_set_tlb_type(&mut self, t: TlbType) -> Result<(), uc_error> {
        unsafe {
            uc_ctl(
                self.get_handle(),
                UC_CTL_WRITE!(ControlType::TLB_TYPE),
                t as i32,
            )
        }
        .into()
    }
}
