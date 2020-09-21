#![allow(non_snake_case)]
extern crate libc;

use capstone::prelude::*;
use super::arm::RegisterARM;
use super::arm64::RegisterARM64;
use super::x86::RegisterX86;
use super::sparc::RegisterSPARC;
use super::mips::RegisterMIPS;
use super::m68k::RegisterM68K;
use super::{Permission, Mode, Arch, HookType, MemType, uc_error};
use std::ptr;
use std::cell::RefCell;
use std::collections::HashMap;
use libc::{mmap, c_void, size_t, MAP_ANON, MAP_PRIVATE,PROT_READ,PROT_WRITE};


#[derive(Debug)]
pub struct Chunk {
    pub offset: u64,
    pub len: size_t,
    pub freed: bool,
}


#[derive(Debug)]
pub struct Heap {
    pub real_base: *mut c_void,
    pub uc_base: u64,
    pub len: size_t,
    pub grow_dynamically: bool,
    pub chunk_map: HashMap<u64, Chunk>,
    pub top: u64,
    pub unalloc_hook: super::ffi::uc_hook,
}


/// Hooks (parts of the) code segment to display register info and the current instruction.
pub fn add_debug_prints_ARM<D>(uc: &mut super::UnicornHandle<D>, code_start: u64, code_end: u64) {
    let cs_arm: Capstone = Capstone::new()
        .arm()
        .mode(arch::arm::ArchMode::Arm)
        .detail(true)
        .build().expect("failed to create capstone for ARM");

    let cs_thumb: Capstone = Capstone::new()
        .arm()
        .mode(arch::arm::ArchMode::Thumb)
        .detail(true)
        .build().expect("failed to create capstone for thumb");

    let callback = Box::new(move |uc: super::UnicornHandle<D>, addr: u64, size: u32| {        
        let sp = uc.reg_read(RegisterARM::SP as i32).expect("failed to read SP");
        let lr = uc.reg_read(RegisterARM::LR as i32).expect("failed to read LR");
        let r0 = uc.reg_read(RegisterARM::R0 as i32).expect("failed to read r0");
        let r1 = uc.reg_read(RegisterARM::R1 as i32).expect("failed to read r1");
        let r2 = uc.reg_read(RegisterARM::R2 as i32).expect("failed to read r2");
        let r3 = uc.reg_read(RegisterARM::R3 as i32).expect("failed to read r3");
        let r4 = uc.reg_read(RegisterARM::R4 as i32).expect("failed to read r4");
        let r5 = uc.reg_read(RegisterARM::R5 as i32).expect("failed to read r5");
        let r6 = uc.reg_read(RegisterARM::R6 as i32).expect("failed to read r6");
        let r7 = uc.reg_read(RegisterARM::R7 as i32).expect("failed to read r7");
        let r8 = uc.reg_read(RegisterARM::R8 as i32).expect("failed to read r8");
        let r9 = uc.reg_read(RegisterARM::R9 as i32).expect("failed to read r9");
        let r10 = uc.reg_read(RegisterARM::R10 as i32).expect("failed to read r10");
        let r11 = uc.reg_read(RegisterARM::R11 as i32).expect("failed to read r11");
        println!("________________________________________________________________________\n");
        println!("$r0: {:#010x}   $r1: {:#010x}    $r2: {:#010x}    $r3: {:#010x}", r0, r1, r2, r3);
        println!("$r4: {:#010x}   $r5: {:#010x}    $r6: {:#010x}    $r7: {:#010x}", r4, r5, r6, r7);
        println!("$r8: {:#010x}   $r9: {:#010x}   $r10: {:#010x}   $r11: {:#010x}", r8, r9, r10, r11);
        println!("$sp: {:#010x}   $lr: {:#010x}\n", sp, lr);
        
        // decide which mode (ARM/Thumb) to use for disasm
        let cpsr = uc.reg_read(RegisterARM::CPSR as i32).expect("failed to read CPSR");
        let mut buf = vec![0; size as usize];
        uc.mem_read(addr, &mut buf).expect("failed to read opcode from memory");
        let ins = if cpsr & 0x20 != 0 {
            cs_thumb.disasm_all(&buf, size as u64)
        } else {
            cs_arm.disasm_all(&buf, size as u64)
        }.expect(&format!("failed to disasm at addr {:#010x}", addr));
        println!("$pc: {:#010x}", addr);
        println!("{}", ins);
    });

    uc.add_code_hook(code_start, code_end, callback).expect("failed to set debug hook");
}


/// Returns a new Unicorn instance with an initialized heap and active sanitizer. 
/// 
/// Introduces an accessible way of dynamic memory allocation for emulation and helps
/// detecting common memory corruption bugs. 
/// The allocator makes heavy use of Unicorn hooks for sanitization/ crash amplification
/// and thus introduces some overhead.
pub fn init_emu_with_heap(arch: Arch, 
        mut size: u32, 
        base_addr: u64, 
        grow: bool
) -> Result<super::Unicorn<RefCell<Heap>>, uc_error> {
    let heap = RefCell::new(Heap {real_base: 0 as _, 
                                    uc_base: 0, 
                                    len: 0, 
                                    grow_dynamically: false, 
                                    chunk_map: HashMap::new(), 
                                    top: 0, 
                                    unalloc_hook: 0 as _ });

    let mut unicorn = super::Unicorn::new(arch, Mode::LITTLE_ENDIAN, heap)?;
    let mut uc = unicorn.borrow(); // get handle

    // uc memory regions have to be 8 byte aligned
    if size % 8 != 0 {
        size = ((size / 8) + 1) * 8;
    }

    // init heap management struct for later use within unicorn
    let null_ptr = ptr::null_mut();
    unsafe {
        // manually mmap space for heap to know location
        let arena_ptr = mmap(null_ptr, size as usize, PROT_READ | PROT_WRITE, MAP_ANON | MAP_PRIVATE, 0, 0);
        uc.mem_map_ptr(base_addr, size as usize, Permission::READ | Permission::WRITE, arena_ptr)?;
        let h = uc.add_mem_hook(HookType::MEM_VALID, base_addr, base_addr + size as u64, Box::new(heap_unalloc))?;
        let chunks = HashMap::new();
        let heap: &mut Heap = &mut *uc.get_data().borrow_mut();
        heap.real_base = arena_ptr; // heap pointer in process mem
        heap.uc_base = base_addr;
        heap.len = size as usize;
        /* 
        let the heap grow dynamically 
        (ATTENTION: There are no guarantees that the heap segment will be continuous in process mem any more)
        */
        heap.grow_dynamically = grow; 
        heap.chunk_map = chunks;
        heap.top = base_addr; // pointer to top of heap in unicorn mem, increases on allocations
        heap.unalloc_hook = h; // hook ID, needed to rearrange hooks on allocations
    }

    return Ok(unicorn);
}

/// `malloc` for the utils allocator.
/// 
/// Returns a pointer into memory used as heap and applies
/// canary hooks to detect out-of-bounds accesses. 
/// Grows the heap if necessary and if it is configured to, otherwise
/// return WRITE_UNMAPPED if there is no space left.
pub fn uc_alloc(uc: &mut super::UnicornHandle<RefCell<Heap>>, mut size: u64) -> Result<u64, uc_error> {
    // 8 byte aligned
    if size % 8 != 0 {
        size = ((size / 8) + 1) * 8;
    }
    let addr = uc.get_data().borrow_mut().top;
    let mut len = uc.get_data().borrow_mut().len;
    let uc_base = uc.get_data().borrow_mut().uc_base;

    if addr + size >= uc_base + len as u64 {
        if !uc.get_data().borrow_mut().grow_dynamically {
            return Err(uc_error::WRITE_UNMAPPED);
        } else {
            // grow heap
            let mut increase_by = len / 2;
            if increase_by % 8 != 0 {
                increase_by = ((increase_by / 8) + 1) * 8;
            }
            uc.mem_map(uc_base + len as u64, increase_by,  Permission::READ | Permission::WRITE)?;
            uc.get_data().borrow_mut().len += increase_by;
            len = uc.get_data().borrow_mut().len;
        }
    }

    // canary hooks
    uc.add_mem_hook(HookType::MEM_WRITE, addr, addr + 3, Box::new(heap_bo))?;
    uc.add_mem_hook(HookType::MEM_READ,  addr, addr + 3, Box::new(heap_oob))?;
    uc.add_mem_hook(HookType::MEM_WRITE, addr + 4 + size, addr + 4 + size + 3, Box::new(heap_bo))?;
    uc.add_mem_hook(HookType::MEM_READ,  addr + 4 + size, addr + 4 + size + 3, Box::new(heap_oob))?;
    
    // add new chunk
    let curr_offset = addr + 4 - uc_base;
    let curr_chunk = Chunk {offset: curr_offset, len: size as size_t, freed: false};
    uc.get_data().borrow_mut().chunk_map.insert(addr + 4, curr_chunk);
    let new_top = uc.get_data().borrow_mut().top + size + 8; // canary*2
    #[cfg(debug_assertions)]
    println!("[+] New Allocation from {:#010x} to {:#010x} (size: {})", 
        uc.get_data().borrow().top, uc.get_data().borrow().top + size - 1 + 8, size);
    uc.get_data().borrow_mut().top = new_top; 

    // adjust oob hooks
    let old_h = uc.get_data().borrow_mut().unalloc_hook;
    uc.remove_hook(old_h)?;
    let new_h = uc.add_mem_hook(HookType::MEM_VALID, new_top, uc_base + len as u64, Box::new(heap_unalloc))?;
    uc.get_data().borrow_mut().unalloc_hook = new_h;

    return Ok(addr + 4);
}

/// `free` for the utils allocator.
/// 
/// Marks the chunk to be freed to detect double-frees later on
/// and places sanitization hooks over the freed region to detect
/// use-after-frees.
pub fn uc_free(uc: &mut super::UnicornHandle<RefCell<Heap>>, ptr: u64) -> Result<(), uc_error> {
    #[cfg(debug_assertions)]
    println!("[-] Freeing {:#010x}", ptr);

    if ptr != 0x0 {
        #[allow(unused_assignments)]
        let mut chunk_size = 0;
        {
            let mut heap = uc.get_data().borrow_mut();
            let curr_chunk = heap.chunk_map.get_mut(&ptr).expect("failed to find requested chunk on heap");
            chunk_size = curr_chunk.len as u64;
            curr_chunk.freed = true;
        }
        uc.add_mem_hook(HookType::MEM_VALID, ptr, ptr + chunk_size - 1, Box::new(heap_uaf))?;
    }
    return Ok(());
} 


fn heap_unalloc(uc: super::UnicornHandle<RefCell<Heap>>, _mem_type: MemType, addr: u64, _size: usize, _val: i64) {
    let arch = uc.get_arch();
    let reg = match arch {
        Arch::X86 => RegisterX86::RIP as i32,
        Arch::ARM => RegisterARM::PC as i32,
        Arch::ARM64 => RegisterARM64::PC as i32,
        Arch::MIPS => RegisterMIPS::PC as i32,
        Arch::SPARC => RegisterSPARC::PC as i32,
        Arch::M68K => RegisterM68K::PC as i32,
        _ => panic!("Arch not yet supported by unicorn::utils module")
    };
    let pc = uc.reg_read(reg).expect("failed to read pc"); 
    panic!("ERROR: unicorn-rs Sanitizer: Heap out-of-bounds access of unallocated memory on addr {:#0x}, $pc: {:#010x}",
        addr, pc);
}


fn heap_oob(uc: super::UnicornHandle<RefCell<Heap>>, _mem_type: MemType, addr: u64, _size: usize, _val: i64) {
    let arch = uc.get_arch();
    let reg = match arch {
        Arch::X86 => RegisterX86::RIP as i32,
        Arch::ARM => RegisterARM::PC as i32,
        Arch::ARM64 => RegisterARM64::PC as i32,
        Arch::MIPS => RegisterMIPS::PC as i32,
        Arch::SPARC => RegisterSPARC::PC as i32,
        Arch::M68K => RegisterM68K::PC as i32,
        _ => panic!("Arch not yet supported by unicorn::utils module")
    };
    let pc = uc.reg_read(reg).expect("failed to read pc"); 
    panic!("ERROR: unicorn-rs Sanitizer: Heap out-of-bounds read on addr {:#0x}, $pc: {:#010x}", addr, pc);
}


fn heap_bo (uc: super::UnicornHandle<RefCell<Heap>>, _mem_type: MemType, addr: u64, _size: usize, _val: i64) {       
    let arch = uc.get_arch();
    let reg = match arch {
        Arch::X86 => RegisterX86::RIP as i32,
        Arch::ARM => RegisterARM::PC as i32,
        Arch::ARM64 => RegisterARM64::PC as i32,
        Arch::MIPS => RegisterMIPS::PC as i32,
        Arch::SPARC => RegisterSPARC::PC as i32,
        Arch::M68K => RegisterM68K::PC as i32,
        _ => panic!("Arch not yet supported by unicorn::utils module")
    };
    let pc = uc.reg_read(reg).expect("failed to read pc"); 
    panic!("ERROR: unicorn-rs Sanitizer: Heap buffer-overflow on addr {:#0x}, $pc: {:#010x}", addr, pc);
}


fn heap_uaf (uc: super::UnicornHandle<RefCell<Heap>>, _mem_type: MemType, addr: u64, _size: usize, _val: i64) {       
    let arch = uc.get_arch();
    let reg = match arch {
        Arch::X86 => RegisterX86::RIP as i32,
        Arch::ARM => RegisterARM::PC as i32,
        Arch::ARM64 => RegisterARM64::PC as i32,
        Arch::MIPS => RegisterMIPS::PC as i32,
        Arch::SPARC => RegisterSPARC::PC as i32,
        Arch::M68K => RegisterM68K::PC as i32,
        _ => panic!("Arch not yet supported by unicorn::utils module")
    };
    let pc = uc.reg_read(reg).expect("failed to read pc"); 
    panic!("ERROR: unicorn-rs Sanitizer: Heap use-after-free on addr {:#0x}, $pc: {:#010x}", addr, pc);
    
}


pub fn vmmap<D>(uc: &mut super::UnicornHandle<D>) {
    let regions = uc
        .mem_regions()
        .expect("failed to retrieve memory mappings");
    println!("Regions : {}", regions.len());

    for region in &regions {
        println!("{:#010x?}", region);
    }
}
