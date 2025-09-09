use unicorn_engine_sys::{ContextMode, RegisterX86};

use super::*;

#[test]
fn test_map_correct() {
    let mut uc = Unicorn::new(Arch::X86, Mode::MODE_64).unwrap();

    uc.mem_map(0x40000, 0x1000 * 16, Prot::ALL).unwrap(); // [0x40000, 0x50000]
    uc.mem_map(0x60000, 0x1000 * 16, Prot::ALL).unwrap(); // [0x60000, 0x70000]
    uc.mem_map(0x20000, 0x1000 * 16, Prot::ALL).unwrap(); // [0x20000, 0x30000]
    assert_eq!(
        uc.mem_map(0x10000, 0x2000 * 16, Prot::ALL),
        Err(uc_error::MAP)
    );
    assert_eq!(
        uc.mem_map(0x25000, 0x1000 * 16, Prot::ALL),
        Err(uc_error::MAP)
    );
    assert_eq!(
        uc.mem_map(0x35000, 0x1000 * 16, Prot::ALL),
        Err(uc_error::MAP)
    );
    assert_eq!(
        uc.mem_map(0x45000, 0x1000 * 16, Prot::ALL),
        Err(uc_error::MAP)
    );
    assert_eq!(
        uc.mem_map(0x55000, 0x2000 * 16, Prot::ALL),
        Err(uc_error::MAP)
    );
    uc.mem_map(0x35000, 0x5000, Prot::ALL).unwrap();
    uc.mem_map(0x50000, 0x5000, Prot::ALL).unwrap();
}

#[test]
fn test_map_wrapping() {
    let mut uc = Unicorn::new(Arch::X86, Mode::MODE_64).unwrap();
    assert_eq!(
        uc.mem_map((!0 - 0x4000) & !0xfff, 0x8000, Prot::ALL),
        Err(uc_error::ARG)
    );
}

#[test]
fn test_mem_protect() {
    let code = [
        0x01, 0x70, 0x04, // add [eax + 4], esi
    ];

    let mut uc = Unicorn::new(Arch::X86, Mode::MODE_32).unwrap();
    let eax = 0x2000;
    let esi = 0xdeadbeef;

    uc.reg_write(RegisterX86::EAX, eax).unwrap();
    uc.reg_write(RegisterX86::ESI, esi).unwrap();
    uc.mem_map(0x1000, 0x1000, Prot::READ | Prot::EXEC).unwrap();
    uc.mem_map(0x2000, 0x1000, Prot::READ).unwrap();
    uc.mem_protect(0x2000, 0x1000, Prot::READ | Prot::WRITE)
        .unwrap();
    uc.mem_write(0x1000, &code).unwrap();

    uc.emu_start(0x1000, 0x1000 + code.len() as u64, 0, 1)
        .unwrap();

    let mem = u32::from_le_bytes(
        uc.mem_read_as_vec(0x2000 + 4, 4)
            .unwrap()
            .try_into()
            .unwrap(),
    );
    assert_eq!(mem, 0xdeadbeef);
}

#[test]
fn test_splitting_mem_unmap() {
    let mut uc = Unicorn::new(Arch::X86, Mode::MODE_32).unwrap();

    uc.mem_map(0x20000, 0x1000, Prot::NONE).unwrap();
    uc.mem_map(0x21000, 0x2000, Prot::NONE).unwrap();

    uc.mem_unmap(0x21000, 0x1000).unwrap();
}

#[test]
fn test_splitting_mmio_unmap() {
    let mut uc = Unicorn::new(Arch::X86, Mode::MODE_32).unwrap();
    let code = &[
        0x8b, 0x0d, 0x04, 0x30, 0x00, 0x00, // mov ecx, [0x3004] <-- normal read
        0x8b, 0x1d, 0x04, 0x40, 0x00, 0x00, // mov ebx, [0x4004] <-- mmio read
    ];
    let bytes = 0xdeadbeefu32;

    uc.mem_map(0x1000, 0x1000, Prot::ALL).unwrap();
    uc.mem_write(0x1000, code).unwrap();

    uc.mmio_map_ro(0x3000, 0x2000, |_, offset, size| {
        assert_eq!(offset, 4);
        assert_eq!(size, 4);
        0x19260817
    })
    .unwrap();

    // Map a ram area instead
    uc.mem_unmap(0x3000, 0x1000).unwrap();
    uc.mem_map(0x3000, 0x1000, Prot::ALL).unwrap();
    uc.mem_write(0x3004, &bytes.to_le_bytes()).unwrap();

    uc.emu_start(0x1000, 0x1000 + code.len() as u64, 0, 0)
        .unwrap();

    let ecx = uc.reg_read(RegisterX86::ECX).unwrap();
    let ebx = uc.reg_read(RegisterX86::EBX).unwrap();

    assert_eq!(ecx, 0xdeadbeef);
    assert_eq!(ebx, 0x19260817);
}

#[test]
fn test_mem_protect_map_ptr() {
    let mut uc = Unicorn::new(Arch::X86, Mode::MODE_64).unwrap();
    let val = 0x114514u64;
    let mut data1 = vec![0u8; 0x4000];
    let mut data2 = vec![0u8; 0x2000];

    unsafe {
        uc.mem_map_ptr(0x4000, 0x4000, Prot::ALL, data1.as_mut_ptr().cast())
            .unwrap();
    }
    uc.mem_unmap(0x6000, 0x2000).unwrap();
    unsafe {
        uc.mem_map_ptr(0x6000, 0x2000, Prot::ALL, data2.as_mut_ptr().cast())
            .unwrap();
    }

    uc.mem_write(0x6004, &val.to_le_bytes()).unwrap();
    uc.mem_protect(0x6000, 0x1000, Prot::READ).unwrap();
    let mut mem = vec![0u8; 8];
    uc.mem_read(0x6004, &mut mem).unwrap();

    assert_eq!(val.to_le_bytes(), mem.as_slice());
}

#[test]
fn test_map_at_the_end() {
    let mut uc = Unicorn::new(Arch::X86, Mode::MODE_64).unwrap();
    let mem = vec![0xffu8; 0x1000];

    uc.mem_map(0xfffffffffffff000, 0x1000, Prot::ALL).unwrap();
    uc.mem_write(0xfffffffffffff000, &mem).unwrap();

    assert_eq!(
        uc.mem_write(0xffffffffffffff00, &mem),
        Err(uc_error::WRITE_UNMAPPED)
    );
    assert_eq!(uc.mem_write(0, &mem), Err(uc_error::WRITE_UNMAPPED));
}

#[test]
fn test_map_big_memory() {
    let mut uc = Unicorn::new(Arch::X86, Mode::MODE_64).unwrap();
    let requested_size = !(page_size::get() - 1);
    assert_eq!(
        uc.mem_map(0x0, requested_size.try_into().unwrap(), Prot::ALL),
        Err(uc_error::NOMEM)
    );
}

#[test]
fn test_mem_protect_remove_exec() {
    #[rustfmt::skip]
    let code = [
        0x90,       // nop
        0xeb, 0x00, // jmp 3
        0x90,       // nop
    ];

    let mut uc = Unicorn::new_with_data(Arch::X86, Mode::MODE_64, 0).unwrap();

    uc.mem_map(0x1000, 0x1000, Prot::ALL).unwrap();
    uc.mem_map(0x2000, 0x1000, Prot::ALL).unwrap();

    uc.mem_write(0x1000, &code).unwrap();
    uc.add_block_hook(1, 0, |uc, _, _| {
        *uc.get_data_mut() += 1;
        uc.mem_protect(0x2000, 0x1000, Prot::READ).unwrap();
    })
    .unwrap();

    uc.emu_start(0x1000, 0x1000 + code.len() as u64, 0, 0)
        .unwrap();

    assert_eq!(*uc.get_data_mut(), 2);
}

#[test]
fn test_mem_protect_mmio() {
    #[rustfmt::skip]
    let code = [
        0xa1, 0x20, 0x20, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // movabs eax, dword ptr [0x2020]
        0xa3, 0x20, 0x20, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // movabs dword ptr [0x2020], eax
    ];

    let mut uc = Unicorn::new_with_data(Arch::X86, Mode::MODE_64, 0).unwrap();

    uc.mem_map(0x8000, 0x1000, Prot::ALL).unwrap();
    uc.mem_write(0x8000, &code).unwrap();

    uc.mmio_map(
        0x1000,
        0x3000,
        Some(|uc: &mut Unicorn<'_, i32>, addr, _| {
            assert_eq!(addr, 0x20);
            *uc.get_data_mut() += 1;
            0x114514
        }),
        Some(|_: &mut Unicorn<'_, i32>, _addr, _size, _val| {
            panic!("Write callback should not be called");
        }),
    )
    .unwrap();
    uc.mem_protect(0x2000, 0x1000, Prot::READ).unwrap();

    assert_eq!(
        uc.emu_start(0x8000, 0x8000 + code.len() as u64, 0, 0),
        Err(uc_error::WRITE_PROT)
    );
    let eax = uc.reg_read(RegisterX86::RAX).unwrap();

    assert_eq!(*uc.get_data_mut(), 1);
    assert_eq!(eax, 0x114514u64);
}

#[test]
fn test_snapshot() {
    #[rustfmt::skip]
    let code = [
        0xa1, 0x20, 0x20, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // movabs eax, dword ptr [0x2020]
        0xff, 0xc0,                                           // inc eax
        0xa3, 0x20, 0x20, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // movabs dword ptr [0x2020], eax
    ];

    let mut uc = Unicorn::new(Arch::X86, Mode::MODE_64).unwrap();
    let mut c0 = uc.context_alloc().unwrap();
    let mut c1 = uc.context_alloc().unwrap();
    uc.ctl_set_context_mode(ContextMode::MEMORY).unwrap();
    uc.mem_map(0x1000, 0x1000, Prot::ALL).unwrap();
    uc.mem_write(0x1000, &code).unwrap();

    uc.mem_map(0x2000, 0x1000, Prot::ALL).unwrap();
    uc.context_save(&mut c0).unwrap();

    uc.emu_start(0x1000, 0x1000 + code.len() as u64, 0, 0)
        .unwrap();
    let mem = u32::from_le_bytes(uc.mem_read_as_vec(0x2020, 4).unwrap().try_into().unwrap());
    assert_eq!(mem, 1);
    uc.context_save(&mut c1).unwrap();

    uc.emu_start(0x1000, 0x1000 + code.len() as u64, 0, 0)
        .unwrap();
    let mem = u32::from_le_bytes(uc.mem_read_as_vec(0x2020, 4).unwrap().try_into().unwrap());
    assert_eq!(mem, 2);
    uc.context_restore(&c1).unwrap();

    let mem = u32::from_le_bytes(uc.mem_read_as_vec(0x2020, 4).unwrap().try_into().unwrap());
    assert_eq!(mem, 1);
    uc.context_restore(&c0).unwrap();

    let mem = u32::from_le_bytes(uc.mem_read_as_vec(0x2020, 4).unwrap().try_into().unwrap());
    assert_eq!(mem, 0);

    let code_data = uc.mem_read_as_vec(0x1000, 1).unwrap();
    assert_eq!(code_data[0], 0xa1);
}

// static bool test_snapshot_with_vtlb_callback(uc_engine *uc, uint64_t addr,
//                                              uc_mem_type type,
//                                              uc_tlb_entry *result,
//                                              void *user_data)
// {
//     result->paddr = addr - 0x400000000;
//     result->perms = UC_PROT_ALL;
//     return true;
// }
//
// static void test_snapshot_with_vtlb(void)
// {
//     uc_engine *uc;
//     uc_context *c0, *c1;
//     uint32_t mem;
//     uc_hook hook;
//
//     // mov eax, [0x2020]; inc eax; mov [0x2020], eax
//     char code[] = "\xA1\x20\x20\x00\x00\x04\x00\x00\x00\xFF\xC0\xA3\x20\x20\x00"
//                   "\x00\x04\x00\x00\x00";
//
//     OK(uc_open(UC_ARCH_X86, UC_MODE_64, &uc));
//
//     // Allocate contexts
//     OK(uc_context_alloc(uc, &c0));
//     OK(uc_context_alloc(uc, &c1));
//     OK(uc_ctl_context_mode(uc, UC_CTL_CONTEXT_MEMORY));
//
//     OK(uc_ctl_tlb_mode(uc, UC_TLB_VIRTUAL));
//     OK(uc_hook_add(uc, &hook, UC_HOOK_TLB_FILL,
//                    test_snapshot_with_vtlb_callback, NULL, 1, 0));
//
//     // Map physical memory
//     OK(uc_mem_map(uc, 0x1000, 0x1000, UC_PROT_EXEC | UC_PROT_READ));
//     OK(uc_mem_write(uc, 0x1000, code, sizeof(code) - 1));
//     OK(uc_mem_map(uc, 0x2000, 0x1000, UC_PROT_ALL));
//
//     // Initial context save
//     OK(uc_context_save(uc, c0));
//
//     OK(uc_emu_start(uc, 0x400000000 + 0x1000,
//                     0x400000000 + 0x1000 + sizeof(code) - 1, 0, 0));
//     OK(uc_mem_read(uc, 0x2020, &mem, sizeof(mem)));
//     TEST_CHECK(mem == 1);
//     OK(uc_context_save(uc, c1));
//     OK(uc_emu_start(uc, 0x400000000 + 0x1000,
//                     0x400000000 + 0x1000 + sizeof(code) - 1, 0, 0));
//     OK(uc_mem_read(uc, 0x2020, &mem, sizeof(mem)));
//     TEST_CHECK(mem == 2);
//     OK(uc_context_restore(uc, c1));
//     // TODO check mem
//     OK(uc_mem_read(uc, 0x2020, &mem, sizeof(mem)));
//     TEST_CHECK(mem == 1);
//     OK(uc_context_restore(uc, c0));
//     OK(uc_mem_read(uc, 0x2020, &mem, sizeof(mem)));
//     TEST_CHECK(mem == 0);
//     // TODO check mem
//
//     OK(uc_context_free(c0));
//     OK(uc_context_free(c1));
//     OK(uc_close(uc));
// }

#[test]
fn test_snapshot_with_vtlb() {
    #[rustfmt::skip]
    let code = [
        0xa1, 0x20, 0x20, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, // movabs eax, dword ptr [0x2020]
        0xff, 0xc0,                                           // inc eax
        0xa3, 0x20, 0x20, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, // movabs dword ptr [0x2020], eax
    ];

    let mut uc = Unicorn::new(Arch::X86, Mode::MODE_64).unwrap();

    // Allocate contexts
    let mut c0 = uc.context_alloc().unwrap();
    let mut c1 = uc.context_alloc().unwrap();
    uc.ctl_set_context_mode(ContextMode::MEMORY).unwrap();

    uc.ctl_set_tlb_type(TlbType::VIRTUAL).unwrap();
    uc.add_tlb_hook(1, 0, |_, addr, _| {
        Some(TlbEntry {
            paddr: addr - 0x400000000,
            perms: Prot::ALL,
        })
    })
    .unwrap();

    // Map physical memory
    uc.mem_map(0x1000, 0x1000, Prot::EXEC | Prot::READ).unwrap();
    uc.mem_write(0x1000, &code).unwrap();
    uc.mem_map(0x2000, 0x1000, Prot::ALL).unwrap();

    // Initial context save
    uc.context_save(&mut c0).unwrap();

    uc.emu_start(
        0x400000000 + CODE_START,
        0x400000000 + CODE_START + code.len() as u64,
        0,
        0,
    )
    .unwrap();
    let mem = u32::from_le_bytes(uc.mem_read_as_vec(0x2020, 4).unwrap().try_into().unwrap());
    assert_eq!(mem, 1);
    uc.context_save(&mut c1).unwrap();

    uc.emu_start(
        0x400000000 + CODE_START,
        0x400000000 + CODE_START + code.len() as u64,
        0,
        0,
    )
    .unwrap();
    let mem = u32::from_le_bytes(uc.mem_read_as_vec(0x2020, 4).unwrap().try_into().unwrap());
    assert_eq!(mem, 2);

    uc.context_restore(&c1).unwrap();
    let mem = u32::from_le_bytes(uc.mem_read_as_vec(0x2020, 4).unwrap().try_into().unwrap());
    assert_eq!(mem, 1);

    uc.context_restore(&c0).unwrap();
    let mem = u32::from_le_bytes(uc.mem_read_as_vec(0x2020, 4).unwrap().try_into().unwrap());
    assert_eq!(mem, 0);
}

#[test]
fn test_context_snapshot() {
    let mut uc = Unicorn::new(Arch::X86, Mode::MODE_64).unwrap();
    let baseaddr = 0xfffff1000;
    let offset = 0x10;
    let mut tmp = 1u64;

    uc.ctl_set_context_mode(ContextMode::MEMORY | ContextMode::CPU)
        .unwrap();
    uc.mem_map(baseaddr, 0x1000, Prot::ALL).unwrap();
    let mut ctx = uc.context_alloc().unwrap();
    uc.context_save(&mut ctx).unwrap();

    uc.mem_write(baseaddr + offset, &tmp.to_le_bytes()).unwrap();
    tmp = u64::from_le_bytes(
        uc.mem_read_as_vec(baseaddr + offset, 8)
            .unwrap()
            .try_into()
            .unwrap(),
    );
    assert_eq!(tmp, 1);
    uc.context_restore(&ctx).unwrap();
    tmp = u64::from_le_bytes(
        uc.mem_read_as_vec(baseaddr + offset, 8)
            .unwrap()
            .try_into()
            .unwrap(),
    );
    assert_eq!(tmp, 0);

    tmp = 2;
    uc.mem_write(baseaddr + offset, &tmp.to_le_bytes()).unwrap();
    tmp = u64::from_le_bytes(
        uc.mem_read_as_vec(baseaddr + offset, 8)
            .unwrap()
            .try_into()
            .unwrap(),
    );
    assert_eq!(tmp, 2);
    uc.context_restore(&ctx).unwrap();
    tmp = u64::from_le_bytes(
        uc.mem_read_as_vec(baseaddr + offset, 8)
            .unwrap()
            .try_into()
            .unwrap(),
    );
    assert_eq!(tmp, 0);
}

// static void test_snapshot_unmap(void)
// {
//     uc_engine *uc;
//     uc_context *ctx;
//     uint64_t tmp;
//
//     OK(uc_open(UC_ARCH_X86, UC_MODE_64, &uc));
//     OK(uc_ctl_context_mode(uc, UC_CTL_CONTEXT_MEMORY | UC_CTL_CONTEXT_CPU));
//     OK(uc_mem_map(uc, 0x1000, 0x2000, UC_PROT_ALL));
//
//     tmp = 1;
//     OK(uc_mem_write(uc, 0x1000, &tmp, sizeof(tmp)));
//     tmp = 2;
//     OK(uc_mem_write(uc, 0x2000, &tmp, sizeof(tmp)));
//
//     OK(uc_context_alloc(uc, &ctx));
//     OK(uc_context_save(uc, ctx));
//
//     uc_assert_err(UC_ERR_ARG, uc_mem_unmap(uc, 0x1000, 0x1000));
//     OK(uc_mem_unmap(uc, 0x1000, 0x2000));
//     uc_assert_err(UC_ERR_READ_UNMAPPED,
//                   uc_mem_read(uc, 0x1000, &tmp, sizeof(tmp)));
//     uc_assert_err(UC_ERR_READ_UNMAPPED,
//                   uc_mem_read(uc, 0x2000, &tmp, sizeof(tmp)));
//
//     OK(uc_context_restore(uc, ctx));
//     OK(uc_mem_read(uc, 0x1000, &tmp, sizeof(tmp)));
//     TEST_CHECK(tmp == 1);
//     OK(uc_mem_read(uc, 0x2000, &tmp, sizeof(tmp)));
//     TEST_CHECK(tmp == 2);
//
//     OK(uc_context_free(ctx));
//     OK(uc_close(uc));
// }

#[test]
fn test_snapshot_unmap() {
    let mut uc = Unicorn::new(Arch::X86, Mode::MODE_64).unwrap();
    let offset = 0x10;

    uc.ctl_set_context_mode(ContextMode::MEMORY | ContextMode::CPU)
        .unwrap();
    uc.mem_map(0x1000, 0x2000, Prot::ALL).unwrap();

    let mut tmp = 1u64;
    uc.mem_write(0x1000 + offset, &tmp.to_le_bytes()).unwrap();
    tmp = 2;
    uc.mem_write(0x2000 + offset, &tmp.to_le_bytes()).unwrap();

    let mut ctx = uc.context_alloc().unwrap();
    uc.context_save(&mut ctx).unwrap();

    assert_eq!(uc.mem_unmap(0x1000, 0x1000).unwrap_err(), uc_error::ARG);
    uc.mem_unmap(0x1000, 0x2000).unwrap();
    assert_eq!(
        uc.mem_read_as_vec(0x1000 + offset, 8).unwrap_err(),
        uc_error::READ_UNMAPPED,
    );
    assert_eq!(
        uc.mem_read_as_vec(0x2000 + offset, 8).unwrap_err(),
        uc_error::READ_UNMAPPED,
    );

    uc.context_restore(&ctx).unwrap();
    tmp = u64::from_le_bytes(
        uc.mem_read_as_vec(0x1000 + offset, 8)
            .unwrap()
            .try_into()
            .unwrap(),
    );
    assert_eq!(tmp, 1);
    tmp = u64::from_le_bytes(
        uc.mem_read_as_vec(0x2000 + offset, 8)
            .unwrap()
            .try_into()
            .unwrap(),
    );
    assert_eq!(tmp, 2);
}
