use unicorn_engine_sys::{Arm64CpuModel, Arm64Insn, RegisterARM64, RegisterARM64CP};

use super::*;

#[test]
fn test_arm64_until() {
    let code = &[
        0x30, 0x00, 0x80, 0xd2, // mov x16, #1
        0x11, 0x04, 0x80, 0xd2, // mov x17, #0x20
        0x9c, 0x23, 0x00, 0x91, // add x28, x28, 8
    ];

    let mut uc = uc_common_setup(
        Arch::ARM64,
        Mode::ARM,
        Some(Arm64CpuModel::A72 as i32),
        code,
        (),
    );

    let x16 = 0x12341234;
    let x17 = 0x78907890;
    let x28 = 0x12341234;

    uc.reg_write(RegisterARM64::X16, x16).unwrap();
    uc.reg_write(RegisterARM64::X17, x17).unwrap();
    uc.reg_write(RegisterARM64::X28, x28).unwrap();

    uc.emu_start(CODE_START, CODE_START + code.len() as u64, 0, 3)
        .unwrap();

    let x16 = uc.reg_read(RegisterARM64::X16).unwrap();
    let x17 = uc.reg_read(RegisterARM64::X17).unwrap();
    let x28 = uc.reg_read(RegisterARM64::X28).unwrap();
    let pc = uc.reg_read(RegisterARM64::PC).unwrap();

    assert_eq!(x16, 0x1);
    assert_eq!(x17, 0x20);
    assert_eq!(x28, 0x1234123c);
    assert_eq!(pc, CODE_START + code.len() as u64);
}

#[test]
fn test_arm64_code_patching() {
    let code = &[0x00, 0x04, 0x00, 0x11]; // add w0, w0, 0x1
    let mut uc = uc_common_setup(
        Arch::ARM64,
        Mode::ARM,
        Some(Arm64CpuModel::A72 as i32),
        code,
        (),
    );

    let x0 = 0x0;
    uc.reg_write(RegisterARM64::X0, x0).unwrap();

    uc.emu_start(CODE_START, CODE_START + code.len() as u64, 0, 0)
        .unwrap();

    let x0 = uc.reg_read(RegisterARM64::X0).unwrap();
    assert_eq!(x0, 0x1);

    let patch_code = &[0x00, 0xfc, 0x1f, 0x11]; // add w0, w0, 0x7FF
    uc.mem_write(CODE_START, patch_code).unwrap();

    let x0 = 0x0;
    uc.reg_write(RegisterARM64::X0, x0).unwrap();

    uc.emu_start(CODE_START, CODE_START + patch_code.len() as u64, 0, 0)
        .unwrap();

    let x0 = uc.reg_read(RegisterARM64::X0).unwrap();
    assert_ne!(x0, 0x1);
    assert_eq!(x0, 0x7ff);
}

/// Need to flush the cache before running the emulation after patching
#[test]
fn test_arm64_code_patching_count() {
    let code = &[0x00, 0x04, 0x00, 0x11]; // add w0, w0, 0x1
    let mut uc = uc_common_setup(
        Arch::ARM64,
        Mode::ARM,
        Some(Arm64CpuModel::A72 as i32),
        code,
        (),
    );

    let x0 = 0x0;
    uc.reg_write(RegisterARM64::X0, x0).unwrap();

    uc.emu_start(CODE_START, CODE_START + code.len() as u64, 0, 1)
        .unwrap();

    let x0 = uc.reg_read(RegisterARM64::X0).unwrap();
    assert_eq!(x0, 0x1);

    let patch_code = &[0x00, 0xfc, 0x1f, 0x11]; // add w0, w0, 0x7FF
    uc.mem_write(CODE_START, patch_code).unwrap();
    uc.ctl_remove_cache(CODE_START, CODE_START + patch_code.len() as u64)
        .unwrap();

    let x0 = 0x0;
    uc.reg_write(RegisterARM64::X0, x0).unwrap();

    uc.emu_start(CODE_START, CODE_START + patch_code.len() as u64, 0, 1)
        .unwrap();

    let x0 = uc.reg_read(RegisterARM64::X0).unwrap();
    assert_ne!(x0, 0x1);
    assert_eq!(x0, 0x7ff);
}

#[test]
fn test_arm64_v8_pac() {
    let code = &[0x28, 0xfd, 0xea, 0xc8]; // casal x10, x8, [x9]
    let mut uc = uc_common_setup(
        Arch::ARM64,
        Mode::ARM,
        Some(Arm64CpuModel::MAX as i32),
        code,
        (),
    );

    uc.mem_map(0x40000, 0x1000, Prot::ALL).unwrap();
    uc.mem_write(0x40000, &[0; 8]).unwrap();

    let x9 = 0x40000;
    uc.reg_write(RegisterARM64::X9, x9).unwrap();

    let x8 = 0xdeadbeafdeadbeaf;
    uc.reg_write(RegisterARM64::X8, x8).unwrap();

    uc.emu_start(CODE_START, CODE_START + code.len() as u64, 0, 0)
        .unwrap();

    let mem = u64::from_le_bytes(uc.mem_read_as_vec(0x40000, 8).unwrap().try_into().unwrap());
    assert_eq!(mem, x8);
}

#[test]
fn test_arm64_read_sctlr() {
    let uc = Unicorn::new(Arch::ARM64, Mode::ARM | Mode::LITTLE_ENDIAN).unwrap();

    let mut reg = RegisterARM64CP::new().crn(1).op0(0b11);
    uc.reg_read_arm64_coproc(&mut reg).unwrap();

    assert_eq!(reg.val >> 58, 0);
}

#[test]
fn test_arm64_mrs_hook() {
    let code = &[0x62, 0xd0, 0x3b, 0xd5]; // mrs x2, tpidrro_el0
    let mut uc = uc_common_setup(
        Arch::ARM64,
        Mode::ARM | Mode::LITTLE_ENDIAN,
        Some(Arm64CpuModel::A72 as i32),
        code,
        (),
    );

    uc.add_insn_sys_hook_arm64(Arm64Insn::UC_ARM64_INS_MRS, 1, 0, |uc, reg, _| {
        let x2 = 0x114514;
        uc.reg_write(reg, x2).unwrap();

        // Skip
        true
    })
    .unwrap();

    uc.emu_start(CODE_START, CODE_START + code.len() as u64, 0, 0)
        .unwrap();

    let x2 = uc.reg_read(RegisterARM64::X2).unwrap();
    assert_eq!(x2, 0x114514);
}

#[test]
fn test_arm64_correct_address_in_small_jump_hook() {
    let code = &[
        0x00, 0xe0, 0x8f, 0xd2, // mov x0, #0x7F00
        0x00, 0x00, 0x1f, 0xd6, // br x0
    ];

    let mut uc = uc_common_setup(
        Arch::ARM64,
        Mode::ARM,
        Some(Arm64CpuModel::A72 as i32),
        code,
        (),
    );

    uc.add_mem_hook(HookType::MEM_UNMAPPED, 1, 0, |uc, _, address, _, _| {
        let x0 = uc.reg_read(RegisterARM64::X0).unwrap();
        let pc = uc.reg_read(RegisterARM64::PC).unwrap();
        assert_eq!(x0, 0x7F00);
        assert_eq!(pc, 0x7F00);
        assert_eq!(address, 0x7F00);
        false
    })
    .unwrap();

    let err = uc
        .emu_start(CODE_START, CODE_START + code.len() as u64, 0, 0)
        .unwrap_err();
    assert_eq!(err, uc_error::FETCH_UNMAPPED);

    let x0 = uc.reg_read(RegisterARM64::X0).unwrap();
    let pc = uc.reg_read(RegisterARM64::PC).unwrap();
    assert_eq!(x0, 0x7F00);
    assert_eq!(pc, 0x7F00);
}

#[test]
fn test_arm64_correct_address_in_long_jump_hook() {
    let code = &[0xe0, 0xdb, 0x78, 0xb2, 0x00, 0x00, 0x1f, 0xd6]; // mov x0, 0x7FFFFFFFFFFFFF00; br x0
    let mut uc = uc_common_setup(
        Arch::ARM64,
        Mode::ARM,
        Some(Arm64CpuModel::A72 as i32),
        code,
        (),
    );

    uc.add_mem_hook(HookType::MEM_UNMAPPED, 1, 0, |uc, _, address, _, _| {
        let x0 = uc.reg_read(RegisterARM64::X0).unwrap();
        let pc = uc.reg_read(RegisterARM64::PC).unwrap();
        assert_eq!(x0, 0x7FFFFFFFFFFFFF00);
        assert_eq!(pc, 0x7FFFFFFFFFFFFF00);
        assert_eq!(address, 0x7FFFFFFFFFFFFF00);
        false
    })
    .unwrap();

    let err = uc
        .emu_start(CODE_START, CODE_START + code.len() as u64, 0, 0)
        .unwrap_err();
    assert_eq!(err, uc_error::FETCH_UNMAPPED);

    let x0 = uc.reg_read(RegisterARM64::X0).unwrap();
    let pc = uc.reg_read(RegisterARM64::PC).unwrap();
    assert_eq!(x0, 0x7FFFFFFFFFFFFF00);
    assert_eq!(pc, 0x7FFFFFFFFFFFFF00);
}

#[test]
fn test_arm64_block_sync_pc() {
    let code = &[
        0x00, 0x48, 0x13, 0x91, // add x0, x0, #1234
        0x01, 0x00, 0x00, 0x94, // bl t
        0xc1, 0xc5, 0x82, 0xd2, // t: mov x1, #5678
    ];

    let mut uc = uc_common_setup(
        Arch::ARM64,
        Mode::ARM,
        Some(Arm64CpuModel::A72 as i32),
        code,
        true,
    );

    uc.add_block_hook(CODE_START + 8, CODE_START + 12, |uc, addr, _| {
        let pc = uc.reg_read(RegisterARM64::PC).unwrap();
        assert_eq!(pc, addr);
        let val = CODE_START;
        let first = *uc.get_data_mut();
        if first {
            uc.reg_write(RegisterARM64::PC, val).unwrap();
            *uc.get_data_mut() = false;
        }
    })
    .unwrap();

    let x0 = 0;
    uc.reg_write(RegisterARM64::X0, x0).unwrap();

    uc.emu_start(CODE_START, CODE_START + code.len() as u64, 0, 0)
        .unwrap();

    let x0 = uc.reg_read(RegisterARM64::X0).unwrap();
    assert_eq!(x0, 1234 * 2);
}

#[test]
fn test_arm64_block_invalid_mem_read_write_sync() {
    let code = &[
        0x20, 0x00, 0x80, 0xd2, // mov x0, #1
        0x41, 0x00, 0x80, 0xd2, // mov x1, #2
        0x20, 0x00, 0x40, 0xf9, // ldr x0, [x1]
    ];

    let mut uc = uc_common_setup(
        Arch::ARM64,
        Mode::ARM,
        Some(Arm64CpuModel::A72 as i32),
        code,
        true,
    );

    uc.add_mem_hook(
        HookType::MEM_READ,
        CODE_START + 8,
        CODE_START + 12,
        |_, _, _, _, _| false,
    )
    .unwrap();

    let err = uc
        .emu_start(CODE_START, CODE_START + code.len() as u64, 0, 0)
        .unwrap_err();
    assert_eq!(err, uc_error::READ_UNMAPPED);

    let x0 = uc.reg_read(RegisterARM64::X0).unwrap();
    let x1 = uc.reg_read(RegisterARM64::X1).unwrap();
    assert_eq!(x0, 1);
    assert_eq!(x1, 2);
}

#[test]
fn test_arm64_mmu() {
    #[rustfmt::skip]
    let code = &[
        // Read data from physical address
        0x00, 0x81, 0x00, 0x58, // ldr x0, =0x40000000
        0x01, 0x00, 0x40, 0xf9, // ldr x1, [x0]

        // Initialize translation table control registers
        0x00, 0x81, 0x00, 0x58, // ldr x0, =0x180803F20
        0x40, 0x20, 0x18, 0xd5, // msr TCR_EL1, x0
        0x00, 0x81, 0x00, 0x58, // ldr x0, =0xFFFFFFFF
        0x00, 0xa2, 0x18, 0xd5, // msr MAIR_EL1, x0

        // Set translation table
        0x40, 0x7f, 0x00, 0x10, // adr x0, ttb0_base
        0x00, 0x20, 0x18, 0xd5, // msr TTBR0_EL1, x0

        // Enable caches and the MMU
        0x00, 0x10, 0x38, 0xd5, // mrs x0, SCTLR_EL1
        0x00, 0x00, 0x7e, 0xb2, // orr x0, x0, #(0x1 << 2)  // The C bit (data cache)
        0x00, 0x00, 0x74, 0xb2, // orr x0, x0, #(0x1 << 12) // The I bit (instruction cache)
        0x00, 0x00, 0x40, 0xb2, // orr x0, x0, #0x1
        0x00, 0x10, 0x18, 0xd5, // msr SCTLR_EL1, x0
        0x9f, 0x3f, 0x03, 0xd5, // dsb SY
        0xdf, 0x3f, 0x03, 0xd5, // isb

        // Read the same memory area through virtual address
        0xe0, 0x7f, 0x00, 0x58, // ldr x0, =0x80000000
        0x02, 0x00, 0x40, 0xf9, // ldr x2, [x0]

        // Stop
        0x00, 0x00, 0x00, 0x14, // b .
        0x1f, 0x20, 0x03, 0xd5, // nop
        0x1f, 0x20, 0x03, 0xd5, // nop
        0x1f, 0x20, 0x03, 0xd5, // nop
        0x1f, 0x20, 0x03, 0xd5, // nop
        0x1f, 0x20, 0x03, 0xd5, // nop
    ];

    let mut data = vec![0x44u8; 0x1000];
    let mut tlbe = [0x41, 0x07, 0, 0, 0, 0, 0, 0];

    let mut uc = Unicorn::new(Arch::ARM64, Mode::ARM).unwrap();
    uc.ctl_set_tlb_type(unicorn_engine_sys::TlbType::CPU)
        .unwrap();
    uc.mem_map(0, 0x2000, Prot::ALL).unwrap();
    uc.mem_write(0, code).unwrap();

    uc.mem_write(0x1000, &tlbe).unwrap();

    tlbe[3] = 0x40;
    uc.mem_write(0x1008, &tlbe).unwrap();
    uc.mem_write(0x1010, &tlbe).unwrap();
    uc.mem_write(0x1018, &tlbe).unwrap();

    tlbe[0] = 0;
    tlbe[1] = 0;
    uc.mem_write(0x1020, &tlbe).unwrap();

    tlbe[0] = 0x20;
    tlbe[1] = 0x3f;
    tlbe[2] = 0x80;
    tlbe[3] = 0x80;
    tlbe[4] = 0x1;
    uc.mem_write(0x1028, &tlbe).unwrap();

    tlbe[0] = 0xff;
    tlbe[1] = 0xff;
    tlbe[2] = 0xff;
    tlbe[3] = 0xff;
    tlbe[4] = 0x00;
    uc.mem_write(0x1030, &tlbe).unwrap();

    tlbe[0] = 0;
    tlbe[1] = 0;
    tlbe[2] = 0;
    tlbe[3] = 0x80;
    uc.mem_write(0x1038, &tlbe).unwrap();

    unsafe {
        uc.mem_map_ptr(
            0x40000000,
            0x1000,
            Prot::READ,
            data.as_mut_ptr().cast::<core::ffi::c_void>(),
        )
        .unwrap();
    }

    uc.emu_start(0, 0x44, 0, 0).unwrap();

    let x0 = uc.reg_read(RegisterARM64::X0).unwrap();
    let x1 = uc.reg_read(RegisterARM64::X1).unwrap();
    let x2 = uc.reg_read(RegisterARM64::X2).unwrap();

    assert_eq!(x0, 0x80000000);
    assert_eq!(x1, 0x4444444444444444);
    assert_eq!(x2, 0x4444444444444444);
}

#[test]
fn test_arm64_pc_wrap() {
    let code1 = &[0x20, 0x00, 0x02, 0x8b]; // add x1, x2, x3
    let code2 = &[0x20, 0x00, 0x03, 0x8b]; // add x1, x3, x3

    let mut uc = Unicorn::new(Arch::ARM64, Mode::ARM).unwrap();
    uc.mem_map(0xFFFFFFFFFFFFF000, 4096, Prot::READ | Prot::EXEC)
        .unwrap();
    uc.mem_write(0xFFFFFFFFFFFFFFFC, code1).unwrap();

    let x1 = 1;
    let x2 = 2;
    uc.reg_write(RegisterARM64::X1, x1).unwrap();
    uc.reg_write(RegisterARM64::X2, x2).unwrap();

    uc.emu_start(
        0xFFFFFFFFFFFFFFFC,
        0xFFFFFFFFFFFFFFFCu64.wrapping_add(4),
        0,
        1,
    )
    .unwrap();

    uc.mem_unmap(0xFFFFFFFFFFFFF000, 4096).unwrap();

    let x0 = uc.reg_read(RegisterARM64::X0).unwrap();
    assert_eq!(x0, 1 + 2);

    uc.mem_map(0xFFFFFFFFFFFFF000, 4096, Prot::READ | Prot::EXEC)
        .unwrap();
    uc.mem_write(0xFFFFFFFFFFFFFFFC, code2).unwrap();

    let x1 = 5;
    let x2 = 0;
    let x3 = 5;
    uc.reg_write(RegisterARM64::X1, x1).unwrap();
    uc.reg_write(RegisterARM64::X2, x2).unwrap();
    uc.reg_write(RegisterARM64::X3, x3).unwrap();

    uc.emu_start(
        0xFFFFFFFFFFFFFFFC,
        0xFFFFFFFFFFFFFFFCu64.wrapping_add(4),
        0,
        1,
    )
    .unwrap();

    uc.mem_unmap(0xFFFFFFFFFFFFF000, 4096).unwrap();

    let x0 = uc.reg_read(RegisterARM64::X0).unwrap();
    assert_eq!(x0, 5 + 5);
}

#[test]
fn test_arm64_mem_prot_regress() {
    let code = &[0x08, 0x40, 0x5e, 0x78]; // ldurh w8, [x0, #-0x1c]

    let mut uc = Unicorn::new(Arch::ARM64, Mode::ARM).unwrap();

    uc.mem_map(0, 0x4000, Prot::READ | Prot::EXEC).unwrap();
    uc.mem_map(0x4000, 0xC000, Prot::READ | Prot::WRITE)
        .unwrap();
    uc.mem_write(0, code).unwrap();

    uc.add_mem_hook(
        HookType::MEM_READ | HookType::MEM_WRITE,
        1,
        0,
        |_, _, _, _, _| false,
    )
    .unwrap();

    uc.add_mem_hook(HookType::MEM_PROT, 1, 0, |_, _, _, _, _| false)
        .unwrap();

    uc.add_mem_hook(HookType::MEM_UNMAPPED, 1, 0, |_, _, _, _, _| false)
        .unwrap();

    let value = 0x801b;
    uc.reg_write(RegisterARM64::X0, value).unwrap();

    uc.emu_start(0, code.len() as u64, 0, 0).unwrap();
}

#[test]
fn test_arm64_mem_hook_read_write() {
    let code = &[
        0xe1, 0x0b, 0x40, 0xa9, // ldp x1, x2, [sp]
        0xe1, 0x0b, 0x00, 0xa9, // stp x1, x2, [sp]
        0xe1, 0x0b, 0x40, 0xa9, // ldp x1, x2, [sp]
        0xe1, 0x0b, 0x00, 0xa9, // stp x1, x2, [sp]
    ];

    let mut uc = uc_common_setup(
        Arch::ARM64,
        Mode::ARM,
        Some(Arm64CpuModel::A72 as i32),
        code,
        [0, 0],
    );

    let sp = 0x16db6a040;
    uc.reg_write(RegisterARM64::SP, sp).unwrap();
    uc.mem_map(0x16db68000, 1024 * 16, Prot::ALL).unwrap();

    uc.add_mem_hook(HookType::MEM_READ, 1, 0, |uc, _, _, _, _| {
        (*uc.get_data_mut())[0] += 1;
        false
    })
    .unwrap();

    uc.add_mem_hook(HookType::MEM_WRITE, 1, 0, |uc, _, _, _, _| {
        (*uc.get_data_mut())[1] += 1;
        false
    })
    .unwrap();

    uc.emu_start(CODE_START, CODE_START + code.len() as u64, 0, 0)
        .unwrap();

    let [read, write] = *uc.get_data();
    assert_eq!(read, 4);
    assert_eq!(write, 4);
}
