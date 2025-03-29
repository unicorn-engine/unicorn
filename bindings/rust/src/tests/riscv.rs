use unicorn_engine_sys::RegisterRISCV;

use super::*;

#[test]
fn test_riscv32_nop() {
    let code = [
        0x13, 0x00, 0x00, 0x00, // nop
    ];

    let t0 = 0x1234;
    let t1 = 0x5678;

    let mut uc = uc_common_setup(Arch::RISCV, Mode::RISCV32, None, &code, ());
    uc.reg_write(RegisterRISCV::T0, t0).unwrap();
    uc.reg_write(RegisterRISCV::T1, t1).unwrap();

    uc.emu_start(CODE_START, CODE_START + code.len() as u64, 0, 0)
        .unwrap();

    let t0 = uc.reg_read(RegisterRISCV::T0).unwrap();
    let t1 = uc.reg_read(RegisterRISCV::T1).unwrap();
    assert_eq!(t0, 0x1234);
    assert_eq!(t1, 0x5678);
}

#[test]
fn test_riscv64_nop() {
    let code = [
        0x13, 0x00, 0x00, 0x00, // nop
    ];

    let t0 = 0x1234;
    let t1 = 0x5678;

    let mut uc = uc_common_setup(Arch::RISCV, Mode::RISCV64, None, &code, ());
    uc.reg_write(RegisterRISCV::T0, t0).unwrap();
    uc.reg_write(RegisterRISCV::T1, t1).unwrap();

    uc.emu_start(CODE_START, CODE_START + code.len() as u64, 0, 0)
        .unwrap();

    let t0 = uc.reg_read(RegisterRISCV::T0).unwrap();
    let t1 = uc.reg_read(RegisterRISCV::T1).unwrap();
    assert_eq!(t0, 0x1234);
    assert_eq!(t1, 0x5678);
}

#[test]
fn test_riscv32_until_pc_update() {
    let code = [
        0x93, 0x02, 0x10, 0x00, // addi t0, zero, 1
        0x13, 0x03, 0x00, 0x02, // addi t1, zero, 0x20
        0x13, 0x01, 0x81, 0x00, // addi sp, sp, 8
    ];

    let mut uc = uc_common_setup(Arch::RISCV, Mode::RISCV32, None, &code, ());

    let mut t0 = 0x1234;
    let mut t1 = 0x7890;
    let mut sp = 0x1234;

    uc.reg_write(RegisterRISCV::T0, t0).unwrap();
    uc.reg_write(RegisterRISCV::T1, t1).unwrap();
    uc.reg_write(RegisterRISCV::SP, sp).unwrap();

    uc.emu_start(CODE_START, CODE_START + code.len() as u64, 0, 0)
        .unwrap();

    t0 = uc.reg_read(RegisterRISCV::T0).unwrap();
    t1 = uc.reg_read(RegisterRISCV::T1).unwrap();
    sp = uc.reg_read(RegisterRISCV::SP).unwrap();
    let pc = uc.reg_read(RegisterRISCV::PC).unwrap();

    assert_eq!(t0, 0x1);
    assert_eq!(t1, 0x20);
    assert_eq!(sp, 0x123c);

    assert_eq!(pc, CODE_START + code.len() as u64);
}

#[test]
fn test_riscv64_until_pc_update() {
    let code = [
        0x93, 0x02, 0x10, 0x00, // addi t0, zero, 1
        0x13, 0x03, 0x00, 0x02, // addi t1, zero, 0x20
        0x13, 0x01, 0x81, 0x00, // addi sp, sp, 8
    ];

    let mut uc = uc_common_setup(Arch::RISCV, Mode::RISCV64, None, &code, ());

    let mut t0 = 0x1234;
    let mut t1 = 0x7890;
    let mut sp = 0x1234;

    uc.reg_write(RegisterRISCV::T0, t0).unwrap();
    uc.reg_write(RegisterRISCV::T1, t1).unwrap();
    uc.reg_write(RegisterRISCV::SP, sp).unwrap();

    uc.emu_start(CODE_START, CODE_START + code.len() as u64, 0, 0)
        .unwrap();

    t0 = uc.reg_read(RegisterRISCV::T0).unwrap();
    t1 = uc.reg_read(RegisterRISCV::T1).unwrap();
    sp = uc.reg_read(RegisterRISCV::SP).unwrap();
    let pc = uc.reg_read(RegisterRISCV::PC).unwrap();

    assert_eq!(t0, 0x1);
    assert_eq!(t1, 0x20);
    assert_eq!(sp, 0x123c);

    assert_eq!(pc, CODE_START + code.len() as u64);
}

#[test]
fn test_riscv32_3steps_pc_update() {
    let code = [
        0x93, 0x02, 0x10, 0x00, // addi t0, zero, 1
        0x13, 0x03, 0x00, 0x02, // addi t1, zero, 0x20
        0x13, 0x01, 0x81, 0x00, // addi sp, sp, 8
    ];

    let mut uc = uc_common_setup(Arch::RISCV, Mode::RISCV32, None, &code, ());

    let mut t0 = 0x1234;
    let mut t1 = 0x7890;
    let mut sp = 0x1234;

    uc.reg_write(RegisterRISCV::T0, t0).unwrap();
    uc.reg_write(RegisterRISCV::T1, t1).unwrap();
    uc.reg_write(RegisterRISCV::SP, sp).unwrap();

    uc.emu_start(CODE_START, u64::MAX, 0, 3).unwrap();

    t0 = uc.reg_read(RegisterRISCV::T0).unwrap();
    t1 = uc.reg_read(RegisterRISCV::T1).unwrap();
    sp = uc.reg_read(RegisterRISCV::SP).unwrap();
    let pc = uc.reg_read(RegisterRISCV::PC).unwrap();

    assert_eq!(t0, 0x1);
    assert_eq!(t1, 0x20);
    assert_eq!(sp, 0x123c);

    assert_eq!(pc, CODE_START + code.len() as u64);
}

#[test]
fn test_riscv64_3steps_pc_update() {
    let code = [
        0x93, 0x02, 0x10, 0x00, // addi t0, zero, 1
        0x13, 0x03, 0x00, 0x02, // addi t1, zero, 0x20
        0x13, 0x01, 0x81, 0x00, // addi sp, sp, 8
    ];

    let mut uc = uc_common_setup(Arch::RISCV, Mode::RISCV64, None, &code, ());

    let mut t0 = 0x1234;
    let mut t1 = 0x7890;
    let mut sp = 0x1234;

    uc.reg_write(RegisterRISCV::T0, t0).unwrap();
    uc.reg_write(RegisterRISCV::T1, t1).unwrap();
    uc.reg_write(RegisterRISCV::SP, sp).unwrap();

    uc.emu_start(CODE_START, u64::MAX, 0, 3).unwrap();

    t0 = uc.reg_read(RegisterRISCV::T0).unwrap();
    t1 = uc.reg_read(RegisterRISCV::T1).unwrap();
    sp = uc.reg_read(RegisterRISCV::SP).unwrap();
    let pc = uc.reg_read(RegisterRISCV::PC).unwrap();

    assert_eq!(t0, 0x1);
    assert_eq!(t1, 0x20);
    assert_eq!(sp, 0x123c);

    assert_eq!(pc, CODE_START + code.len() as u64);
}

#[test]
fn test_riscv32_fp_move() {
    let code = [
        0xd3, 0x81, 0x10, 0x22, // fmv.d f3, f1
    ];

    let mut f1 = 0x123456781a2b3c4d;
    let mut f3 = 0x56780246aaaabbbb;

    let mut uc = uc_common_setup(Arch::RISCV, Mode::RISCV32, None, &code, ());

    uc.reg_write(RegisterRISCV::F1, f1).unwrap();
    uc.reg_write(RegisterRISCV::F3, f3).unwrap();

    uc.emu_start(CODE_START, u64::MAX, 0, 1).unwrap();

    f1 = uc.reg_read(RegisterRISCV::F1).unwrap();
    f3 = uc.reg_read(RegisterRISCV::F3).unwrap();

    assert_eq!(f1, 0x123456781a2b3c4d);
    assert_eq!(f3, 0x123456781a2b3c4d);
}

#[test]
fn test_riscv64_fp_move() {
    let code = [
        0xd3, 0x81, 0x10, 0x22, // fmv.d f3, f1
    ];

    let mut f1 = 0x123456781a2b3c4d;
    let mut f3 = 0x56780246aaaabbbb;

    let mut uc = uc_common_setup(Arch::RISCV, Mode::RISCV64, None, &code, ());

    uc.reg_write(RegisterRISCV::F1, f1).unwrap();
    uc.reg_write(RegisterRISCV::F3, f3).unwrap();

    uc.emu_start(CODE_START, u64::MAX, 0, 1).unwrap();

    f1 = uc.reg_read(RegisterRISCV::F1).unwrap();
    f3 = uc.reg_read(RegisterRISCV::F3).unwrap();

    assert_eq!(f1, 0x123456781a2b3c4d);
    assert_eq!(f3, 0x123456781a2b3c4d);
}

#[test]
fn test_riscv64_fp_move_from_int() {
    let code = [
        0xf3, 0x90, 0x01, 0x30, // csrrw x2, mstatus, x3;
        0x53, 0x00, 0x0b, 0xf2, // fmvd.d.x ft0, s6
    ];

    let mut ft0 = 0x12341234;
    let mut s6 = 0x56785678;
    let x3 = 0x6000;

    let mut uc = uc_common_setup(Arch::RISCV, Mode::RISCV64, None, &code, ());

    uc.reg_write(RegisterRISCV::FT0, ft0).unwrap();
    uc.reg_write(RegisterRISCV::S6, s6).unwrap();

    // mstatus.fs
    uc.reg_write(RegisterRISCV::X3, x3).unwrap();

    uc.emu_start(CODE_START, u64::MAX, 0, 2).unwrap();

    ft0 = uc.reg_read(RegisterRISCV::FT0).unwrap();
    s6 = uc.reg_read(RegisterRISCV::S6).unwrap();

    assert_eq!(ft0, 0x56785678);
    assert_eq!(s6, 0x56785678);
}

#[test]
fn test_riscv64_fp_move_from_int_reg_write() {
    let code = [
        0x53, 0x00, 0x0b, 0xf2, // fmvd.d.x ft0, s6
    ];

    let mut ft0 = 0x12341234;
    let mut s6 = 0x56785678;
    let mstatus = 0x6000;

    let mut uc = uc_common_setup(Arch::RISCV, Mode::RISCV64, None, &code, ());

    uc.reg_write(RegisterRISCV::FT0, ft0).unwrap();
    uc.reg_write(RegisterRISCV::S6, s6).unwrap();

    // mstatus.fs
    uc.reg_write(RegisterRISCV::MSTATUS, mstatus).unwrap();

    uc.emu_start(CODE_START, u64::MAX, 0, 1).unwrap();

    ft0 = uc.reg_read(RegisterRISCV::FT0).unwrap();
    s6 = uc.reg_read(RegisterRISCV::S6).unwrap();

    assert_eq!(ft0, 0x56785678);
    assert_eq!(s6, 0x56785678);
}

#[test]
fn test_riscv64_fp_move_to_int() {
    let code = [
        0xf3, 0x90, 0x01, 0x30, // csrrw x2, mstatus, x3;
        0x53, 0x0b, 0x00, 0xe2, // fmv.x.d s6, ft0
    ];

    let mut ft0 = 0x12341234;
    let mut s6 = 0x56785678;
    let x3 = 0x6000;

    let mut uc = uc_common_setup(Arch::RISCV, Mode::RISCV64, None, &code, ());

    uc.reg_write(RegisterRISCV::FT0, ft0).unwrap();
    uc.reg_write(RegisterRISCV::S6, s6).unwrap();

    // mstatus.fs
    uc.reg_write(RegisterRISCV::X3, x3).unwrap();

    uc.emu_start(CODE_START, u64::MAX, 0, 2).unwrap();

    ft0 = uc.reg_read(RegisterRISCV::FT0).unwrap();
    s6 = uc.reg_read(RegisterRISCV::S6).unwrap();

    assert_eq!(ft0, 0x12341234);
    assert_eq!(s6, 0x12341234);
}

#[test]
fn test_riscv64_code_patching() {
    let code = [
        0x93, 0x82, 0x12, 0x00, // addi t0, t0, 0x1
    ];

    let mut uc = uc_common_setup(Arch::RISCV, Mode::RISCV64, None, &code, ());

    // Zero out t0 and t1
    let mut t0 = 0x0;
    uc.reg_write(RegisterRISCV::T0, t0).unwrap();

    // emulate the instruction
    uc.emu_start(CODE_START, CODE_START + code.len() as u64, 0, 0)
        .unwrap();

    // check value
    t0 = uc.reg_read(RegisterRISCV::T0).unwrap();
    assert_eq!(t0, 0x1);

    // patch instruction
    let patch_code = [
        0x93, 0x82, 0xf2, 0x7f, // addi t0, t0, 0x7FF
    ];
    uc.mem_write(CODE_START, &patch_code).unwrap();

    // zero out t0
    t0 = 0x0;
    uc.reg_write(RegisterRISCV::T0, t0).unwrap();
    uc.emu_start(CODE_START, CODE_START + patch_code.len() as u64, 0, 0)
        .unwrap();

    // check value
    t0 = uc.reg_read(RegisterRISCV::T0).unwrap();
    assert_eq!(t0, 0x7ff);
}

#[test]
fn test_riscv64_code_patching_count() {
    let code = [
        0x93, 0x82, 0x12, 0x00, // addi t0, t0, 0x1
    ];

    let mut uc = uc_common_setup(Arch::RISCV, Mode::RISCV64, None, &code, ());

    // Zero out t0 and t1
    let mut t0 = 0x0;
    uc.reg_write(RegisterRISCV::T0, t0).unwrap();

    // emulate the instruction
    uc.emu_start(CODE_START, u64::MAX, 0, 1).unwrap();

    // check value
    t0 = uc.reg_read(RegisterRISCV::T0).unwrap();
    assert_eq!(t0, 0x1);

    // patch instruction
    let patch_code = [
        0x93, 0x82, 0xf2, 0x7f, // addi t0, t0, 0x7FF
    ];
    uc.mem_write(CODE_START, &patch_code).unwrap();
    uc.ctl_remove_cache(CODE_START, CODE_START + patch_code.len() as u64)
        .unwrap();

    // zero out t0
    t0 = 0x0;
    uc.reg_write(RegisterRISCV::T0, t0).unwrap();
    uc.emu_start(CODE_START, u64::MAX, 0, 1).unwrap();

    // check value
    t0 = uc.reg_read(RegisterRISCV::T0).unwrap();
    assert_eq!(t0, 0x7ff);
}

#[test]
fn test_riscv64_ecall() {
    let code = [
        0x73, 0x00, 0x00, 0x00, // ecall
    ];

    let mut uc = uc_common_setup(Arch::RISCV, Mode::RISCV64, None, &code, ());

    uc.add_intr_hook(|uc, _| uc.emu_stop().unwrap()).unwrap();

    uc.emu_start(CODE_START, CODE_START + code.len() as u64, 0, 0)
        .unwrap();

    let pc = uc.reg_read(RegisterRISCV::PC).unwrap();

    assert_eq!(pc, CODE_START + 4);
}

#[test]
fn test_riscv32_mmio_map() {
    #[rustfmt::skip]
    let code = [
        0x37, 0x17, 0x02, 0x40, // lui  a4, 0x40021
        0x1c, 0x4f,             // c.lw a5, 0x18(a4)
    ];

    let mut uc = uc_common_setup(Arch::RISCV, Mode::RISCV32, None, &code, ());

    uc.mmio_map_ro(0x40000000, 0x40000, |uc, offset, _size| {
        let a4 = uc.reg_read(RegisterRISCV::A4).unwrap();
        assert_eq!(a4, 0x40021 << 12);
        assert_eq!(offset, 0x21018);
        0
    })
    .unwrap();

    uc.emu_start(CODE_START, CODE_START + code.len() as u64, 0, 0)
        .unwrap();
}

#[test]
fn test_riscv32_map() {
    #[rustfmt::skip]
    let code = [
        0x37, 0x17, 0x02, 0x40, // lui  a4, 0x40021
        0x1c, 0x4f,             // c.lw a5, 0x18(a4)
    ];

    let mut uc = uc_common_setup(Arch::RISCV, Mode::RISCV32, None, &code, ());

    let val = 0xdeadbeefu64;
    uc.mem_map(0x40000000, 0x40000, Prot::ALL).unwrap();
    uc.mem_write(0x40000000 + 0x21018, &val.to_le_bytes())
        .unwrap();

    uc.emu_start(CODE_START, CODE_START + code.len() as u64, 0, 0)
        .unwrap();

    let a5 = uc.reg_read(RegisterRISCV::A5).unwrap();
    assert_eq!(a5, val);
}

#[test]
fn test_riscv64_mmio_map() {
    #[rustfmt::skip]
    let code = [
        0x37, 0x17, 0x02, 0x40, // lui  a4, 0x40021
        0x1c, 0x4f,             // c.lw a5, 0x18(a4)
    ];

    let mut uc = uc_common_setup(Arch::RISCV, Mode::RISCV64, None, &code, ());

    uc.mmio_map_ro(0x40000000, 0x40000, |uc, offset, _size| {
        let a4 = uc.reg_read(RegisterRISCV::A4).unwrap();
        assert_eq!(a4, 0x40021 << 12);
        assert_eq!(offset, 0x21018);
        0
    })
    .unwrap();

    uc.emu_start(CODE_START, CODE_START + code.len() as u64, 0, 0)
        .unwrap();
}

#[test]
fn test_riscv_correct_address_in_small_jump_hook() {
    #[rustfmt::skip]
    let code = [
        0xb7, 0x82, 0x00, 0x00, // lui t0, 8
        0x9b, 0x82, 0x02, 0xf0, // addiw t0, t0, -256;
        0x67, 0x80, 0x02, 0x00, // jr x5
    ];

    let mut uc = uc_common_setup(Arch::RISCV, Mode::RISCV64, None, &code, ());

    uc.add_mem_hook(HookType::MEM_UNMAPPED, 1, 0, |uc, _, address, _, _| {
        // Check registers
        let x5 = uc.reg_read(RegisterRISCV::X5).unwrap();
        let pc = uc.reg_read(RegisterRISCV::PC).unwrap();
        assert_eq!(x5, 0x7F00);
        assert_eq!(pc, 0x7F00);

        // Check address
        assert_eq!(address, 0x7F00);
        false
    })
    .unwrap();

    let err = uc
        .emu_start(CODE_START, CODE_START + code.len() as u64, 0, 0)
        .unwrap_err();
    assert_eq!(err, uc_error::FETCH_UNMAPPED);

    let x5 = uc.reg_read(RegisterRISCV::X5).unwrap();
    let pc = uc.reg_read(RegisterRISCV::PC).unwrap();

    assert_eq!(x5, 0x7F00);
    assert_eq!(pc, 0x7F00);
}

#[test]
fn test_riscv_correct_address_in_long_jump_hook() {
    #[rustfmt::skip]
    let code = [
        0x93, 0x02, 0xf0, 0xff, // addi t0, zero, -1
        0x93, 0x92, 0xf2, 0x03, // slli t0, t0, 63
        0x93, 0x82, 0x02, 0xf0, // addi t0, t0, -256
        0x67, 0x80, 0x02, 0x00, // jr x5
    ];

    let mut uc = uc_common_setup(Arch::RISCV, Mode::RISCV64, None, &code, ());

    uc.add_mem_hook(HookType::MEM_UNMAPPED, 1, 0, |uc, _, address, _, _| {
        // Check registers
        let x5 = uc.reg_read(RegisterRISCV::X5).unwrap();
        let pc = uc.reg_read(RegisterRISCV::PC).unwrap();
        assert_eq!(x5, 0x7FFFFFFFFFFFFF00);
        assert_eq!(pc, 0x7FFFFFFFFFFFFF00);

        // Check address
        assert_eq!(address, 0x7FFFFFFFFFFFFF00);
        false
    })
    .unwrap();

    let err = uc
        .emu_start(CODE_START, CODE_START + code.len() as u64, 0, 0)
        .unwrap_err();
    assert_eq!(err, uc_error::FETCH_UNMAPPED);

    let x5 = uc.reg_read(RegisterRISCV::X5).unwrap();
    let pc = uc.reg_read(RegisterRISCV::PC).unwrap();

    assert_eq!(x5, 0x7FFFFFFFFFFFFF00);
    assert_eq!(pc, 0x7FFFFFFFFFFFFF00);
}

#[test]
fn test_riscv_mmu() {
    fn test_riscv_mmu_prepare_tlb(uc: &mut Unicorn<'_, ()>, data_address: u64, code_address: u64) {
        let sptbr = 0x2000;
        uc.mem_map(sptbr, 0x3000, Prot::ALL).unwrap(); // tlb base

        let tlbe = ((sptbr + 0x1000) >> 2) | 1;
        uc.mem_write(sptbr, &tlbe.to_le_bytes()).unwrap();
        let tlbe = ((sptbr + 0x2000) >> 2) | 1;
        uc.mem_write(sptbr + 0x1000, &tlbe.to_le_bytes()).unwrap();

        let tlbe = (code_address >> 2) | (7 << 1) | 1;
        uc.mem_write(sptbr + 0x2000 + 0x15 * 8, &tlbe.to_le_bytes())
            .unwrap();

        let tlbe = (data_address >> 2) | (7 << 1) | 1;
        uc.mem_write(sptbr + 0x2000 + 0x16 * 8, &tlbe.to_le_bytes())
            .unwrap();
    }

    let code_address = 0x5000;
    let data_address = 0x6000;
    let data_value = 0x41414141u32;

    let code_m = [
        0x1b, 0x0e, 0xf0, 0xff, // li t3, (8 << 60) | 2
        0x13, 0x1e, 0xfe, 0x03, // csrw sptbr, t3
        0x13, 0x0e, 0x2e, 0x00, // li t0, (1 << 11) | (1 << 5)
        0x73, 0x10, 0x0e, 0x18, // csrw mstatus, t0
        0xb7, 0x12, 0x00, 0x00, // la t1, 0x15000
        0x9b, 0x82, 0x02, 0x82, // csrw mepc, t1
        0x73, 0x90, 0x02, 0x30, // mret
        0x37, 0x53, 0x01, 0x00, // lui t0, 8
        0x73, 0x10, 0x13, 0x34, // csrw mepc, t1
        0x73, 0x00, 0x20, 0x30, // mret
    ];

    #[rustfmt::skip]
    let code_s = [
        0xb7, 0x42, 0x41, 0x41, 0x9b, 0x82, 0x12, 0x14, // li t0, 0x41414141
        0x37, 0x63, 0x01, 0x00,                         // li t1, 0x16000
        0x23, 0x20, 0x53, 0x00,                         // sw t0, 0(t1)
        0x13, 0x00, 0x00, 0x00,                         // nop
    ];

    let mut uc = Unicorn::new(Arch::RISCV, Mode::RISCV64).unwrap();
    uc.ctl_set_tlb_type(TlbType::CPU).unwrap();
    uc.add_code_hook(1, 0, |uc, address, _| {
        if address == 0x15010 {
            uc.emu_stop().unwrap();
        }
    })
    .unwrap();
    uc.mem_map(0x1000, 0x1000, Prot::ALL).unwrap();
    uc.mem_map(code_address, 0x1000, Prot::ALL).unwrap();
    uc.mem_map(data_address, 0x1000, Prot::ALL).unwrap();
    uc.mem_write(code_address, &code_s).unwrap();
    uc.mem_write(0x1000, &code_m).unwrap();

    test_riscv_mmu_prepare_tlb(&mut uc, data_address, code_address);

    uc.emu_start(0x1000, 0x1000 + code_m.len() as u64, 0, 0)
        .unwrap();
    let data_result = u32::from_le_bytes(
        uc.mem_read_as_vec(data_address, 4)
            .unwrap()
            .try_into()
            .unwrap(),
    );

    assert_eq!(data_value, data_result);
}

#[test]
fn test_riscv_priv() {
    let m_entry_address = 0x1000;
    let main_address = 0x3000;

    #[rustfmt::skip]
    let code_m_entry = [
        0x93, 0x02, 0x00, 0x00, // li t0, 0
        0x73, 0x90, 0x02, 0x30, // csrw mstatus, t0
        0x37, 0x33, 0x00, 0x00, // li t1, 0x3000
        0x73, 0x10, 0x13, 0x34, // csrw mepc, t1
        0x73, 0x00, 0x20, 0x30, // mret
    ];

    #[rustfmt::skip]
    let code_main = [
        0x73, 0x90, 0x02, 0x14, // csrw sscratch, t1
        0x13, 0x00, 0x00, 0x00, // nop
    ];

    let main_end_address = main_address + code_main.len() as u64;

    let mut uc = Unicorn::new(Arch::RISCV, Mode::RISCV64).unwrap();
    uc.ctl_set_tlb_type(TlbType::CPU).unwrap();
    uc.mem_map(m_entry_address, 0x1000, Prot::ALL).unwrap();
    uc.mem_map(main_address, 0x1000, Prot::ALL).unwrap();
    uc.mem_write(m_entry_address, &code_m_entry).unwrap();
    uc.mem_write(main_address, &code_main).unwrap();

    // Before anything executes we should be in M-Mode
    let mut priv_value = uc.reg_read(RegisterRISCV::PRIV).unwrap();
    assert_eq!(priv_value, 3);

    // We'll put a sentinel value in sscratch so we can determine whether we've
    // successfully written to it below.
    let mut reg_value = 0xffff;
    uc.reg_write(RegisterRISCV::SSCRATCH, reg_value).unwrap();

    // Run until we reach the "csrw" at the start of code_main, at which
    // point we should be in U-Mode due to the mret instruction.
    uc.emu_start(m_entry_address, main_address, 0, 10).unwrap();

    let mut pc = uc.reg_read(RegisterRISCV::PC).unwrap();
    assert_eq!(pc, main_address);
    priv_value = uc.reg_read(RegisterRISCV::PRIV).unwrap();
    assert_eq!(priv_value, 0); // Now in U-Mode

    // U-Mode can't write to sscratch, so execution at this point should
    // cause an invalid instruction exception.
    let err = uc
        .emu_start(main_address, main_end_address, 0, 0)
        .unwrap_err();
    assert_eq!(err, uc_error::EXCEPTION);
    pc = uc.reg_read(RegisterRISCV::PC).unwrap();
    assert_eq!(pc, main_address + 4);

    // ...but if we force S-Mode then we should be able to set it successfully.
    priv_value = 1;
    uc.reg_write(RegisterRISCV::PRIV, priv_value).unwrap();
    uc.emu_start(main_address, main_end_address, 0, 0).unwrap();
    reg_value = uc.reg_read(RegisterRISCV::SSCRATCH).unwrap();
    assert_eq!(reg_value, 0);
    pc = uc.reg_read(RegisterRISCV::PC).unwrap();
    assert_eq!(pc, main_end_address);
}
