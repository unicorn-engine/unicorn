use unicorn_engine_sys::RegisterPPC;

use super::*;

#[test]
fn test_ppc32_add() {
    let code = [
        0x7f, 0x46, 0x1a, 0x14, // add 26, 6, 3
    ];
    let r3 = 42;
    let r6 = 1337;

    let mut uc = uc_common_setup(Arch::PPC, Mode::PPC32 | Mode::BIG_ENDIAN, None, &code, ());

    uc.reg_write(RegisterPPC::R3, r3).unwrap();
    uc.reg_write(RegisterPPC::R6, r6).unwrap();

    uc.emu_start(CODE_START, CODE_START + code.len() as u64, 0, 0)
        .unwrap();

    let reg = uc.reg_read(RegisterPPC::R26).unwrap();

    assert_eq!(reg, 1379);
}

// https://www.ibm.com/docs/en/aix/7.2?topic=set-fadd-fa-floating-add-instruction
#[test]
fn test_ppc32_fadd() {
    let code = [
        0xfc, 0xc4, 0x28, 0x2a, // fadd 6, 4, 5
    ];
    let mut msr = 0;
    let fpr4 = 0xC053400000000000;
    let fpr5 = 0x400C000000000000;

    let mut uc = uc_common_setup(Arch::PPC, Mode::PPC32 | Mode::BIG_ENDIAN, None, &code, ());

    msr |= 1 << 13; // Big endian
    uc.reg_write(RegisterPPC::MSR, msr).unwrap(); // enable FP

    uc.reg_write(RegisterPPC::FPR4, fpr4).unwrap();
    uc.reg_write(RegisterPPC::FPR5, fpr5).unwrap();

    uc.emu_start(CODE_START, CODE_START + code.len() as u64, 0, 0)
        .unwrap();

    let fpr6 = uc.reg_read(RegisterPPC::FPR6).unwrap();

    assert_eq!(fpr6, 0xC052600000000000);
}

#[test]
fn test_ppc32_sc() {
    let code = [
        0x44, 0x00, 0x00, 0x02, // sc
    ];
    let mut uc = uc_common_setup(Arch::PPC, Mode::PPC32 | Mode::BIG_ENDIAN, None, &code, ());

    uc.add_intr_hook(|uc, _| uc.emu_stop().unwrap()).unwrap();

    uc.emu_start(CODE_START, CODE_START + code.len() as u64, 0, 0)
        .unwrap();

    let pc = uc.reg_read(RegisterPPC::PC).unwrap();

    assert_eq!(pc, CODE_START + 4);
}

#[test]
fn test_ppc32_cr() {
    let mut uc = uc_common_setup(Arch::PPC, Mode::PPC32 | Mode::BIG_ENDIAN, None, &[], ());

    let mut cr = 0x12345678;
    uc.reg_write(RegisterPPC::CR, cr).unwrap();
    cr = uc.reg_read(RegisterPPC::CR).unwrap();

    assert_eq!(cr, 0x12345678);
}

#[test]
fn test_ppc32_spr_time() {
    let code = [
        0x7c, 0x76, 0x02, 0xa6, // mfspr r3, DEC
        0x7c, 0x6d, 0x42, 0xa6, // mfspr r3, TBUr
    ];

    let mut uc = uc_common_setup(Arch::PPC, Mode::PPC32 | Mode::BIG_ENDIAN, None, &code, ());

    uc.emu_start(CODE_START, CODE_START + code.len() as u64, 0, 0)
        .unwrap();
}
