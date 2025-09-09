use unicorn_engine_sys::RegisterMIPS;

use super::*;

const CODE_START: u64 = 0x10000000;
const CODE_LEN: u64 = 0x4000;

fn uc_common_setup<T>(
    arch: Arch,
    mode: Mode,
    cpu_model: Option<i32>,
    code: &[u8],
    data: T,
) -> Unicorn<'_, T> {
    let mut uc = Unicorn::new_with_data(arch, mode, data).unwrap();
    if let Some(cpu_model) = cpu_model {
        uc.ctl_set_cpu_model(cpu_model).unwrap();
    }
    uc.mem_map(CODE_START, CODE_LEN, Prot::ALL).unwrap();
    uc.mem_write(CODE_START, code).unwrap();
    uc
}

#[test]
fn test_mips_el_ori() {
    let code = [
        0x56, 0x34, 0x21, 0x34, // ori $at, $at, 0x3456;
    ];
    let r1 = 0x6789;

    let mut uc = uc_common_setup(
        Arch::MIPS,
        Mode::MIPS32 | Mode::LITTLE_ENDIAN,
        None,
        &code,
        (),
    );

    uc.reg_write(RegisterMIPS::R1, r1).unwrap();
    uc.emu_start(CODE_START, CODE_START + code.len() as u64, 0, 0)
        .unwrap();
    let r1 = uc.reg_read(RegisterMIPS::R1).unwrap();
    assert_eq!(r1, 0x77df);
}

#[test]
fn test_mips_eb_ori() {
    let code = [
        0x34, 0x21, 0x34, 0x56, // ori $at, $at, 0x3456;
    ];
    let r1 = 0x6789;

    let mut uc = uc_common_setup(Arch::MIPS, Mode::MIPS32 | Mode::BIG_ENDIAN, None, &code, ());

    uc.reg_write(RegisterMIPS::R1, r1).unwrap();
    uc.emu_start(CODE_START, CODE_START + code.len() as u64, 0, 0)
        .unwrap();
    let r1 = uc.reg_read(RegisterMIPS::R1).unwrap();
    assert_eq!(r1, 0x77df);
}

#[test]
fn test_mips_stop_at_branch() {
    let code = [
        0x02, 0x00, 0x00, 0x08, // j 0x8
        0x21, 0x10, 0x62, 0x00, // addu $v0, $v1, $v0
    ];
    let v1 = 5;

    let mut uc = uc_common_setup(
        Arch::MIPS,
        Mode::MIPS32 | Mode::LITTLE_ENDIAN,
        None,
        &code,
        (),
    );

    uc.reg_write(RegisterMIPS::V1, v1).unwrap();

    // Execute one instruction with branch delay slot.
    uc.emu_start(CODE_START, CODE_START + code.len() as u64, 0, 1)
        .unwrap();

    let pc = uc.reg_read(RegisterMIPS::PC).unwrap();
    let v1 = uc.reg_read(RegisterMIPS::V0).unwrap();

    // Even if we just execute one instruction, the instruction in the
    // delay slot would also be executed.
    assert_eq!(pc, CODE_START + 0x8);
    assert_eq!(v1, 0x5);
}

#[test]
fn test_mips_stop_at_delay_slot() {
    let code = [
        0x02, 0x00, 0x00, 0x08, // j 0x8
        0x00, 0x00, 0x00, 0x00, // nop
        0x00, 0x00, 0x00, 0x00, // nop
    ];

    let mut uc = uc_common_setup(
        Arch::MIPS,
        Mode::MIPS32 | Mode::LITTLE_ENDIAN,
        None,
        &code,
        (),
    );

    // Stop at the delay slot by design.
    uc.emu_start(CODE_START, CODE_START + 4, 0, 0).unwrap();

    let pc = uc.reg_read(RegisterMIPS::PC).unwrap();

    // The branch instruction isn't committed and the PC is not updated.
    // The user is responsible for restarting emulation at the branch instruction.
    assert_eq!(pc, CODE_START);
}

#[test]
fn test_mips_stop_at_delay_slot_2() {
    let code = [
        0x24, 0x06, 0x00, 0x03, // addiu $a2, $zero, 3
        0x10, 0xa6, 0x00, 0x79, // beq   $a1, $a2, 0x1e8
        0x30, 0x42, 0x00, 0xfc, // andi  $v0, $v0, 0xfc
        0x10, 0x40, 0x00, 0x32, // beqz  $v0, 0x47c8c90
        0x24, 0xab, 0xff, 0xda, // addiu $t3, $a1, -0x26
        0x2d, 0x62, 0x00, 0x02, // sltiu $v0, $t3, 2
        0x10, 0x40, 0x00, 0x32, // beqz  $v0, 0x47c8c9c
        0x00, 0x00, 0x00, 0x00, // nop
    ];

    let v0 = 0xff;
    let a1 = 0x3;

    let mut uc = uc_common_setup(Arch::MIPS, Mode::MIPS32 | Mode::BIG_ENDIAN, None, &code, ());

    uc.reg_write(RegisterMIPS::V0, v0).unwrap();
    uc.reg_write(RegisterMIPS::A1, a1).unwrap();
    uc.emu_start(CODE_START, CODE_START + code.len() as u64 + 16, 0, 2)
        .unwrap();

    let pc = uc.reg_read(RegisterMIPS::PC).unwrap();
    let v0 = uc.reg_read(RegisterMIPS::V0).unwrap();
    assert_eq!(pc, CODE_START + 4 + 0x1e8);
    assert_eq!(v0, 0xfc);
}

#[test]
fn test_mips_lwx_exception_issue_1314() {
    let code = [
        0x0a, 0xc8, 0x79, 0x7e, // lwx $t9, $t9($s3)
    ];

    let mut uc = uc_common_setup(
        Arch::MIPS,
        Mode::MIPS32 | Mode::LITTLE_ENDIAN,
        None,
        &code,
        (),
    );
    uc.mem_map(0x10000, 0x4000, Prot::ALL).unwrap();

    // Enable DSP
    // https://s3-eu-west-1.amazonaws.com/downloads-mips/documents/MD00090-2B-MIPS32PRA-AFP-06.02.pdf
    let mut reg = uc.reg_read(RegisterMIPS::CP0_STATUS).unwrap();
    reg |= 1 << 24;
    uc.reg_write(RegisterMIPS::CP0_STATUS, reg).unwrap();

    reg = 0;
    uc.reg_write(RegisterMIPS::R1, reg).unwrap();
    uc.reg_write(RegisterMIPS::T9, reg).unwrap();
    reg = 0xdeadbeef;
    uc.mem_write(0x10000, &(reg as u32).to_le_bytes()).unwrap();
    reg = 0x10000;
    uc.reg_write(RegisterMIPS::S3, reg).unwrap();

    uc.emu_start(CODE_START, CODE_START + code.len() as u64, 0, 0)
        .unwrap();

    reg = uc.reg_read(RegisterMIPS::T9).unwrap();
    assert_eq!(reg, 0xdeadbeef);
}

#[test]
fn test_mips_mips16() {
    let code = [
        0xC4, 0x6B, 0x49, 0xE3, // sc $t1, 0x6bc4($k0)
    ];
    let v0 = 0x6789;
    let mips16_lowbit = 1;

    let mut uc = uc_common_setup(
        Arch::MIPS,
        Mode::MIPS32 | Mode::LITTLE_ENDIAN,
        None,
        &code,
        (),
    );

    uc.reg_write(RegisterMIPS::V0, v0).unwrap();
    uc.emu_start(
        CODE_START | mips16_lowbit,
        CODE_START + code.len() as u64,
        0,
        0,
    )
    .unwrap();

    let v0 = uc.reg_read(RegisterMIPS::V0).unwrap();
    assert_eq!(v0, 0x684D);
}

#[test]
fn test_mips_mips_fpr() {
    #[rustfmt::skip]
    let code = [
        0xf6, 0x42, 0x09, 0x3c, 0x79, 0xe9, 0x29, 0x35, // li $t1, 0x42f6e979
        0x00, 0x08, 0x89, 0x44,                         // mtc1 $t1, $f1
    ];

    let mut uc = uc_common_setup(Arch::MIPS, Mode::MIPS32, None, &code, ());
    uc.emu_start(CODE_START, CODE_START + code.len() as u64, 0, 0)
        .unwrap();

    let f1 = uc.reg_read(RegisterMIPS::F1).unwrap();
    assert_eq!(f1, 0x42f6e979);
}
