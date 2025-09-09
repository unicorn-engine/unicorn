use super::*;
use crate::{ArmCpuModel, RegisterARM, RegisterARMCP, TcgOpCode, TcgOpFlag, uc_error};

#[test]
fn test_arm_nop() {
    let code = b"\x00\xf0\x20\xe3"; // nop
    let r0 = 0x1234;
    let r1 = 0x5678;

    let mut uc = uc_common_setup(Arch::ARM, Mode::ARM, None, code, ());
    uc.reg_write(RegisterARM::R0, r0).unwrap();
    uc.reg_write(RegisterARM::R1, r1).unwrap();

    uc.emu_start(CODE_START, CODE_START + code.len() as u64, 0, 0)
        .unwrap();

    let r0 = uc.reg_read(RegisterARM::R0).unwrap();
    let r1 = uc.reg_read(RegisterARM::R1).unwrap();
    assert_eq!(r0, 0x1234);
    assert_eq!(r1, 0x5678);
}

#[test]
fn test_arm_thumb_sub() {
    let code = b"\x83\xb0"; // sub sp, #0xc
    let sp = 0x1234;

    let mut uc = uc_common_setup(
        Arch::ARM,
        Mode::THUMB,
        Some(ArmCpuModel::CORTEX_A15 as i32),
        code,
        (),
    );
    uc.reg_write(RegisterARM::SP, sp).unwrap();

    uc.emu_start(CODE_START | 1, CODE_START + code.len() as u64, 0, 0)
        .unwrap();

    let sp = uc.reg_read(RegisterARM::SP).unwrap();
    assert_eq!(sp, 0x1228);
}

#[test]
fn test_armeb_sub() {
    let code = &[
        0xe3, 0xa0, 0x00, 0x37, // mov r0, #0x37
        0xe0, 0x42, 0x10, 0x03, // sub r1, r2, r3
    ];
    let r0 = 0x1234;
    let r2 = 0x6789;
    let r3 = 0x3333;

    let mut uc = uc_common_setup(
        Arch::ARM,
        Mode::ARM | Mode::BIG_ENDIAN,
        Some(ArmCpuModel::Model_1176 as i32),
        code,
        (),
    );
    uc.reg_write(RegisterARM::R0, r0).unwrap();
    uc.reg_write(RegisterARM::R2, r2).unwrap();
    uc.reg_write(RegisterARM::R3, r3).unwrap();

    uc.emu_start(CODE_START, CODE_START + code.len() as u64, 0, 0)
        .unwrap();

    let r0 = uc.reg_read(RegisterARM::R0).unwrap();
    let r1 = uc.reg_read(RegisterARM::R1).unwrap();
    let r2 = uc.reg_read(RegisterARM::R2).unwrap();
    let r3 = uc.reg_read(RegisterARM::R3).unwrap();

    assert_eq!(r0, 0x37);
    assert_eq!(r2, 0x6789);
    assert_eq!(r3, 0x3333);
    assert_eq!(r1, 0x3456);
}

#[test]
fn test_armeb_be8_sub() {
    let code = &[
        0x37, 0x00, 0xa0, 0xe3, // mov r0, #0x37
        0x03, 0x10, 0x42, 0xe0, // sub r1, r2, r3
    ];
    let r0 = 0x1234;
    let r2 = 0x6789;
    let r3 = 0x3333;

    let mut uc = uc_common_setup(
        Arch::ARM,
        Mode::ARM | Mode::ARMBE8,
        Some(ArmCpuModel::CORTEX_A15 as i32),
        code,
        (),
    );
    uc.reg_write(RegisterARM::R0, r0).unwrap();
    uc.reg_write(RegisterARM::R2, r2).unwrap();
    uc.reg_write(RegisterARM::R3, r3).unwrap();

    uc.emu_start(CODE_START, CODE_START + code.len() as u64, 0, 0)
        .unwrap();

    let r0 = uc.reg_read(RegisterARM::R0).unwrap();
    let r1 = uc.reg_read(RegisterARM::R1).unwrap();
    let r2 = uc.reg_read(RegisterARM::R2).unwrap();
    let r3 = uc.reg_read(RegisterARM::R3).unwrap();

    assert_eq!(r0, 0x37);
    assert_eq!(r2, 0x6789);
    assert_eq!(r3, 0x3333);
    assert_eq!(r1, 0x3456);
}

#[test]
fn test_arm_thumbeb_sub() {
    let code = b"\xb0\x83"; // sub sp, #0xc
    let sp = 0x1234;

    let mut uc = uc_common_setup(
        Arch::ARM,
        Mode::THUMB | Mode::BIG_ENDIAN,
        Some(ArmCpuModel::Model_1176 as i32),
        code,
        (),
    );
    uc.reg_write(RegisterARM::SP, sp).unwrap();

    uc.emu_start(CODE_START | 1, CODE_START + code.len() as u64, 0, 0)
        .unwrap();

    let sp = uc.reg_read(RegisterARM::SP).unwrap();
    assert_eq!(sp, 0x1228);
}

#[test]
fn test_arm_thumb_ite() {
    let code = &[
        0x9a, 0x42, // cmp r2, r3
        0x15, 0xbf, // itete ne
        0x00, 0x9a, // ldrne r2, [sp]
        0x01, 0x9a, // ldreq r2, [sp,#4]
        0x78, 0x23, // movne r3, #0x78
        0x15, 0x23, // moveq r3, #0x15
    ];
    let sp = 0x8000;
    let mut r2 = 0u32;
    let mut r3 = 1u32;
    let mut pc = CODE_START as u32;
    let mut count = 0;

    let mut uc = uc_common_setup(
        Arch::ARM,
        Mode::THUMB,
        Some(ArmCpuModel::CORTEX_A15 as i32),
        code,
        count,
    );

    uc.reg_write(RegisterARM::SP, sp).unwrap();
    uc.reg_write(RegisterARM::R2, r2 as u64).unwrap();
    uc.reg_write(RegisterARM::R3, r3 as u64).unwrap();

    uc.mem_map(sp, 0x1000, Prot::ALL).unwrap();
    r2 = 0x68;
    uc.mem_write(sp, &r2.to_le_bytes()).unwrap();
    r2 = 0x4d;
    uc.mem_write(sp + 4, &r2.to_le_bytes()).unwrap();

    uc.add_code_hook(CODE_START, CODE_START + code.len() as u64, |uc, _, _| {
        *uc.get_data_mut() += 1;
    })
    .unwrap();

    // Execute four instructions
    uc.emu_start(CODE_START | 1, CODE_START + code.len() as u64, 0, 0)
        .unwrap();

    r2 = uc.reg_read(RegisterARM::R2).unwrap() as u32;
    r3 = uc.reg_read(RegisterARM::R3).unwrap() as u32;
    count = *uc.get_data();
    assert_eq!(r2, 0x68);
    assert_eq!(r3, 0x78);
    assert_eq!(count, 4);

    r2 = 0;
    *uc.get_data_mut() = 0;

    uc.reg_write(RegisterARM::R2, r2 as u64).unwrap();
    uc.reg_write(RegisterARM::R3, r3 as u64).unwrap();

    for _ in 0..6 {
        // Execute one instruction at a time.
        uc.emu_start(pc as u64 | 1, CODE_START + code.len() as u64, 0, 1)
            .unwrap();

        pc = uc.reg_read(RegisterARM::PC).unwrap() as u32;
    }

    r2 = uc.reg_read(RegisterARM::R2).unwrap() as u32;
    r3 = uc.reg_read(RegisterARM::R3).unwrap() as u32;
    count = *uc.get_data();

    assert_eq!(r2, 0x68);
    assert_eq!(r3, 0x78);
    assert_eq!(count, 4);
}

#[test]
fn test_arm_m_thumb_mrs() {
    let code = &[
        0xef, 0xf3, 0x14, 0x80, // mrs r0, control
        0xef, 0xf3, 0x00, 0x81, // mrs r1, apsr
    ];
    let control = 0b10;
    let apsr = (0b10101 << 27) as u32;

    let mut uc = uc_common_setup(
        Arch::ARM,
        Mode::THUMB | Mode::MCLASS,
        Some(ArmCpuModel::CORTEX_A15 as i32),
        code,
        (),
    );

    uc.reg_write(RegisterARM::CONTROL, control as u64).unwrap();
    uc.reg_write(RegisterARM::APSR_NZCVQ, apsr as u64).unwrap();

    uc.emu_start(CODE_START | 1, CODE_START + code.len() as u64, 0, 0)
        .unwrap();

    let r0 = uc.reg_read(RegisterARM::R0).unwrap() as u32;
    let r1 = uc.reg_read(RegisterARM::R1).unwrap() as u32;

    assert_eq!(r0, 0b10);
    assert_eq!(r1, 0b10101 << 27);
}

#[test]
fn test_arm_m_control() {
    let mut uc = Unicorn::new(Arch::ARM, Mode::THUMB | Mode::MCLASS).unwrap();
    let mut control = 0;
    uc.reg_write(RegisterARM::CONTROL, control as u64).unwrap();

    let msp = 0x1000;
    uc.reg_write(RegisterARM::R13, msp as u64).unwrap();

    control = 0b10;
    uc.reg_write(RegisterARM::CONTROL, control as u64).unwrap();

    let psp = uc.reg_read(RegisterARM::R13).unwrap() as u32;
    assert_ne!(psp, msp);

    let psp = 0x2000;
    uc.reg_write(RegisterARM::R13, psp as u64).unwrap();

    control = 0;
    uc.reg_write(RegisterARM::CONTROL, control as u64).unwrap();

    let msp = uc.reg_read(RegisterARM::R13).unwrap() as u32;
    assert_ne!(psp, msp);
    assert_eq!(msp, 0x1000);
}

// NOTE:
// QEMU raise a special exception [`EXCP_EXCEPTION_EXIT`] to handle the
// [`EXC_RETURN`]. We can't help user handle [`EXC_RETURN`] since unicorn is designed
// not to handle any CPU exception.
#[test]
fn test_arm_m_exc_return() {
    let code = b"\x6f\xf0\x02\x00\x00\x47"; // mov r0, #0xFFFFFFFD; bx r0;
    let ipsr = 16;
    let mut sp = 0x8000;

    let mut uc = uc_common_setup(
        Arch::ARM,
        Mode::THUMB | Mode::MCLASS,
        Some(ArmCpuModel::CORTEX_A15 as i32),
        code,
        (),
    );

    uc.mem_map(sp - 0x1000, 0x1000, Prot::ALL).unwrap();
    uc.add_intr_hook(|uc, intno| {
        let pc = uc.reg_read(RegisterARM::PC).unwrap() as u32;
        assert_eq!(intno, 8); // EXCP_EXCEPTION_EXIT: Return from v7M exception.
        assert_eq!(pc | 1, 0xFFFFFFFD);
        uc.emu_stop().unwrap();
    })
    .unwrap();

    sp -= 0x1c;
    uc.reg_write(RegisterARM::SP, sp).unwrap();

    uc.reg_write(RegisterARM::IPSR, ipsr as u64).unwrap();

    uc.emu_start(CODE_START | 1, CODE_START + code.len() as u64, 0, 2)
        .unwrap();
}

/// For details, see <https://github.com/unicorn-engine/unicorn/issues/1494>.
#[test]
fn test_arm_und32_to_svc32() {
    let code = &[
        0x00, 0x00, 0xe0, 0xe3, // MVN r0, #0
        0x0e, 0xf0, 0xb0, 0xe1, // MOVS pc, lr
        0x00, 0x00, 0xe0, 0xe3, // MVN r0, #0
        0x00, 0x00, 0xe0, 0xe3, // MVN r0, #0
    ];
    let cpsr = 0x40000093; // SVC32
    let sp = 0x12345678;
    let spsr = 0x40000093; // Save previous CPSR
    let lr = CODE_START + 8;

    let mut uc = uc_common_setup(
        Arch::ARM,
        Mode::ARM,
        Some(ArmCpuModel::CORTEX_A9 as i32),
        code,
        (),
    );

    uc.reg_write(RegisterARM::CPSR, cpsr as u64).unwrap();
    uc.reg_write(RegisterARM::SP, sp as u64).unwrap();

    let cpsr = 0x4000009b; // UND32
    uc.reg_write(RegisterARM::CPSR, cpsr as u64).unwrap();
    uc.reg_write(RegisterARM::SPSR, spsr as u64).unwrap();
    uc.reg_write(RegisterARM::SP, 0xDEAD0000).unwrap();
    uc.reg_write(RegisterARM::LR, lr).unwrap();

    uc.emu_start(CODE_START, CODE_START + code.len() as u64, 0, 3)
        .unwrap();

    let sp = uc.reg_read(RegisterARM::SP).unwrap() as u32;
    assert_eq!(sp, 0x12345678);
}

#[test]
fn test_arm_usr32_to_svc32() {
    let mut uc = Unicorn::new(Arch::ARM, Mode::ARM).unwrap();
    uc.ctl_set_cpu_model(ArmCpuModel::CORTEX_A9 as i32).unwrap();

    // https://www.keil.com/pack/doc/CMSIS/Core_A/html/group__CMSIS__CPSR__M.html
    let mut cpsr = 0x40000093; // SVC32
    let mut sp = 0x12345678;
    let mut lr = 0x00102220;

    uc.reg_write(RegisterARM::CPSR, cpsr as u64).unwrap();
    uc.reg_write(RegisterARM::SP, sp as u64).unwrap();
    uc.reg_write(RegisterARM::LR, lr as u64).unwrap();

    cpsr = 0x4000009b; // UND32
    uc.reg_write(RegisterARM::CPSR, cpsr as u64).unwrap();
    let spsr = 0x40000093; // Save previous CPSR
    uc.reg_write(RegisterARM::SPSR, spsr as u64).unwrap();
    sp = 0xDEAD0000;
    uc.reg_write(RegisterARM::SP, sp as u64).unwrap();
    lr = 0x00509998;
    uc.reg_write(RegisterARM::LR, lr as u64).unwrap();

    cpsr = uc.reg_read(RegisterARM::CPSR).unwrap() as u32;
    assert_eq!(cpsr & ((1 << 4) - 1), 0xb); // We are in UND32

    cpsr = 0x40000090; // USR32
    uc.reg_write(RegisterARM::CPSR, cpsr as u64).unwrap();
    sp = 0x0010000;
    uc.reg_write(RegisterARM::R13, sp as u64).unwrap();
    lr = 0x0001234;
    uc.reg_write(RegisterARM::LR, lr as u64).unwrap();

    cpsr = uc.reg_read(RegisterARM::CPSR).unwrap() as u32;
    assert_eq!(cpsr & ((1 << 4) - 1), 0); // We are in USR32

    cpsr = 0x40000093; // SVC32
    uc.reg_write(RegisterARM::CPSR, cpsr as u64).unwrap();

    cpsr = uc.reg_read(RegisterARM::CPSR).unwrap() as u32;
    sp = uc.reg_read(RegisterARM::SP).unwrap() as u32;
    assert_eq!(cpsr & ((1 << 4) - 1), 3); // We are in SVC32
    assert_eq!(sp, 0x12345678);
}

#[test]
fn test_arm_v8() {
    let code = b"\xd0\xe8\xff\x17"; // LDAEXD.W R1, [R0]
    let r0 = 0x8000;
    let r1 = 0xdeadbeefu32;

    let mut uc = uc_common_setup(
        Arch::ARM,
        Mode::THUMB,
        Some(ArmCpuModel::CORTEX_M33 as i32),
        code,
        (),
    );

    uc.mem_map(r0, 0x1000, Prot::ALL).unwrap();
    uc.mem_write(r0, &r1.to_le_bytes()).unwrap();
    uc.reg_write(RegisterARM::R0, r0).unwrap();

    uc.emu_start(CODE_START | 1, CODE_START + code.len() as u64, 0, 0)
        .unwrap();

    let r1 = uc.reg_read(RegisterARM::R1).unwrap() as u32;
    assert_eq!(r1, 0xdeadbeef);
}

#[test]
fn test_arm_thumb_smlabb() {
    let code = b"\x13\xfb\x01\x23";
    let r1 = 7;
    let r2 = 9;
    let r3 = 5;

    let mut uc = uc_common_setup(
        Arch::ARM,
        Mode::THUMB,
        Some(ArmCpuModel::CORTEX_M7 as i32),
        code,
        (),
    );

    uc.reg_write(RegisterARM::R1, r1 as u64).unwrap();
    uc.reg_write(RegisterARM::R2, r2 as u64).unwrap();
    uc.reg_write(RegisterARM::R3, r3 as u64).unwrap();

    uc.emu_start(CODE_START | 1, CODE_START + code.len() as u64, 0, 0)
        .unwrap();

    let r3 = uc.reg_read(RegisterARM::R3).unwrap() as u32;
    assert_eq!(r3, 5 * 7 + 9);
}

#[test]
fn test_arm_not_allow_privilege_escalation() {
    #[rustfmt::skip]
    let code = &[
        0x1f, 0x60, 0xc6, 0xe3, // BIC r6, r6, #&1F
        0x13, 0x60, 0x86, 0xe3, // ORR r6, r6, #&13
        0x06, 0xf0, 0x21, 0xe1, // MSR cpsr_c, r6 ; switch to SVC32 (should be ineffective from USR32)
        0x00, 0x00, 0xa0, 0xe1, // MOV r0,r0
        0x11, 0x00, 0x00, 0xef, // SWI OS_Exit
    ];
    let cpsr = 0x40000013; // SVC32
    let sp = 0x12345678;
    let lr = 0x00102220;

    let mut uc = uc_common_setup(
        Arch::ARM,
        Mode::ARM,
        Some(ArmCpuModel::CORTEX_A15 as i32),
        code,
        (),
    );

    uc.reg_write(RegisterARM::CPSR, cpsr as u64).unwrap();
    uc.reg_write(RegisterARM::SP, sp as u64).unwrap();
    uc.reg_write(RegisterARM::LR, lr as u64).unwrap();

    let cpsr = 0x40000010; // USR32
    uc.reg_write(RegisterARM::CPSR, cpsr as u64).unwrap();
    let sp = 0x0010000;
    uc.reg_write(RegisterARM::SP, sp as u64).unwrap();
    let lr = 0x0001234;
    uc.reg_write(RegisterARM::LR, lr as u64).unwrap();

    let err = uc
        .emu_start(CODE_START, CODE_START + code.len() as u64, 0, 0)
        .unwrap_err();
    assert_eq!(err, uc_error::EXCEPTION);

    let sp = uc.reg_read(RegisterARM::SP).unwrap() as u32;
    let lr = uc.reg_read(RegisterARM::LR).unwrap() as u32;
    let cpsr = uc.reg_read(RegisterARM::CPSR).unwrap() as u32;

    assert_eq!(cpsr & ((1 << 4) - 1), 0); // Stay in USR32
    assert_eq!(lr, 0x1234);
    assert_eq!(sp, 0x10000);
}

#[test]
fn test_arm_mrc() {
    let code = b"\x1d\xee\x70\x1f"; // mrc p15, #0, r1, c13, c0, #3

    let mut uc = uc_common_setup(Arch::ARM, Mode::THUMB, None, code, ());

    uc.emu_start(CODE_START | 1, CODE_START + code.len() as u64, 0, 0)
        .unwrap();
}

#[test]
fn test_arm_hflags_rebuilt() {
    let code = &[
        0x00, 0x60, 0x0f, 0xe1, // MRS r6, apsr
        0x1f, 0x60, 0xc6, 0xe3, // BIC r6, r6, #&1F
        0x10, 0x60, 0x86, 0xe3, // ORR r6, r6, #&10
        0x06, 0xf0, 0x21, 0xe1, // MSR cpsr_c, r6
        0x16, 0x00, 0x02, 0xef, // SWI OS_EnterOS
        0x06, 0xf0, 0x21, 0xe1, // MSR cpsr_c, r6
    ];
    let cpsr = 0x40000013; // SVC32
    let sp = 0x12345678;
    let lr = 0x00102220;

    let mut uc = uc_common_setup(
        Arch::ARM,
        Mode::ARM,
        Some(ArmCpuModel::CORTEX_A9 as i32),
        code,
        (),
    );

    uc.reg_write(RegisterARM::CPSR, cpsr as u64).unwrap();
    uc.reg_write(RegisterARM::SP, sp as u64).unwrap();
    uc.reg_write(RegisterARM::LR, lr as u64).unwrap();

    let cpsr = 0x40000010; // USR32
    uc.reg_write(RegisterARM::CPSR, cpsr as u64).unwrap();
    let sp = 0x0010000;
    uc.reg_write(RegisterARM::R13, sp as u64).unwrap();
    let lr = 0x0001234;
    uc.reg_write(RegisterARM::R14, lr as u64).unwrap();

    let err = uc
        .emu_start(CODE_START, CODE_START + code.len() as u64, 0, 0)
        .unwrap_err();
    assert_eq!(err, uc_error::EXCEPTION);

    let cpsr = 0x60000013;
    uc.reg_write(RegisterARM::CPSR, cpsr as u64).unwrap();
    let cpsr = 0x60000010;
    uc.reg_write(RegisterARM::CPSR, cpsr as u64).unwrap();
    let cpsr = 0x60000013;
    uc.reg_write(RegisterARM::CPSR, cpsr as u64).unwrap();

    let pc = uc.reg_read(RegisterARM::PC).unwrap();
    uc.emu_start(pc, CODE_START + code.len() as u64, 0, 0)
        .unwrap();

    let cpsr = uc.reg_read(RegisterARM::CPSR).unwrap() as u32;
    let sp = uc.reg_read(RegisterARM::R13).unwrap() as u32;
    let lr = uc.reg_read(RegisterARM::R14).unwrap() as u32;

    assert_eq!(cpsr, 0x60000010);
    assert_eq!(sp, 0x00010000);
    assert_eq!(lr, 0x00001234);
}

#[test]
fn test_arm_mem_access_abort() {
    let code = &[
        0x00, 0x00, 0x90, 0xe5, // LDR r0, [r0]
        0x00, 0xa0, 0xf0, 0xf7, // Undefined instruction
    ];
    let r0 = 0x990000;

    let mut uc = uc_common_setup(
        Arch::ARM,
        Mode::ARM,
        Some(ArmCpuModel::CORTEX_A9 as i32),
        code,
        0,
    );

    uc.reg_write(RegisterARM::R0, r0 as u64).unwrap();

    uc.add_mem_hook(HookType::MEM_UNMAPPED, 1, 0, |uc, _, _, _, _| {
        *uc.get_data_mut() = uc.reg_read(RegisterARM::PC).unwrap();
        false
    })
    .unwrap();

    uc.add_insn_invalid_hook(|uc| {
        *uc.get_data_mut() = uc.reg_read(RegisterARM::PC).unwrap();
        false
    })
    .unwrap();

    let err = uc.emu_start(CODE_START, CODE_START + 4, 0, 0).unwrap_err();
    assert_eq!(err, uc_error::READ_UNMAPPED);

    let pc = uc.reg_read(RegisterARM::PC).unwrap();
    assert_eq!(pc, *uc.get_data());

    let err = uc
        .emu_start(CODE_START + 4, CODE_START + 8, 0, 0)
        .unwrap_err();
    assert_eq!(err, uc_error::INSN_INVALID);

    let pc = uc.reg_read(RegisterARM::PC).unwrap();
    assert_eq!(pc, *uc.get_data());

    let err = uc.emu_start(0x900000, 0x900000 + 8, 0, 0).unwrap_err();
    assert_eq!(err, uc_error::FETCH_UNMAPPED);

    let pc = uc.reg_read(RegisterARM::PC).unwrap();
    assert_eq!(pc, *uc.get_data());
}

#[test]
fn test_arm_read_sctlr() {
    let uc = Unicorn::new(Arch::ARM, Mode::ARM).unwrap();
    let mut reg = RegisterARMCP::new().cp(15).crn(1);
    uc.reg_read_arm_coproc(&mut reg).unwrap();
    assert_eq!((reg.val >> 31) & 1, 0);
}

#[test]
fn test_arm_be_cpsr_sctlr() {
    let mut uc = Unicorn::new(Arch::ARM, Mode::ARM | Mode::BIG_ENDIAN).unwrap();
    uc.ctl_set_cpu_model(ArmCpuModel::Model_1176 as i32)
        .unwrap();

    let mut reg = RegisterARMCP::new().cp(15).crn(1);
    uc.reg_read_arm_coproc(&mut reg).unwrap();
    let cpsr = uc.reg_read(RegisterARM::CPSR).unwrap();

    assert_ne!(reg.val & (1 << 7), 0);
    assert_ne!(cpsr & (1 << 9), 0);

    let mut uc = Unicorn::new(Arch::ARM, Mode::ARM | Mode::ARMBE8).unwrap();
    uc.ctl_set_cpu_model(ArmCpuModel::CORTEX_A15 as i32)
        .unwrap();

    let mut reg = RegisterARMCP::new().cp(15).crn(1);
    uc.reg_read_arm_coproc(&mut reg).unwrap();
    let cpsr = uc.reg_read(RegisterARM::CPSR).unwrap();

    // SCTLR.B == 0
    assert_eq!(reg.val & (1 << 7), 0);
    assert_ne!(cpsr & (1 << 9), 0);
}

#[test]
fn test_arm_switch_endian() {
    let code = b"\x00\x00\x91\xe5"; // ldr r0, [r1]

    let mut uc = uc_common_setup(
        Arch::ARM,
        Mode::ARM,
        Some(ArmCpuModel::CORTEX_A15 as i32),
        code,
        (),
    );

    let r1 = CODE_START;
    uc.reg_write(RegisterARM::R1, r1).unwrap();

    uc.emu_start(CODE_START, CODE_START + code.len() as u64, 0, 0)
        .unwrap();

    let r0 = uc.reg_read(RegisterARM::R0).unwrap();

    assert_eq!(r0, 0xe5910000);

    let mut cpsr = uc.reg_read(RegisterARM::CPSR).unwrap();
    cpsr |= 1 << 9;
    uc.reg_write(RegisterARM::CPSR, cpsr).unwrap();

    uc.emu_start(CODE_START, CODE_START + code.len() as u64, 0, 0)
        .unwrap();

    let r0 = uc.reg_read(RegisterARM::R0).unwrap();

    assert_eq!(r0, 0x000091e5);
}

#[test]
fn test_armeb_ldrb() {
    let code = b"\xe5\xd2\x10\x00"; // ldrb r1, [r2]
    let data_address = 0x800000;

    let mut uc = uc_common_setup(
        Arch::ARM,
        Mode::ARM | Mode::BIG_ENDIAN,
        Some(ArmCpuModel::Model_1176 as i32),
        code,
        (),
    );

    uc.mem_map(data_address, 1024 * 1024, Prot::ALL).unwrap();
    uc.mem_write(data_address, b"\x66\x67\x68\x69").unwrap();

    let mut r2 = data_address;
    uc.reg_write(RegisterARM::R2, r2).unwrap();
    uc.emu_start(CODE_START, CODE_START + code.len() as u64, 0, 0)
        .unwrap();
    let r1 = uc.reg_read(RegisterARM::R1).unwrap();
    assert_eq!(r1, 0x66);

    r2 += 1;
    uc.reg_write(RegisterARM::R2, r2).unwrap();
    uc.emu_start(CODE_START, CODE_START + code.len() as u64, 0, 0)
        .unwrap();
    let r1 = uc.reg_read(RegisterARM::R1).unwrap();
    assert_eq!(r1, 0x67);

    r2 += 1;
    uc.reg_write(RegisterARM::R2, r2).unwrap();
    uc.emu_start(CODE_START, CODE_START + code.len() as u64, 0, 0)
        .unwrap();
    let r1 = uc.reg_read(RegisterARM::R1).unwrap();
    assert_eq!(r1, 0x68);

    r2 += 1;
    uc.reg_write(RegisterARM::R2, r2).unwrap();
    uc.emu_start(CODE_START, CODE_START + code.len() as u64, 0, 0)
        .unwrap();
    let r1 = uc.reg_read(RegisterARM::R1).unwrap();
    assert_eq!(r1, 0x69);
}

#[test]
fn test_arm_context_save() {
    let code = b"\x83\xb0"; // sub sp, #0xc

    let uc = uc_common_setup(
        Arch::ARM,
        Mode::THUMB,
        Some(ArmCpuModel::CORTEX_R5 as i32),
        code,
        (),
    );

    let mut context = uc.context_alloc().unwrap();
    uc.context_save(&mut context).unwrap();

    let pc = context.reg_read(RegisterARM::PC).unwrap();
    context.reg_write(RegisterARM::PC, pc).unwrap();
    uc.context_restore(&context).unwrap();

    let uc2 = uc_common_setup(
        Arch::ARM,
        Mode::THUMB,
        Some(ArmCpuModel::CORTEX_A7 as i32), // NOTE: different CPU model
        code,
        (),
    );
    uc2.context_restore(&context).unwrap();

    let pc2 = uc2.reg_read(RegisterARM::PC).unwrap();
    assert_eq!(pc, pc2);
}

#[test]
fn test_arm_thumb2() {
    #[rustfmt::skip]
    let code = &[
        0x24, 0x20,             // MOVS R0, #0x24
        0x00, 0xF0, 0x04, 0x00, // AND.W R0, R0, #4
    ];

    let mut uc = uc_common_setup(
        Arch::ARM,
        Mode::THUMB | Mode::LITTLE_ENDIAN,
        Some(ArmCpuModel::CORTEX_R5 as i32),
        code,
        (),
    );

    uc.emu_start(CODE_START | 1, CODE_START + code.len() as u64, 0, 0)
        .unwrap();

    let r0 = uc.reg_read(RegisterARM::R0).unwrap();
    assert_eq!(r0, 0x4);
}

#[test]
fn test_armeb_be32_thumb2() {
    #[rustfmt::skip]
    let code = &[
        0x20, 0x24,             // MOVS R0, #0x24
        0xF0, 0x00, 0x00, 0x04, // AND.W R0, R0, #4
    ];

    let mut uc = uc_common_setup(
        Arch::ARM,
        Mode::THUMB | Mode::BIG_ENDIAN,
        Some(ArmCpuModel::CORTEX_R5 as i32),
        code,
        (),
    );

    uc.emu_start(CODE_START | 1, CODE_START + code.len() as u64, 0, 0)
        .unwrap();

    let r0 = uc.reg_read(RegisterARM::R0).unwrap();
    assert_eq!(r0, 0x4);
}

#[test]
fn test_arm_mem_hook_read_write() {
    #[rustfmt::skip]
    let code = &[
        0x00, 0x10, 0x9d, 0xe5, // ldr r1, [sp]
        0x04, 0x10, 0x8d, 0xe5, // str r1, [sp, #4]
        0x04, 0x20, 0x9d, 0xe5, // ldr r2, [sp, #4]
        0x00, 0x20, 0x8d, 0xe5, // str r2, [sp]
    ];

    let sp = 0x9000;

    let mut uc = uc_common_setup(
        Arch::ARM,
        Mode::ARM,
        Some(ArmCpuModel::CORTEX_A15 as i32),
        code,
        [0u64; 2],
    );

    uc.reg_write(RegisterARM::SP, sp).unwrap();
    uc.mem_map(0x8000, 1024 * 16, Prot::ALL).unwrap();

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
    assert_eq!(read, 2);
    assert_eq!(write, 2);
}

#[derive(Default)]
struct CmpInfo {
    v0: u64,
    v1: u64,
    size: u64,
    pc: u64,
}

fn uc_hook_sub_cmp(uc: &mut Unicorn<'_, CmpInfo>, address: u64, arg1: u64, arg2: u64, size: usize) {
    let data = uc.get_data_mut();
    data.pc = address;
    data.size = size as u64;
    data.v0 = arg1;
    data.v1 = arg2;
}

#[test]
fn test_arm_tcg_opcode_cmp() {
    let code = &[
        0x04, 0x00, 0x9f, 0xe5, // ldr r0, [pc, #4]
        0x04, 0x10, 0x9f, 0xe5, // ldr r1, [pc, #4]
        0x01, 0x00, 0x50, 0xe1, // cmp r0, r1
        0x05, 0x00, 0x00, 0x00, // (5)
        0x03, 0x00, 0x00, 0x00, // (3)
    ];

    let mut uc = uc_common_setup(
        Arch::ARM,
        Mode::ARM,
        Some(ArmCpuModel::CORTEX_A15 as i32),
        code,
        CmpInfo::default(),
    );

    uc.add_tcg_hook(TcgOpCode::SUB, TcgOpFlag::CMP, 1, 0, uc_hook_sub_cmp)
        .unwrap();

    uc.emu_start(CODE_START, CODE_START + code.len() as u64, 0, 3)
        .unwrap();

    let cmp_info = uc.get_data();
    assert_eq!(cmp_info.v0, 5);
    assert_eq!(cmp_info.v1, 3);
    assert_eq!(cmp_info.pc, 0x1008);
    assert_eq!(cmp_info.size, 32);
}

#[test]
fn test_arm_thumb_tcg_opcode_cmn() {
    #[rustfmt::skip]
    let code = &[
        0x01, 0x48,             // ldr r0, [pc #4]
        0x02, 0x49,             // ldr r1, [pc #8]
        0x00, 0xbf,             // nop
        0xc8, 0x42,             // cmn r0, r1
        0x05, 0x00, 0x00, 0x00, // (5)
        0x03, 0x00, 0x00, 0x00, // (3)
    ];

    let mut uc = uc_common_setup(
        Arch::ARM,
        Mode::THUMB,
        Some(ArmCpuModel::CORTEX_A15 as i32),
        code,
        CmpInfo::default(),
    );

    uc.add_tcg_hook(TcgOpCode::SUB, TcgOpFlag::CMP, 1, 0, uc_hook_sub_cmp)
        .unwrap();

    uc.emu_start(CODE_START | 1, CODE_START + code.len() as u64, 0, 4)
        .unwrap();

    let cmp_info = uc.get_data();
    assert_eq!(cmp_info.v0, 5);
    assert_eq!(cmp_info.v1, 3);
    assert_eq!(cmp_info.pc, 0x1006);
    assert_eq!(cmp_info.size, 32);
}

#[test]
fn test_arm_cp15_c1_c0_2() {
    let val = 0x12345678;

    // Initialize emulator in ARM mode
    let mut uc = Unicorn::new(Arch::ARM, Mode::ARM).unwrap();
    uc.ctl_set_cpu_model(ArmCpuModel::CORTEX_A15 as i32)
        .unwrap();

    // Write to CP15 C1_C0_2
    uc.reg_write(RegisterARM::C1_C0_2, val).unwrap();

    // Read from CP15 C1_C0_2
    let read_val = uc.reg_read(RegisterARM::C1_C0_2).unwrap();

    assert_eq!(val, read_val);
}
