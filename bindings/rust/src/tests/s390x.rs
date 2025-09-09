use unicorn_engine_sys::RegisterS390X;

use super::*;

#[test]
fn test_s390x_lr() {
    let code = [
        0x18, 0x23, // lr %r2, %r3
    ];

    let r3 = 0x114514;

    let mut uc = uc_common_setup(Arch::S390X, Mode::BIG_ENDIAN, None, &code, ());

    uc.reg_write(RegisterS390X::R3, r3).unwrap();

    uc.emu_start(CODE_START, CODE_START + code.len() as u64, 0, 0)
        .unwrap();

    let r2 = uc.reg_read(RegisterS390X::R2).unwrap();
    let pc = uc.reg_read(RegisterS390X::PC).unwrap();

    assert_eq!(r2, 0x114514);
    assert_eq!(pc, CODE_START + code.len() as u64);
}
