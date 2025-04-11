use unicorn_engine_sys::RegisterM68K;

use super::*;

#[test]
fn test_move_to_sr() {
    let code = [
        0x46, 0xfc, 0x27, 0x00, // move #$2700, sr
    ];

    let mut uc = uc_common_setup(Arch::M68K, Mode::BIG_ENDIAN, None, &code, ());

    let mut sr = uc.reg_read(RegisterM68K::SR).unwrap();
    sr |= 0x2000;
    uc.reg_write(RegisterM68K::SR, sr).unwrap(); // Set supervisor mode

    uc.emu_start(CODE_START, CODE_START + code.len() as u64, 0, 0)
        .unwrap();

    let sr = uc.reg_read(RegisterM68K::SR).unwrap();
    assert_eq!(sr, 0x2700);
}
