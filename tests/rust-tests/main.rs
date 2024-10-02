extern crate alloc;

use alloc::rc::Rc;
use core::cell::RefCell;
use unicorn_engine::unicorn_const::{
    uc_error, Arch, HookType, MemType, Mode, Permission, SECOND_SCALE, TlbEntry, TlbType
};
use unicorn_engine::{InsnSysX86, RegisterARM, RegisterMIPS, RegisterPPC, RegisterX86, Unicorn};

pub static X86_REGISTERS: [RegisterX86; 125] = [
    RegisterX86::AH,
    RegisterX86::AL,
    RegisterX86::AX,
    RegisterX86::BH,
    RegisterX86::BL,
    RegisterX86::BP,
    RegisterX86::BPL,
    RegisterX86::BX,
    RegisterX86::CH,
    RegisterX86::CL,
    RegisterX86::CS,
    RegisterX86::CX,
    RegisterX86::DH,
    RegisterX86::DI,
    RegisterX86::DIL,
    RegisterX86::DL,
    RegisterX86::DS,
    RegisterX86::DX,
    RegisterX86::EAX,
    RegisterX86::EBP,
    RegisterX86::EBX,
    RegisterX86::ECX,
    RegisterX86::EDI,
    RegisterX86::EDX,
    RegisterX86::EFLAGS,
    RegisterX86::EIP,
    RegisterX86::ES,
    RegisterX86::ESI,
    RegisterX86::ESP,
    RegisterX86::FPSW,
    RegisterX86::FS,
    RegisterX86::GS,
    RegisterX86::IP,
    RegisterX86::RAX,
    RegisterX86::RBP,
    RegisterX86::RBX,
    RegisterX86::RCX,
    RegisterX86::RDI,
    RegisterX86::RDX,
    RegisterX86::RIP,
    RegisterX86::RSI,
    RegisterX86::RSP,
    RegisterX86::SI,
    RegisterX86::SIL,
    RegisterX86::SP,
    RegisterX86::SPL,
    RegisterX86::SS,
    RegisterX86::CR0,
    RegisterX86::CR1,
    RegisterX86::CR2,
    RegisterX86::CR3,
    RegisterX86::CR4,
    RegisterX86::CR8,
    RegisterX86::DR0,
    RegisterX86::DR1,
    RegisterX86::DR2,
    RegisterX86::DR3,
    RegisterX86::DR4,
    RegisterX86::DR5,
    RegisterX86::DR6,
    RegisterX86::DR7,
    RegisterX86::FP0,
    RegisterX86::FP1,
    RegisterX86::FP2,
    RegisterX86::FP3,
    RegisterX86::FP4,
    RegisterX86::FP5,
    RegisterX86::FP6,
    RegisterX86::FP7,
    RegisterX86::K0,
    RegisterX86::K1,
    RegisterX86::K2,
    RegisterX86::K3,
    RegisterX86::K4,
    RegisterX86::K5,
    RegisterX86::K6,
    RegisterX86::K7,
    RegisterX86::MM0,
    RegisterX86::MM1,
    RegisterX86::MM2,
    RegisterX86::MM3,
    RegisterX86::MM4,
    RegisterX86::MM5,
    RegisterX86::MM6,
    RegisterX86::MM7,
    RegisterX86::R8,
    RegisterX86::R9,
    RegisterX86::R10,
    RegisterX86::R11,
    RegisterX86::R12,
    RegisterX86::R13,
    RegisterX86::R14,
    RegisterX86::R15,
    RegisterX86::ST0,
    RegisterX86::ST1,
    RegisterX86::ST2,
    RegisterX86::ST3,
    RegisterX86::ST4,
    RegisterX86::ST5,
    RegisterX86::ST6,
    RegisterX86::ST7,
    RegisterX86::R8B,
    RegisterX86::R9B,
    RegisterX86::R10B,
    RegisterX86::R11B,
    RegisterX86::R12B,
    RegisterX86::R13B,
    RegisterX86::R14B,
    RegisterX86::R15B,
    RegisterX86::R8D,
    RegisterX86::R9D,
    RegisterX86::R10D,
    RegisterX86::R11D,
    RegisterX86::R12D,
    RegisterX86::R13D,
    RegisterX86::R14D,
    RegisterX86::R15D,
    RegisterX86::R8W,
    RegisterX86::R9W,
    RegisterX86::R10W,
    RegisterX86::R11W,
    RegisterX86::R12W,
    RegisterX86::R13W,
    RegisterX86::R14W,
    RegisterX86::R15W,
];

#[test]
fn emulate_x86() {
    let x86_code32: Vec<u8> = vec![0x41, 0x4a]; // INC ecx; DEC edx

    let mut emu = unicorn_engine::Unicorn::new(Arch::X86, Mode::MODE_32)
        .expect("failed to initialize unicorn instance");
    assert_eq!(emu.reg_write(RegisterX86::EAX, 123), Ok(()));
    assert_eq!(emu.reg_read(RegisterX86::EAX), Ok(123));

    // Attempt to write to memory before mapping it.
    assert_eq!(
        emu.mem_write(0x1000, &x86_code32),
        (Err(uc_error::WRITE_UNMAPPED))
    );

    assert_eq!(emu.mem_map(0x1000, 0x4000, Permission::ALL), Ok(()));
    assert_eq!(emu.mem_write(0x1000, &x86_code32), Ok(()));
    assert_eq!(
        emu.mem_read_as_vec(0x1000, x86_code32.len()),
        Ok(x86_code32.clone())
    );

    assert_eq!(emu.reg_write(RegisterX86::ECX, 10), Ok(()));
    assert_eq!(emu.reg_write(RegisterX86::EDX, 50), Ok(()));

    assert_eq!(
        emu.emu_start(
            0x1000,
            (0x1000 + x86_code32.len()) as u64,
            10 * SECOND_SCALE,
            1000
        ),
        Ok(())
    );
    assert_eq!(emu.reg_read(RegisterX86::ECX), Ok(11));
    assert_eq!(emu.reg_read(RegisterX86::EDX), Ok(49));
}

#[test]
fn x86_code_callback() {
    #[derive(PartialEq, Debug)]
    struct CodeExpectation(u64, u32);
    let expects = vec![CodeExpectation(0x1000, 1), CodeExpectation(0x1001, 1)];
    let codes: Vec<CodeExpectation> = Vec::new();
    let codes_cell = Rc::new(RefCell::new(codes));

    let callback_codes = codes_cell.clone();
    let callback = move |_: &mut Unicorn<'_, ()>, address: u64, size: u32| {
        let mut codes = callback_codes.borrow_mut();
        codes.push(CodeExpectation(address, size));
    };

    let x86_code32: Vec<u8> = vec![0x41, 0x4a]; // INC ecx; DEC edx

    let mut emu = unicorn_engine::Unicorn::new(Arch::X86, Mode::MODE_32)
        .expect("failed to initialize unicorn instance");
    assert_eq!(emu.mem_map(0x1000, 0x4000, Permission::ALL), Ok(()));
    assert_eq!(emu.mem_write(0x1000, &x86_code32), Ok(()));

    let hook = emu
        .add_code_hook(0x1000, 0x2000, callback)
        .expect("failed to add code hook");
    assert_eq!(
        emu.emu_start(0x1000, 0x1002, 10 * SECOND_SCALE, 1000),
        Ok(())
    );
    assert_eq!(expects, *codes_cell.borrow());
    assert_eq!(emu.remove_hook(hook), Ok(()));
}

#[test]
fn x86_intr_callback() {
    #[derive(PartialEq, Debug)]
    struct IntrExpectation(u32);
    let expect = IntrExpectation(0x80);
    let intr_cell = Rc::new(RefCell::new(IntrExpectation(0)));

    let callback_intr = intr_cell.clone();
    let callback = move |_: &mut Unicorn<'_, ()>, intno: u32| {
        *callback_intr.borrow_mut() = IntrExpectation(intno);
    };

    let x86_code32: Vec<u8> = vec![0xcd, 0x80]; // INT 0x80;

    let mut emu = unicorn_engine::Unicorn::new(Arch::X86, Mode::MODE_32)
        .expect("failed to initialize unicorn instance");
    assert_eq!(emu.mem_map(0x1000, 0x4000, Permission::ALL), Ok(()));
    assert_eq!(emu.mem_write(0x1000, &x86_code32), Ok(()));

    let hook = emu
        .add_intr_hook(callback)
        .expect("failed to add intr hook");

    assert_eq!(
        emu.emu_start(
            0x1000,
            0x1000 + x86_code32.len() as u64,
            10 * SECOND_SCALE,
            1000
        ),
        Ok(())
    );
    assert_eq!(expect, *intr_cell.borrow());
    assert_eq!(emu.remove_hook(hook), Ok(()));
}

#[test]
fn x86_mem_callback() {
    #[derive(PartialEq, Debug)]
    struct MemExpectation(MemType, u64, usize, i64);
    let expects = vec![
        MemExpectation(MemType::WRITE, 0x2000, 4, 0xdeadbeef),
        MemExpectation(MemType::READ_UNMAPPED, 0x10000, 4, 0),
        MemExpectation(MemType::READ, 0x10000, 4, 0),
    ];
    let mems: Vec<MemExpectation> = Vec::new();
    let mems_cell = Rc::new(RefCell::new(mems));

    let callback_mems = mems_cell.clone();
    let callback = move |uc: &mut Unicorn<'_, ()>,
                         mem_type: MemType,
                         address: u64,
                         size: usize,
                         value: i64| {
        let mut mems = callback_mems.borrow_mut();

        mems.push(MemExpectation(mem_type, address, size, value));

        if mem_type == MemType::READ_UNMAPPED {
            uc.mem_map(address, 0x1000, Permission::ALL).unwrap();
        }
        true
    };

    // mov eax, 0xdeadbeef;
    // mov [0x2000], eax;
    // mov eax, [0x10000];
    let x86_code32: Vec<u8> = vec![
        0xB8, 0xEF, 0xBE, 0xAD, 0xDE, 0xA3, 0x00, 0x20, 0x00, 0x00, 0xA1, 0x00, 0x00, 0x01, 0x00,
    ];

    let mut emu = unicorn_engine::Unicorn::new(Arch::X86, Mode::MODE_32)
        .expect("failed to initialize unicorn instance");
    assert_eq!(emu.mem_map(0x1000, 0x4000, Permission::ALL), Ok(()));
    assert_eq!(emu.mem_write(0x1000, &x86_code32), Ok(()));

    let hook = emu
        .add_mem_hook(HookType::MEM_ALL, 0, u64::MAX, callback)
        .expect("failed to add memory hook");
    assert_eq!(emu.reg_write(RegisterX86::EAX, 0x123), Ok(()));
    assert_eq!(
        emu.emu_start(
            0x1000,
            0x1000 + x86_code32.len() as u64,
            10 * SECOND_SCALE,
            0x1000
        ),
        Ok(())
    );

    assert_eq!(expects, *mems_cell.borrow());
    assert_eq!(emu.remove_hook(hook), Ok(()));
}

#[test]
fn x86_insn_in_callback() {
    #[derive(PartialEq, Debug)]
    struct InsnInExpectation(u32, usize);
    let expect = InsnInExpectation(0x10, 4);
    let insn_cell = Rc::new(RefCell::new(InsnInExpectation(0, 0)));

    let callback_insn = insn_cell.clone();
    let callback = move |_: &mut Unicorn<()>, port: u32, size: usize| {
        *callback_insn.borrow_mut() = InsnInExpectation(port, size);
        42
    };

    let x86_code32: Vec<u8> = vec![0xe5, 0x10]; // IN eax, 0x10;

    let mut emu = unicorn_engine::Unicorn::new(Arch::X86, Mode::MODE_32)
        .expect("failed to initialize unicorn instance");
    assert_eq!(emu.mem_map(0x1000, 0x4000, Permission::ALL), Ok(()));
    assert_eq!(emu.mem_write(0x1000, &x86_code32), Ok(()));

    let hook = emu
        .add_insn_in_hook(callback)
        .expect("failed to add in hook");

    assert_eq!(
        emu.emu_start(
            0x1000,
            0x1000 + x86_code32.len() as u64,
            10 * SECOND_SCALE,
            1000
        ),
        Ok(())
    );
    assert_eq!(expect, *insn_cell.borrow());
    assert_eq!(emu.reg_read(RegisterX86::EAX), Ok(42));
    assert_eq!(emu.remove_hook(hook), Ok(()));
}

#[test]
fn x86_insn_out_callback() {
    #[derive(PartialEq, Debug)]
    struct InsnOutExpectation(u32, usize, u32);
    let expect = InsnOutExpectation(0x46, 1, 0x32);
    let insn_cell = Rc::new(RefCell::new(InsnOutExpectation(0, 0, 0)));

    let callback_insn = insn_cell.clone();
    let callback = move |_: &mut Unicorn<'_, ()>, port: u32, size: usize, value: u32| {
        *callback_insn.borrow_mut() = InsnOutExpectation(port, size, value);
    };

    let x86_code32: Vec<u8> = vec![0xb0, 0x32, 0xe6, 0x46]; // MOV al, 0x32; OUT  0x46, al;

    let mut emu = unicorn_engine::Unicorn::new(Arch::X86, Mode::MODE_32)
        .expect("failed to initialize unicorn instance");
    assert_eq!(emu.mem_map(0x1000, 0x4000, Permission::ALL), Ok(()));
    assert_eq!(emu.mem_write(0x1000, &x86_code32), Ok(()));

    let hook = emu
        .add_insn_out_hook(callback)
        .expect("failed to add out hook");

    assert_eq!(
        emu.emu_start(
            0x1000,
            0x1000 + x86_code32.len() as u64,
            10 * SECOND_SCALE,
            1000
        ),
        Ok(())
    );
    assert_eq!(expect, *insn_cell.borrow());
    assert_eq!(emu.remove_hook(hook), Ok(()));
}

#[test]
fn x86_insn_sys_callback() {
    #[derive(PartialEq, Debug)]
    struct InsnSysExpectation(u64);
    let expect = InsnSysExpectation(0xdeadbeef);
    let insn_cell = Rc::new(RefCell::new(InsnSysExpectation(0)));

    let callback_insn = insn_cell.clone();
    let callback = move |uc: &mut Unicorn<'_, ()>| {
        println!("!!!!");
        let rax = uc.reg_read(RegisterX86::RAX).unwrap();
        *callback_insn.borrow_mut() = InsnSysExpectation(rax);
    };

    // MOV rax, 0xdeadbeef; SYSCALL;
    let x86_code: Vec<u8> = vec![
        0x48, 0xB8, 0xEF, 0xBE, 0xAD, 0xDE, 0x00, 0x00, 0x00, 0x00, 0x0F, 0x05,
    ];

    let mut emu = unicorn_engine::Unicorn::new(Arch::X86, Mode::MODE_64)
        .expect("failed to initialize unicorn instance");
    assert_eq!(emu.mem_map(0x1000, 0x4000, Permission::ALL), Ok(()));
    assert_eq!(emu.mem_write(0x1000, &x86_code), Ok(()));

    let hook = emu
        .add_insn_sys_hook(InsnSysX86::SYSCALL, 1, 0, callback)
        .expect("failed to add syscall hook");

    assert_eq!(
        emu.emu_start(
            0x1000,
            0x1000 + x86_code.len() as u64,
            10 * SECOND_SCALE,
            1000
        ),
        Ok(())
    );
    assert_eq!(expect, *insn_cell.borrow());
    assert_eq!(emu.remove_hook(hook), Ok(()));
}

#[test]
fn x86_mmio() {
    #[derive(PartialEq, Debug)]
    struct MmioReadExpectation(u64, usize);
    #[derive(PartialEq, Debug)]
    struct MmioWriteExpectation(u64, usize, u64);
    let read_expect = MmioReadExpectation(4, 4);
    let write_expect = MmioWriteExpectation(8, 2, 42);

    let mut emu = unicorn_engine::Unicorn::new(Arch::X86, Mode::MODE_64)
        .expect("failed to initialize unicorn instance");
    assert_eq!(emu.mem_map(0x1000, 0x1000, Permission::ALL), Ok(()));

    {
        // MOV eax, [0x2004]; MOV [0x2008], ax;
        let x86_code: Vec<u8> = vec![
            0x8B, 0x04, 0x25, 0x04, 0x20, 0x00, 0x00, 0x66, 0x89, 0x04, 0x25, 0x08, 0x20, 0x00,
            0x00,
        ];

        let read_cell = Rc::new(RefCell::new(MmioReadExpectation(0, 0)));
        let cb_read_cell = read_cell.clone();
        let read_callback = move |_: &mut Unicorn<'_, ()>, offset, size| {
            *cb_read_cell.borrow_mut() = MmioReadExpectation(offset, size);
            42
        };

        let write_cell = Rc::new(RefCell::new(MmioWriteExpectation(0, 0, 0)));
        let cb_write_cell = write_cell.clone();
        let write_callback = move |_: &mut Unicorn<'_, ()>, offset, size, value| {
            *cb_write_cell.borrow_mut() = MmioWriteExpectation(offset, size, value);
        };

        assert_eq!(emu.mem_write(0x1000, &x86_code), Ok(()));

        assert_eq!(
            emu.mmio_map(0x2000, 0x1000, Some(read_callback), Some(write_callback)),
            Ok(())
        );

        assert_eq!(
            emu.emu_start(
                0x1000,
                0x1000 + x86_code.len() as u64,
                10 * SECOND_SCALE,
                1000
            ),
            Ok(())
        );

        assert_eq!(read_expect, *read_cell.borrow());
        assert_eq!(write_expect, *write_cell.borrow());

        assert_eq!(emu.mem_unmap(0x2000, 0x1000), Ok(()));
    }

    {
        // MOV eax, [0x2004];
        let x86_code: Vec<u8> = vec![0x8B, 0x04, 0x25, 0x04, 0x20, 0x00, 0x00];

        let read_cell = Rc::new(RefCell::new(MmioReadExpectation(0, 0)));
        let cb_read_cell = read_cell.clone();
        let read_callback = move |_: &mut Unicorn<'_, ()>, offset, size| {
            *cb_read_cell.borrow_mut() = MmioReadExpectation(offset, size);
            42
        };

        assert_eq!(emu.mem_write(0x1000, &x86_code), Ok(()));

        assert_eq!(emu.mmio_map_ro(0x2000, 0x1000, read_callback), Ok(()));

        assert_eq!(
            emu.emu_start(
                0x1000,
                0x1000 + x86_code.len() as u64,
                10 * SECOND_SCALE,
                1000
            ),
            Ok(())
        );

        assert_eq!(read_expect, *read_cell.borrow());

        assert_eq!(emu.mem_unmap(0x2000, 0x1000), Ok(()));
    }

    {
        // MOV ax, 42; MOV [0x2008], ax;
        let x86_code: Vec<u8> = vec![
            0x66, 0xB8, 0x2A, 0x00, 0x66, 0x89, 0x04, 0x25, 0x08, 0x20, 0x00, 0x00,
        ];

        let write_cell = Rc::new(RefCell::new(MmioWriteExpectation(0, 0, 0)));
        let cb_write_cell = write_cell.clone();
        let write_callback = move |_: &mut Unicorn<'_, ()>, offset, size, value| {
            *cb_write_cell.borrow_mut() = MmioWriteExpectation(offset, size, value);
        };

        assert_eq!(emu.mem_write(0x1000, &x86_code), Ok(()));

        assert_eq!(emu.mmio_map_wo(0x2000, 0x1000, write_callback), Ok(()));

        assert_eq!(
            emu.emu_start(
                0x1000,
                0x1000 + x86_code.len() as u64,
                10 * SECOND_SCALE,
                1000
            ),
            Ok(())
        );

        assert_eq!(write_expect, *write_cell.borrow());

        assert_eq!(emu.mem_unmap(0x2000, 0x1000), Ok(()));
    }
}

#[test]
fn emulate_arm() {
    let arm_code32: Vec<u8> = vec![0x83, 0xb0]; // sub    sp, #0xc

    let mut emu = unicorn_engine::Unicorn::new(Arch::ARM, Mode::THUMB)
        .expect("failed to initialize unicorn instance");
    assert_eq!(emu.reg_write(RegisterARM::R1, 123), Ok(()));
    assert_eq!(emu.reg_read(RegisterARM::R1), Ok(123));

    // Attempt to write to memory before mapping it.
    assert_eq!(
        emu.mem_write(0x1000, &arm_code32),
        (Err(uc_error::WRITE_UNMAPPED))
    );

    assert_eq!(emu.mem_map(0x1000, 0x4000, Permission::ALL), Ok(()));
    assert_eq!(emu.mem_write(0x1000, &arm_code32), Ok(()));
    assert_eq!(
        emu.mem_read_as_vec(0x1000, arm_code32.len()),
        Ok(arm_code32.clone())
    );

    assert_eq!(emu.reg_write(RegisterARM::SP, 12), Ok(()));
    assert_eq!(emu.reg_write(RegisterARM::R0, 10), Ok(()));

    // ARM checks the least significant bit of the address to know
    // if the code is in Thumb mode.
    assert_eq!(
        emu.emu_start(
            0x1000 | 0x01,
            (0x1000 | (0x01 + arm_code32.len())) as u64,
            10 * SECOND_SCALE,
            1000
        ),
        Ok(())
    );
    assert_eq!(emu.reg_read(RegisterARM::SP), Ok(0));
    assert_eq!(emu.reg_read(RegisterARM::R0), Ok(10));
}

#[test]
fn emulate_mips() {
    let mips_code32 = vec![0x56, 0x34, 0x21, 0x34]; // ori $at, $at, 0x3456;

    let mut emu = unicorn_engine::Unicorn::new(Arch::MIPS, Mode::MODE_32)
        .expect("failed to initialize unicorn instance");
    assert_eq!(emu.mem_map(0x1000, 0x4000, Permission::ALL), Ok(()));
    assert_eq!(emu.mem_write(0x1000, &mips_code32), Ok(()));
    assert_eq!(
        emu.mem_read_as_vec(0x1000, mips_code32.len()),
        Ok(mips_code32.clone())
    );
    assert_eq!(emu.reg_write(RegisterMIPS::AT, 0), Ok(()));
    assert_eq!(
        emu.emu_start(
            0x1000,
            (0x1000 + mips_code32.len()) as u64,
            10 * SECOND_SCALE,
            1000
        ),
        Ok(())
    );
    assert_eq!(emu.reg_read(RegisterMIPS::AT), Ok(0x3456));
}

#[test]
fn emulate_ppc() {
    let ppc_code32 = vec![0x7F, 0x46, 0x1A, 0x14]; // add 26, 6, 3

    let mut emu = unicorn_engine::Unicorn::new(Arch::PPC, Mode::PPC32 | Mode::BIG_ENDIAN)
        .expect("failed to initialize unicorn instance");
    assert_eq!(emu.mem_map(0x1000, 0x4000, Permission::ALL), Ok(()));
    assert_eq!(emu.mem_write(0x1000, &ppc_code32), Ok(()));
    assert_eq!(
        emu.mem_read_as_vec(0x1000, ppc_code32.len()),
        Ok(ppc_code32.clone())
    );
    assert_eq!(emu.reg_write(RegisterPPC::R3, 42), Ok(()));
    assert_eq!(emu.reg_write(RegisterPPC::R6, 1337), Ok(()));
    assert_eq!(
        emu.emu_start(
            0x1000,
            (0x1000 + ppc_code32.len()) as u64,
            10 * SECOND_SCALE,
            1000
        ),
        Ok(())
    );
    assert_eq!(emu.reg_read(RegisterPPC::R26), Ok(1379));
}

#[test]
fn mem_unmapping() {
    let mut emu = unicorn_engine::Unicorn::new(Arch::X86, Mode::MODE_32)
        .expect("failed to initialize unicorn instance");
    assert_eq!(emu.mem_map(0x1000, 0x4000, Permission::ALL), Ok(()));
    assert_eq!(emu.mem_unmap(0x1000, 0x4000), Ok(()));
}

#[test]
fn mem_map_ptr() {
    // Use an array for the emulator memory.
    let mut mem: [u8; 4000] = [0; 4000];
    let x86_code32: Vec<u8> = vec![0x41, 0x4a]; // INC ecx; DEC edx

    let mut emu = unicorn_engine::Unicorn::new(Arch::X86, Mode::MODE_32)
        .expect("failed to initialize unicorn instance");

    // Attempt to write to memory before mapping it.
    assert_eq!(
        emu.mem_write(0x1000, &x86_code32),
        (Err(uc_error::WRITE_UNMAPPED))
    );

    assert_eq!(
        unsafe { emu.mem_map_ptr(0x1000, 0x4000, Permission::ALL, mem.as_mut_ptr() as _) },
        Ok(())
    );
    assert_eq!(emu.mem_write(0x1000, &x86_code32), Ok(()));
    assert_eq!(
        emu.mem_read_as_vec(0x1000, x86_code32.len()),
        Ok(x86_code32.clone())
    );

    assert_eq!(emu.reg_write(RegisterX86::ECX, 10), Ok(()));
    assert_eq!(emu.reg_write(RegisterX86::EDX, 50), Ok(()));

    assert_eq!(
        emu.emu_start(
            0x1000,
            (0x1000 + x86_code32.len()) as u64,
            10 * SECOND_SCALE,
            1000
        ),
        Ok(())
    );
    assert_eq!(emu.reg_read(RegisterX86::ECX), Ok(11));
    assert_eq!(emu.reg_read(RegisterX86::EDX), Ok(49));
    assert_eq!(emu.mem_unmap(0x1000, 0x4000), Ok(()));

    // Use a Vec for the emulator memory.
    let mut mem: Vec<u8> = Vec::new();
    mem.reserve(4000);

    // Attempt to write to memory before mapping it.
    assert_eq!(
        emu.mem_write(0x1000, &x86_code32),
        (Err(uc_error::WRITE_UNMAPPED))
    );

    assert_eq!(
        unsafe { emu.mem_map_ptr(0x1000, 0x4000, Permission::ALL, mem.as_mut_ptr() as _) },
        Ok(())
    );
    assert_eq!(emu.mem_write(0x1000, &x86_code32), Ok(()));
    assert_eq!(
        emu.mem_read_as_vec(0x1000, x86_code32.len()),
        Ok(x86_code32.clone())
    );

    assert_eq!(emu.reg_write(RegisterX86::ECX, 10), Ok(()));
    assert_eq!(emu.reg_write(RegisterX86::EDX, 50), Ok(()));

    assert_eq!(
        emu.emu_start(
            0x1000,
            (0x1000 + x86_code32.len()) as u64,
            10 * SECOND_SCALE,
            1000
        ),
        Ok(())
    );
    assert_eq!(emu.reg_read(RegisterX86::ECX), Ok(11));
    assert_eq!(emu.reg_read(RegisterX86::EDX), Ok(49));
    assert_eq!(emu.mem_unmap(0x1000, 0x4000), Ok(()));
}

#[test]
fn x86_context_save_and_restore() {
    for mode in [Mode::MODE_32, Mode::MODE_64] {
        let x86_code = [
            0x48, 0xB8, 0xEF, 0xBE, 0xAD, 0xDE, 0x00, 0x00, 0x00, 0x00, 0x0F, 0x05,
        ];
        let mut emu = unicorn_engine::Unicorn::new(Arch::X86, mode)
            .expect("failed to initialize unicorn instance");
        assert_eq!(emu.mem_map(0x1000, 0x4000, Permission::ALL), Ok(()));
        assert_eq!(emu.mem_write(0x1000, &x86_code), Ok(()));
        let _ = emu.emu_start(
            0x1000,
            (0x1000 + x86_code.len()) as u64,
            10 * SECOND_SCALE,
            1000,
        );

        /* now, save the context... */
        let context = emu.context_init();
        let context = context.unwrap();

        /* and create a new emulator, into which we will "restore" that context */
        let emu2 = unicorn_engine::Unicorn::new(Arch::X86, mode)
            .expect("failed to initialize unicorn instance");
        assert_eq!(emu2.context_restore(&context), Ok(()));
        for register in X86_REGISTERS.iter() {
            println!("Testing register {:?}", register);
            assert_eq!(emu2.reg_read(*register), emu.reg_read(*register));
        }
    }
}

#[test]
fn x86_block_callback() {
    #[derive(PartialEq, Debug)]
    struct BlockExpectation(u64, u32);
    let expects = vec![BlockExpectation(0x1000, 2)];
    let blocks: Vec<BlockExpectation> = Vec::new();
    let blocks_cell = Rc::new(RefCell::new(blocks));

    let callback_blocks = blocks_cell.clone();
    let callback = move |_: &mut Unicorn<'_, ()>, address: u64, size: u32| {
        let mut blocks = callback_blocks.borrow_mut();
        blocks.push(BlockExpectation(address, size));
    };

    let x86_code32: Vec<u8> = vec![0x41, 0x4a]; // INC ecx; DEC edx

    let mut emu = unicorn_engine::Unicorn::new(Arch::X86, Mode::MODE_32)
        .expect("failed to initialize unicorn instance");
    assert_eq!(emu.mem_map(0x1000, 0x4000, Permission::ALL), Ok(()));
    assert_eq!(emu.mem_write(0x1000, &x86_code32), Ok(()));

    let hook = emu
        .add_block_hook(1, 0, callback)
        .expect("failed to add block hook");
    assert_eq!(
        emu.emu_start(0x1000, 0x1002, 10 * SECOND_SCALE, 1000),
        Ok(())
    );
    assert_eq!(expects, *blocks_cell.borrow());
    assert_eq!(emu.remove_hook(hook), Ok(()));
}

#[test]
fn x86_tlb_callback() {
    #[derive(PartialEq, Debug)]
    struct BlockExpectation(u64, u32);
    let expects:u64 = 4;
    let count: u64 = 0;
    let count_cell = Rc::new(RefCell::new(count));

    let callback_counter = count_cell.clone();
    let tlb_callback = move |_: &mut Unicorn<'_, ()>, address: u64, _: MemType| -> Option<TlbEntry> {
        let mut blocks = callback_counter.borrow_mut();
        *blocks += 1;
        return Some(TlbEntry{paddr: address, perms: Permission::ALL});
    };

    let syscall_callback = move |uc:  &mut Unicorn<'_, ()>| {
        assert_eq!(uc.ctl_flush_tlb(), Ok(()));
    };

    let code: Vec<u8> = vec![0xa3,0x00,0x00,0x20,0x00,0x00,0x00,0x00,0x00,0x0f,0x05,0xa3,0x00,0x00,0x20,0x00,0x00,0x00,0x00,0x00]; // movabs  dword ptr [0x200000], eax; syscall; movabs  dword ptr [0x200000], eax

    let mut emu = unicorn_engine::Unicorn::new(Arch::X86, Mode::MODE_64)
        .expect("failed to initialize unicorn instance");
    assert_eq!(emu.ctl_tlb_type(TlbType::VIRTUAL), Ok(()));
    assert_eq!(emu.mem_map(0x1000, 0x1000, Permission::ALL), Ok(()));
    assert_eq!(emu.mem_map(0x200000, 0x1000, Permission::ALL), Ok(()));
    assert_eq!(emu.mem_write(0x1000, &code), Ok(()));

    let tlb_hook = emu
        .add_tlb_hook(0, !0u64, tlb_callback)
        .expect("failed to add tlb hook");
    let syscall_hook = emu
        .add_insn_sys_hook(InsnSysX86::SYSCALL, 0, !0u64, syscall_callback)
        .expect("failed to add syscall hook");
    assert_eq!(
        emu.emu_start(0x1000, (0x1000 + code.len()) as u64, 0, 0),
        Ok(())
    );
    assert_eq!(expects, *count_cell.borrow());
    assert_eq!(emu.remove_hook(tlb_hook), Ok(()));
    assert_eq!(emu.remove_hook(syscall_hook), Ok(()));
}
