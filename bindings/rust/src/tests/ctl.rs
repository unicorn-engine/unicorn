use std::time::{Duration, Instant};

use unicorn_engine_sys::{RegisterX86, X86Insn};

use super::*;
use crate::Unicorn;

#[test]
fn test_uc_ctl_mode() {
    let uc = Unicorn::new(Arch::X86, Mode::MODE_32).unwrap();
    let mode = uc.ctl_get_mode().unwrap();
    assert_eq!(mode, Mode::MODE_32);
}

#[test]
fn test_uc_ctl_arch() {
    let uc = Unicorn::new(Arch::X86, Mode::MODE_32).unwrap();
    let arch = uc.ctl_get_arch().unwrap();
    assert_eq!(arch, Arch::X86);
}

#[test]
fn test_uc_ctl_page_size() {
    let uc = Unicorn::new(Arch::X86, Mode::MODE_32).unwrap();
    let page_size = uc.ctl_get_page_size().unwrap();
    assert_eq!(page_size, 4096);
}

#[test]
fn test_uc_ctl_timeout() {
    let uc = Unicorn::new(Arch::X86, Mode::MODE_32).unwrap();
    let timeout = uc.ctl_get_timeout().unwrap();
    assert_eq!(timeout, 0);
}

#[test]
fn test_uc_ctl_exits() {
    //   cmp eax, 0;
    //   jg lb;
    //   inc eax;
    //   nop;       <---- exit1
    // lb:
    //   inc ebx;
    //   nop;      <---- exit2
    let code = b"\x83\xf8\x00\x7f\x02\x40\x90\x43\x90";
    let eax = 0;
    let ebx = 0;
    let exits = [CODE_START + 6, CODE_START + 8];

    let mut uc = Unicorn::new(Arch::X86, Mode::MODE_32).unwrap();
    uc.mem_map(CODE_START, CODE_LEN, Prot::ALL).unwrap();
    uc.mem_write(CODE_START, code).unwrap();

    uc.ctl_exits_enable().unwrap();
    uc.ctl_set_exits(&exits).unwrap();

    uc.reg_write(RegisterX86::EAX, eax).unwrap();
    uc.reg_write(RegisterX86::EBX, ebx).unwrap();

    // Run twice.
    uc.emu_start(CODE_START, 0, 0, 0).unwrap();
    uc.emu_start(CODE_START, 0, 0, 0).unwrap();

    let eax = uc.reg_read(RegisterX86::EAX).unwrap();
    let ebx = uc.reg_read(RegisterX86::EBX).unwrap();

    assert_eq!(eax, 1);
    assert_eq!(ebx, 1);
}

#[test]
fn test_uc_ctl_tb_cache() {
    fn time_emulation(uc: &mut Unicorn<'_, ()>, start: u64, end: u64) -> Duration {
        let now = Instant::now();
        uc.emu_start(start, end, 0, 0).unwrap();
        now.elapsed()
    }

    const TB_COUNT: usize = 8;
    const TCG_MAX_INSNS: usize = 512;
    const CODE_LEN: usize = TB_COUNT * TCG_MAX_INSNS;

    let code = [0x90; CODE_LEN]; // nop

    let mut uc = Unicorn::new(Arch::X86, Mode::MODE_32).unwrap();
    uc.mem_map(CODE_START, CODE_LEN.try_into().unwrap(), Prot::ALL)
        .unwrap();
    uc.mem_write(CODE_START, &code).unwrap();

    let standard = time_emulation(&mut uc, CODE_START, CODE_START + code.len() as u64);

    for i in 0..TB_COUNT {
        uc.ctl_request_cache(CODE_START + (i * TCG_MAX_INSNS) as u64, None)
            .unwrap();
    }
    let cached = time_emulation(&mut uc, CODE_START, CODE_START + code.len() as u64);

    for i in 0..TB_COUNT {
        let start = CODE_START + (i * TCG_MAX_INSNS) as u64;
        uc.ctl_remove_cache(start, start + 1).unwrap();
    }
    let evicted = time_emulation(&mut uc, CODE_START, CODE_START + code.len() as u64);

    assert!(cached < standard);
    assert!(evicted > cached);
}

#[cfg(feature = "arch_arm")]
#[test]
fn test_uc_ctl_change_page_size() {
    let mut uc = Unicorn::new(Arch::ARM, Mode::ARM).unwrap();
    let mut uc2 = Unicorn::new(Arch::ARM, Mode::ARM).unwrap();

    uc2.ctl_set_page_size(4096).unwrap();
    let page_size = uc2.ctl_get_page_size().unwrap();
    assert_eq!(page_size, 4096);

    // Mapping at 0x400 (1024) should succeed for the first Unicorn instance,
    // but fail for the second instance since the page size is different.
    // (Note: ARM's default page size is 1024)
    assert!(uc.mem_map(1 << 10, 1 << 10, Prot::ALL).is_ok());
    assert!(uc2.mem_map(1 << 10, 1 << 10, Prot::ALL).is_err());
}

#[cfg(feature = "arch_arm")]
#[test]
fn test_uc_ctl_arm_cpu() {
    use unicorn_engine_sys::ArmCpuModel;

    let mut uc = Unicorn::new(Arch::ARM, Mode::THUMB).unwrap();
    uc.ctl_set_cpu_model(ArmCpuModel::CORTEX_M7 as i32).unwrap();
}

#[cfg(feature = "arch_arm")]
#[test]
fn test_uc_ctl_change_page_size_arm64() {
    let mut uc = Unicorn::new(Arch::ARM64, Mode::ARM).unwrap();
    let mut uc2 = Unicorn::new(Arch::ARM64, Mode::ARM).unwrap();

    uc2.ctl_set_page_size(16384).unwrap();
    let page_size = uc2.ctl_get_page_size().unwrap();
    assert_eq!(page_size, 16384);

    // Mapping at 0x400 (1024) should succeed for the first Unicorn instance,
    // but fail for the second instance since the page size is different.
    // (Note: ARM64's default page size is 1024)
    assert!(uc.mem_map(1 << 10, 1 << 10, Prot::ALL).is_ok());
    assert!(uc2.mem_map(1 << 10, 1 << 10, Prot::ALL).is_err());
}

#[test]
fn test_uc_hook_cached_uaf() {
    let code = b"\x41\x4a\xeb\x00\x90";

    let mut uc = Unicorn::new_with_data(Arch::X86, Mode::MODE_32, 0u64).unwrap();
    uc.mem_map(CODE_START, CODE_LEN, Prot::ALL).unwrap();
    uc.mem_write(CODE_START, code).unwrap();

    let hook = uc
        .add_code_hook(CODE_START, CODE_START + code.len() as u64, |uc, _, _| {
            *uc.get_data_mut() += 1;
        })
        .unwrap();

    uc.emu_start(CODE_START, CODE_START + code.len() as u64, 0, 0)
        .unwrap();

    // Move the hook to the deleted hooks list.
    uc.remove_hook(hook).unwrap();

    // This will clear deleted hooks and SHOULD clear cache.
    uc.emu_start(CODE_START, CODE_START + code.len() as u64, 0, 0)
        .unwrap();

    // Now hooks are deleted and thus this _should not_ call
    // test_uc_hook_cached_cb anymore. If the hook is allocated like from
    // malloc, and the code region is free-ed, this call _shall not_ call the
    // hook anymore to avoid UAF.
    uc.emu_start(CODE_START, CODE_START + code.len() as u64, 0, 0)
        .unwrap();

    // Only 4 calls
    assert_eq!(*uc.get_data(), 4);
}

#[test]
fn test_uc_emu_stop_set_ip() {
    #[rustfmt::skip]
    let code = &[
        0x48, 0x31, 0xc0, // 0x0    xor rax, rax : rax = 0
        0x90,             // 0x3    nop          :
        0x48, 0xff, 0xc0, // 0x4    inc rax      : rax++
        0x90,             // 0x7    nop          : <-- going to stop here
        0x48, 0xff, 0xc0, // 0x8    inc rax      : rax++
        0x90,             // 0xb    nop          :
        0x0f, 0x0b,       // 0xc    ud2          : <-- will raise UC_ERR_INSN_INVALID,
                          //                     :     but should not never be reached
        0x90,             // 0xe    nop          :
        0x90,             // 0xf    nop          :
    ];

    let mut uc = Unicorn::new(Arch::X86, Mode::MODE_64).unwrap();
    uc.mem_map(CODE_START, CODE_LEN, Prot::ALL).unwrap();
    uc.mem_write(CODE_START, code).unwrap();

    uc.add_code_hook(
        CODE_START,
        CODE_START + code.len() as u64,
        |uc, address, _| {
            let rip = CODE_START + 0xb;
            if address == CODE_START + 0x7 {
                uc.emu_stop().unwrap();
                uc.reg_write(RegisterX86::RIP, rip).unwrap();
            }
        },
    )
    .unwrap();

    uc.emu_start(CODE_START, CODE_START + code.len() as u64, 0, 0)
        .unwrap();

    let rip = uc.reg_read(RegisterX86::RIP).unwrap();
    assert_eq!(rip, CODE_START + 0xb);
}

#[test]
fn test_tlb_clear() {
    #[rustfmt::skip]
    let code = &[
        0xa3, 0x00, 0x00, 0x20, 0x00, 0x00, 0x00, 0x00, 0x00, // movabs  dword ptr [0x200000], eax
        0x0f, 0x05,                                           // syscall
        0xa3, 0x00, 0x00, 0x20, 0x00, 0x00, 0x00, 0x00, 0x00, // movabs  dword ptr [0x200000], eax
    ];

    let mut uc = Unicorn::new_with_data(Arch::X86, Mode::MODE_64, 0usize).unwrap();
    uc.mem_map(CODE_START, CODE_LEN.try_into().unwrap(), Prot::ALL)
        .unwrap();
    uc.mem_write(CODE_START, code).unwrap();

    uc.mem_map(0x200000, 0x1000, Prot::ALL).unwrap();

    uc.ctl_set_tlb_type(TlbType::VIRTUAL).unwrap();
    uc.add_tlb_hook(1, 0, |uc, addr, _| {
        *uc.get_data_mut() += 1;
        Some(TlbEntry {
            paddr: addr,
            perms: Prot::ALL,
        })
    })
    .unwrap();
    uc.add_insn_sys_hook(X86Insn::SYSCALL, 1, 0, |uc| {
        uc.ctl_flush_tlb().unwrap();
    })
    .unwrap();

    uc.emu_start(CODE_START, CODE_START + code.len() as u64, 0, 0)
        .unwrap();

    let tlbcount = *uc.get_data();
    assert_eq!(tlbcount, 4);
}

#[test]
fn test_noexec() {
    #[rustfmt::skip]
    let code = &[
        0x8a, 0x05, 0x00, 0x00, 0x00, 0x00, // mov al, byte ptr[rip]
        0x90,                               // nop
    ];

    let mut uc = Unicorn::new(Arch::X86, Mode::MODE_64).unwrap();
    uc.mem_map(CODE_START, CODE_LEN, Prot::ALL).unwrap();
    uc.mem_write(CODE_START, code).unwrap();

    uc.ctl_set_tlb_type(TlbType::VIRTUAL).unwrap();
    uc.mem_protect(CODE_START, CODE_START as u64 + 0x1000, Prot::EXEC)
        .unwrap();

    let err = uc
        .emu_start(CODE_START, CODE_START + code.len() as u64, 0, 0)
        .unwrap_err();
    assert_eq!(err, uc_error::READ_PROT);
}
