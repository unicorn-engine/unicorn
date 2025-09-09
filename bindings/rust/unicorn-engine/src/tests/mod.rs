extern crate std;

#[cfg(feature = "arch_arm")]
mod arm;
#[cfg(feature = "arch_aarch64")]
mod arm64;
mod ctl;
#[cfg(feature = "arch_m68k")]
mod m68k;
mod mem;
#[cfg(feature = "arch_mips")]
mod mips;
#[cfg(feature = "arch_ppc")]
mod ppc;
#[cfg(feature = "arch_riscv")]
mod riscv;
#[cfg(feature = "arch_s390x")]
mod s390x;

use crate::{Arch, HookType, Mode, Prot, TlbEntry, TlbType, Unicorn, uc_error};

pub const CODE_START: u64 = 0x1000;
pub const CODE_LEN: u64 = 0x4000;

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
