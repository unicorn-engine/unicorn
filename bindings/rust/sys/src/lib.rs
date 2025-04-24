#![allow(non_camel_case_types)]

mod bindings;
pub use bindings::*;

impl uc_error {
    /// Calls `op` if the result is Ok, otherwise returns the [`Err`] value of `self`.
    pub fn and_then<U, F: FnOnce() -> Result<U, Self>>(self, op: F) -> Result<U, Self> {
        if self == Self::OK { op() } else { Err(self) }
    }

    /// Returns `res` if the result is Ok, otherwise returns the [`Err`] value of `self`.
    /// Arguments passed to this are eagerly evaluated; if you are passing the result
    /// of a function call, it is recommended to use [`uc_error::and_then`] instead, as it's lazily
    /// evaluated.
    pub fn and<U>(self, res: Result<U, Self>) -> Result<U, Self> {
        if self == Self::OK { res } else { Err(self) }
    }
}

impl From<uc_error> for Result<(), uc_error> {
    fn from(value: uc_error) -> Self {
        if value == uc_error::OK {
            Ok(())
        } else {
            Err(value)
        }
    }
}

impl core::fmt::Display for uc_error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let error_raw_str = unsafe { uc_strerror(*self) };
        let error_c_str = unsafe { core::ffi::CStr::from_ptr(error_raw_str) };
        write!(f, "{}", error_c_str.to_str().unwrap())
    }
}

impl core::error::Error for uc_error {}

impl TryFrom<usize> for Arch {
    type Error = uc_error;

    fn try_from(v: usize) -> Result<Self, Self::Error> {
        match v {
            x if x == Self::ARM as usize => Ok(Self::ARM),
            x if x == Self::ARM64 as usize => Ok(Self::ARM64),
            x if x == Self::MIPS as usize => Ok(Self::MIPS),
            x if x == Self::X86 as usize => Ok(Self::X86),
            x if x == Self::PPC as usize => Ok(Self::PPC),
            x if x == Self::SPARC as usize => Ok(Self::SPARC),
            x if x == Self::M68K as usize => Ok(Self::M68K),
            x if x == Self::RISCV as usize => Ok(Self::RISCV),
            x if x == Self::S390X as usize => Ok(Self::S390X),
            x if x == Self::TRICORE as usize => Ok(Self::TRICORE),
            x if x == Self::MAX as usize => Ok(Self::MAX),
            _ => Err(uc_error::ARCH),
        }
    }
}

impl TryFrom<i32> for Mode {
    type Error = uc_error;

    #[allow(clippy::cognitive_complexity)]
    fn try_from(v: i32) -> Result<Self, Self::Error> {
        match v {
            x if x == Self::LITTLE_ENDIAN.0 as i32 => Ok(Self::LITTLE_ENDIAN),
            x if x == Self::BIG_ENDIAN.0 as i32 => Ok(Self::BIG_ENDIAN),
            x if x == Self::ARM.0 as i32 => Ok(Self::ARM),
            x if x == Self::THUMB.0 as i32 => Ok(Self::THUMB),
            x if x == Self::MCLASS.0 as i32 => Ok(Self::MCLASS),
            x if x == Self::V8.0 as i32 => Ok(Self::V8),
            x if x == Self::ARMBE8.0 as i32 => Ok(Self::ARMBE8),
            x if x == Self::ARM926.0 as i32 => Ok(Self::ARM926),
            x if x == Self::ARM946.0 as i32 => Ok(Self::ARM946),
            x if x == Self::ARM1176.0 as i32 => Ok(Self::ARM1176),
            x if x == Self::MICRO.0 as i32 => Ok(Self::MICRO),
            x if x == Self::MIPS3.0 as i32 => Ok(Self::MIPS3),
            x if x == Self::MIPS32R6.0 as i32 => Ok(Self::MIPS32R6),
            x if x == Self::MIPS32.0 as i32 => Ok(Self::MIPS32),
            x if x == Self::MIPS64.0 as i32 => Ok(Self::MIPS64),
            x if x == Self::MODE_16.0 as i32 => Ok(Self::MODE_16),
            x if x == Self::MODE_32.0 as i32 => Ok(Self::MODE_32),
            x if x == Self::MODE_64.0 as i32 => Ok(Self::MODE_64),
            x if x == Self::PPC32.0 as i32 => Ok(Self::PPC32),
            x if x == Self::PPC64.0 as i32 => Ok(Self::PPC64),
            x if x == Self::QPX.0 as i32 => Ok(Self::QPX),
            x if x == Self::SPARC32.0 as i32 => Ok(Self::SPARC32),
            x if x == Self::SPARC64.0 as i32 => Ok(Self::SPARC64),
            x if x == Self::V9.0 as i32 => Ok(Self::V9),
            x if x == Self::RISCV32.0 as i32 => Ok(Self::RISCV32),
            x if x == Self::RISCV64.0 as i32 => Ok(Self::RISCV64),
            _ => Err(uc_error::MODE),
        }
    }
}

impl HookType {
    pub const MEM_UNMAPPED: Self =
        Self(Self::MEM_READ_UNMAPPED.0 | Self::MEM_WRITE_UNMAPPED.0 | Self::MEM_FETCH_UNMAPPED.0);

    pub const MEM_PROT: Self =
        Self(Self::MEM_READ_PROT.0 | Self::MEM_WRITE_PROT.0 | Self::MEM_FETCH_PROT.0);

    pub const MEM_VALID: Self = Self(Self::MEM_READ.0 | Self::MEM_WRITE.0 | Self::MEM_FETCH.0);

    pub const MEM_READ_INVALID: Self = Self(Self::MEM_READ_UNMAPPED.0 | Self::MEM_READ_PROT.0);

    pub const MEM_WRITE_INVALID: Self = Self(Self::MEM_WRITE_UNMAPPED.0 | Self::MEM_WRITE_PROT.0);

    pub const MEM_FETCH_INVALID: Self = Self(Self::MEM_FETCH_UNMAPPED.0 | Self::MEM_FETCH_PROT.0);

    pub const MEM_INVALID: Self =
        Self(Self::MEM_READ_INVALID.0 | Self::MEM_WRITE_INVALID.0 | Self::MEM_FETCH_INVALID.0);

    pub const MEM_ALL: Self = Self(Self::MEM_VALID.0 | Self::MEM_INVALID.0);
}

impl ControlType {
    pub const IO_READ: Self = Self(1 << 31);

    pub const IO_WRITE: Self = Self(1 << 30);
}

impl Default for RegisterARMCP {
    fn default() -> Self {
        Self::new()
    }
}

impl RegisterARMCP {
    #[must_use]
    pub const fn new() -> Self {
        Self {
            cp: 0,
            is64: 0,
            sec: 0,
            crn: 0,
            crm: 0,
            opc1: 0,
            opc2: 0,
            val: 0,
        }
    }

    #[must_use]
    pub const fn cp(mut self, cp: u32) -> Self {
        self.cp = cp;
        self
    }

    #[must_use]
    pub const fn is64(mut self, is64: u32) -> Self {
        self.is64 = is64;
        self
    }

    #[must_use]
    pub const fn sec(mut self, sec: u32) -> Self {
        self.sec = sec;
        self
    }

    #[must_use]
    pub const fn crn(mut self, crn: u32) -> Self {
        self.crn = crn;
        self
    }

    #[must_use]
    pub const fn crm(mut self, crm: u32) -> Self {
        self.crm = crm;
        self
    }

    #[must_use]
    pub const fn opc1(mut self, opc1: u32) -> Self {
        self.opc1 = opc1;
        self
    }

    #[must_use]
    pub const fn opc2(mut self, opc2: u32) -> Self {
        self.opc2 = opc2;
        self
    }

    #[must_use]
    pub const fn val(mut self, val: u64) -> Self {
        self.val = val;
        self
    }
}

impl Default for RegisterARM64CP {
    fn default() -> Self {
        Self::new()
    }
}

impl RegisterARM64CP {
    #[must_use]
    pub const fn new() -> Self {
        Self {
            crn: 0,
            crm: 0,
            op0: 0,
            op1: 0,
            op2: 0,
            val: 0,
        }
    }
    #[must_use]
    pub const fn crn(mut self, crn: u32) -> Self {
        self.crn = crn;
        self
    }

    #[must_use]
    pub const fn crm(mut self, crm: u32) -> Self {
        self.crm = crm;
        self
    }

    #[must_use]
    pub const fn op0(mut self, op0: u32) -> Self {
        self.op0 = op0;
        self
    }

    #[must_use]
    pub const fn op1(mut self, op1: u32) -> Self {
        self.op1 = op1;
        self
    }

    #[must_use]
    pub const fn op2(mut self, op2: u32) -> Self {
        self.op2 = op2;
        self
    }

    #[must_use]
    pub const fn val(mut self, val: u64) -> Self {
        self.val = val;
        self
    }
}

impl From<M68kCpuModel> for i32 {
    fn from(value: M68kCpuModel) -> Self {
        value as Self
    }
}

impl From<&M68kCpuModel> for i32 {
    fn from(value: &M68kCpuModel) -> Self {
        *value as Self
    }
}

impl From<X86CpuModel> for i32 {
    fn from(value: X86CpuModel) -> Self {
        value as Self
    }
}

impl From<&X86CpuModel> for i32 {
    fn from(value: &X86CpuModel) -> Self {
        *value as Self
    }
}

impl From<ArmCpuModel> for i32 {
    fn from(value: ArmCpuModel) -> Self {
        value as Self
    }
}

impl From<&ArmCpuModel> for i32 {
    fn from(value: &ArmCpuModel) -> Self {
        *value as Self
    }
}

impl From<Arm64CpuModel> for i32 {
    fn from(value: Arm64CpuModel) -> Self {
        value as Self
    }
}

impl From<&Arm64CpuModel> for i32 {
    fn from(value: &Arm64CpuModel) -> Self {
        *value as Self
    }
}

impl From<Mips32CpuModel> for i32 {
    fn from(value: Mips32CpuModel) -> Self {
        value as Self
    }
}

impl From<&Mips32CpuModel> for i32 {
    fn from(value: &Mips32CpuModel) -> Self {
        *value as Self
    }
}

impl From<Mips64CpuModel> for i32 {
    fn from(value: Mips64CpuModel) -> Self {
        value as Self
    }
}

impl From<&Mips64CpuModel> for i32 {
    fn from(value: &Mips64CpuModel) -> Self {
        *value as Self
    }
}

impl From<Sparc32CpuModel> for i32 {
    fn from(value: Sparc32CpuModel) -> Self {
        value as Self
    }
}

impl From<&Sparc32CpuModel> for i32 {
    fn from(value: &Sparc32CpuModel) -> Self {
        *value as Self
    }
}

impl From<Sparc64CpuModel> for i32 {
    fn from(value: Sparc64CpuModel) -> Self {
        value as Self
    }
}

impl From<&Sparc64CpuModel> for i32 {
    fn from(value: &Sparc64CpuModel) -> Self {
        *value as Self
    }
}

impl From<PpcCpuModel> for i32 {
    fn from(value: PpcCpuModel) -> Self {
        value as Self
    }
}

impl From<&PpcCpuModel> for i32 {
    fn from(value: &PpcCpuModel) -> Self {
        *value as Self
    }
}

impl From<Ppc64CpuModel> for i32 {
    fn from(value: Ppc64CpuModel) -> Self {
        value as Self
    }
}

impl From<&Ppc64CpuModel> for i32 {
    fn from(value: &Ppc64CpuModel) -> Self {
        *value as Self
    }
}

impl From<Riscv32CpuModel> for i32 {
    fn from(value: Riscv32CpuModel) -> Self {
        value as Self
    }
}

impl From<&Riscv32CpuModel> for i32 {
    fn from(value: &Riscv32CpuModel) -> Self {
        *value as Self
    }
}

impl From<Riscv64CpuModel> for i32 {
    fn from(value: Riscv64CpuModel) -> Self {
        value as Self
    }
}

impl From<&Riscv64CpuModel> for i32 {
    fn from(value: &Riscv64CpuModel) -> Self {
        *value as Self
    }
}

impl From<S390xCpuModel> for i32 {
    fn from(value: S390xCpuModel) -> Self {
        value as Self
    }
}

impl From<&S390xCpuModel> for i32 {
    fn from(value: &S390xCpuModel) -> Self {
        *value as Self
    }
}

impl From<TricoreCpuModel> for i32 {
    fn from(value: TricoreCpuModel) -> Self {
        value as Self
    }
}

impl From<&TricoreCpuModel> for i32 {
    fn from(value: &TricoreCpuModel) -> Self {
        *value as Self
    }
}

impl From<RegisterM68K> for i32 {
    fn from(value: RegisterM68K) -> Self {
        value as Self
    }
}

impl From<RegisterX86> for i32 {
    fn from(value: RegisterX86) -> Self {
        value as Self
    }
}

impl From<RegisterARM> for i32 {
    fn from(value: RegisterARM) -> Self {
        value as Self
    }
}

impl From<RegisterARM64> for i32 {
    fn from(value: RegisterARM64) -> Self {
        value as Self
    }
}

impl From<RegisterMIPS> for i32 {
    fn from(value: RegisterMIPS) -> Self {
        value as Self
    }
}

impl From<RegisterSPARC> for i32 {
    fn from(value: RegisterSPARC) -> Self {
        value as Self
    }
}

impl From<RegisterPPC> for i32 {
    fn from(value: RegisterPPC) -> Self {
        value as Self
    }
}

impl From<RegisterRISCV> for i32 {
    fn from(value: RegisterRISCV) -> Self {
        value as Self
    }
}

impl From<RegisterS390X> for i32 {
    fn from(value: RegisterS390X) -> Self {
        value as Self
    }
}

impl From<RegisterTRICORE> for i32 {
    fn from(value: RegisterTRICORE) -> Self {
        value as Self
    }
}
