pub use unicorn_engine_sys::*;

pub const API_MAJOR: u64 = 2;
pub const API_MINOR: u64 = 1;
pub const VERSION_MAJOR: u64 = 2;
pub const VERSION_MINOR: u64 = 1;
pub const VERSION_PATCH: u64 = 3;
pub const VERSION_EXTRA: u64 = 255;
pub const SECOND_SCALE: u64 = 1_000_000;
pub const MILLISECOND_SCALE: u64 = 1_000;

macro_rules! UC_CTL_READ {
    ($expr:expr) => {
        ControlType($expr.0 | ControlType::IO_READ.0)
    };
}

macro_rules! UC_CTL_WRITE {
    ($expr:expr) => {
        ControlType($expr.0 | ControlType::IO_WRITE.0)
    };
}

macro_rules! UC_CTL_READ_WRITE {
    ($expr:expr) => {
        ControlType($expr.0 | ControlType::IO_WRITE.0 | ControlType::IO_READ.0)
    };
}
