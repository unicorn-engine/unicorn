/// Public include's

// Architectures
pub const arm = @import("arm_const.zig");
pub const arm64 = @import("arm64_const.zig");
pub const m68k = @import("m68k_const.zig");
pub const mips = @import("mips_const.zig");
pub const ppc = @import("ppc_const.zig");
pub const riscv = @import("riscv_const.zig");
pub const tricore = @import("tricore_const.zig");
pub const sparc = @import("sparc_const.zig");
pub const s390x = @import("s390x_const.zig");
pub const x86 = @import("x86_const.zig");

// Unicorn consts
pub usingnamespace @import("unicorn_const.zig");
// C include
pub const c = @cImport(@cInclude("unicorn/unicorn.h"));

pub fn uc_version(major: [*c]c_uint, minor: [*c]c_uint) c_uint {
    return c.uc_version(major, minor);
}
pub fn uc_arch_supported(arch: c.uc_arch) bool {
    return c.uc_arch_supported(arch);
}
pub fn uc_open(arch: c.uc_arch, mode: c.uc_mode, uc: [*c]?*c.uc_engine) !void {
    try getErrors(c.uc_open(arch, mode, uc));
}
pub fn uc_close(uc: ?*c.uc_engine) !void {
    try getErrors(c.uc_close(uc));
}
pub fn uc_query(uc: ?*c.uc_engine, @"type": c.uc_query_type, result: [*c]usize) !void {
    try getErrors(c.uc_query(uc, @"type", result));
}
pub fn uc_ctl(uc: ?*c.uc_engine, control: c.uc_control_type) !void {
    try getErrors(c.uc_ctl(uc, control));
}
pub fn uc_errno(uc: ?*c.uc_engine) !void {
    try getErrors(c.uc_errno(uc));
}
pub fn uc_strerror(code: Error) [*:0]const u8 {
    return switch (code) {
        error.ucErrNoMemory => c.uc_strerror(c.UC_ERR_NOMEM),
        error.ucErrArch => c.uc_strerror(c.UC_ERR_ARCH),
        error.ucErrHandle => c.uc_strerror(c.UC_ERR_HANDLE),
        error.ucErrMode => c.uc_strerror(c.UC_ERR_MODE),
        error.ucErrVersion => c.uc_strerror(c.UC_ERR_VERSION),
        error.ucErrReadUnmapped => c.uc_strerror(c.UC_ERR_READ_UNMAPPED),
        error.ucErrWriteUnmapped => c.uc_strerror(c.UC_ERR_WRITE_UNMAPPED),
        error.ucErrFetchUnmapped => c.uc_strerror(c.UC_ERR_FETCH_UNMAPPED),
        error.ucErrHook => c.uc_strerror(c.UC_ERR_HOOK),
        error.ucErrInvalidInstruction => c.uc_strerror(c.UC_ERR_INSN_INVALID),
        error.ucErrMap => c.uc_strerror(c.UC_ERR_MAP),
        error.ucErrWriteProtected => c.uc_strerror(c.UC_ERR_WRITE_PROT),
        error.ucErrReadProtected => c.uc_strerror(c.UC_ERR_READ_PROT),
        error.ucErrFetchProtected => c.uc_strerror(c.UC_ERR_FETCH_PROT),
        error.ucErrInvalidArgument => c.uc_strerror(c.UC_ERR_ARG),
        error.ucErrReadUnaligned => c.uc_strerror(c.UC_ERR_READ_UNALIGNED),
        error.ucErrWriteUnaligned => c.uc_strerror(c.UC_ERR_WRITE_UNALIGNED),
        error.ucErrFetchUnaligned => c.uc_strerror(c.UC_ERR_FETCH_UNALIGNED),
        error.ucErrHookAlreadyExists => c.uc_strerror(c.UC_ERR_HOOK_EXIST),
        error.ucErrResource => c.uc_strerror(c.UC_ERR_RESOURCE),
        error.ucErrException => c.uc_strerror(c.UC_ERR_EXCEPTION),
    };
}
pub fn uc_reg_write(uc: ?*c.uc_engine, regid: c_int, value: ?*const anyopaque) !void {
    try getErrors(c.uc_reg_write(uc, regid, value));
}
pub fn uc_reg_read(uc: ?*c.uc_engine, regid: c_int, value: ?*anyopaque) !void {
    try getErrors(c.uc_reg_read(uc, regid, value));
}
pub fn uc_reg_write_batch(uc: ?*c.uc_engine, regs: [*c]c_int, vals: [*c]const ?*anyopaque, count: c_int) !void {
    try getErrors(c.uc_reg_write_batch(uc, regs, vals, count));
}
pub fn uc_reg_read_batch(uc: ?*c.uc_engine, regs: [*c]c_int, vals: [*c]?*anyopaque, count: c_int) !void {
    try getErrors(c.uc_reg_read_batch(uc, regs, vals, count));
}
pub fn uc_mem_write(uc: ?*c.uc_engine, address: u64, bytes: ?*const anyopaque, size: usize) !void {
    try getErrors(c.uc_mem_write(uc, address, bytes, size));
}
pub fn uc_mem_read(uc: ?*c.uc_engine, address: u64, bytes: ?*anyopaque, size: usize) !void {
    try getErrors(c.uc_mem_read(uc, address, bytes, size));
}
pub fn uc_emu_start(uc: ?*c.uc_engine, begin: u64, until: u64, timeout: u64, count: usize) !void {
    try getErrors(c.uc_emu_start(uc, begin, until, timeout, count));
}
pub fn uc_emu_stop(uc: ?*c.uc_engine) !void {
    try getErrors(c.uc_emu_stop(uc));
}
pub fn uc_hook_add(uc: ?*c.uc_engine, hh: [*c]c.uc_hook, @"type": c_int, callback: ?*anyopaque, user_data: ?*anyopaque, begin: u64, end: u64) !void {
    try getErrors(c.uc_hook_add(uc, hh, @"type", callback, user_data, begin, end));
}
pub fn uc_hook_del(uc: ?*c.uc_engine, hh: c.uc_hook) !void {
    try getErrors(c.uc_hook_del(uc, hh));
}
pub fn uc_mem_map(uc: ?*c.uc_engine, address: u64, size: usize, perms: u32) !void {
    try getErrors(c.uc_mem_map(uc, address, size, perms));
}
pub fn uc_mem_map_ptr(uc: ?*c.uc_engine, address: u64, size: usize, perms: u32, ptr: ?*anyopaque) !void {
    try getErrors(c.uc_mem_map_ptr(uc, address, size, perms, ptr));
}
pub fn uc_mmio_map(uc: ?*c.uc_engine, address: u64, size: usize, read_cb: c.uc_cb_mmio_read_t, user_data_read: ?*anyopaque, write_cb: c.uc_cb_mmio_write_t, user_data_write: ?*anyopaque) !void {
    try getErrors(c.uc_mmio_map(uc, address, size, read_cb, user_data_read, write_cb, user_data_write));
}
pub fn uc_mem_unmap(uc: ?*c.uc_engine, address: u64, size: usize) !void {
    try getErrors(c.uc_mem_unmap(uc, address, size));
}
pub fn uc_mem_protect(uc: ?*c.uc_engine, address: u64, size: usize, perms: u32) !void {
    try getErrors(c.uc_mem_protect(uc, address, size, perms));
}
pub fn uc_mem_regions(uc: ?*c.uc_engine, regions: [*c][*c]c.uc_mem_region, count: [*c]u32) !void {
    try getErrors(c.uc_mem_regions(uc, regions, count));
}
pub fn uc_context_alloc(uc: ?*c.uc_engine, context: [*c]?*c.uc_context) !void {
    try getErrors(c.uc_context_alloc(uc, context));
}
pub fn uc_free(mem: ?*anyopaque) !void {
    try getErrors(c.uc_free(mem));
}
pub fn uc_context_save(uc: ?*c.uc_engine, context: ?*c.uc_context) !void {
    try getErrors(c.uc_context_save(uc, context));
}
pub fn uc_context_reg_write(ctx: ?*c.uc_context, regid: c_int, value: ?*const anyopaque) !void {
    try getErrors(c.uc_context_reg_write(ctx, regid, value));
}
pub fn uc_context_reg_read(ctx: ?*c.uc_context, regid: c_int, value: ?*anyopaque) !void {
    try getErrors(c.uc_context_reg_read(ctx, regid, value));
}
pub fn uc_context_reg_write_batch(ctx: ?*c.uc_context, regs: [*c]c_int, vals: [*c]const ?*anyopaque, count: c_int) !void {
    try getErrors(c.uc_context_reg_write_batch(ctx, regs, vals, count));
}
pub fn uc_context_reg_read_batch(ctx: ?*c.uc_context, regs: [*c]c_int, vals: [*c]?*anyopaque, count: c_int) !void {
    try getErrors(c.uc_context_reg_read_batch(ctx, regs, vals, count));
}
pub fn uc_context_restore(uc: ?*c.uc_engine, context: ?*c.uc_context) !void {
    try getErrors(c.uc_context_restore(uc, context));
}
pub fn uc_context_size(uc: ?*c.uc_engine) usize {
    try getErrors(c.uc_context_size(uc));
}
pub fn uc_context_free(context: ?*c.uc_context) !void {
    try getErrors(c.uc_context_free(context));
}

pub const Error = error{
    ucErrNoMemory,
    ucErrArch,
    ucErrHandle,
    ucErrMode,
    ucErrVersion,
    ucErrReadUnmapped,
    ucErrWriteUnmapped,
    ucErrFetchUnmapped,
    ucErrHook,
    ucErrInvalidInstruction,
    ucErrMap,
    ucErrWriteProtected,
    ucErrReadProtected,
    ucErrFetchProtected,
    ucErrInvalidArgument,
    ucErrReadUnaligned,
    ucErrWriteUnaligned,
    ucErrFetchUnaligned,
    ucErrHookAlreadyExists,
    ucErrResource,
    ucErrException,
};

pub fn errorsToZig(err: c.uc_err) Error!c_int {
    return switch (err) {
        //c.UC_ERR_OK - isn't error
        c.UC_ERR_NOMEM => error.ucErrNoMemory,
        c.UC_ERR_ARCH => error.ucErrArch,
        c.UC_ERR_HANDLE => error.ucErrHandle,
        c.UC_ERR_MODE => error.ucErrMode,
        c.UC_ERR_VERSION => error.ucErrVersion,
        c.UC_ERR_READ_UNMAPPED => error.ucErrReadUnmapped,
        c.UC_ERR_WRITE_UNMAPPED => error.ucErrWriteUnmapped,
        c.UC_ERR_FETCH_UNMAPPED => error.ucErrFetchUnmapped,
        c.UC_ERR_HOOK => error.ucErrHook,
        c.UC_ERR_INSN_INVALID => error.ucErrInvalidInstruction,
        c.UC_ERR_MAP => error.ucErrMap,
        c.UC_ERR_WRITE_PROT => error.ucErrWriteProtected,
        c.UC_ERR_READ_PROT => error.ucErrReadProtected,
        c.UC_ERR_FETCH_PROT => error.ucErrFetchProtected,
        c.UC_ERR_ARG => error.ucErrInvalidArgument,
        c.UC_ERR_READ_UNALIGNED => error.ucErrReadUnaligned,
        c.UC_ERR_WRITE_UNALIGNED => error.ucErrWriteUnaligned,
        c.UC_ERR_FETCH_UNALIGNED => error.ucErrFetchUnaligned,
        c.UC_ERR_HOOK_EXIST => error.ucErrHookAlreadyExists,
        c.UC_ERR_RESOURCE => error.ucErrResource,
        c.UC_ERR_EXCEPTION => error.ucErrException,
        else => -1,
    };
}

fn getErrors(err: c.uc_err) !void {
    if (try errorsToZig(err) == c.UC_ERR_OK)
        return;
}

pub const log = @import("std").log.scoped(.unicorn);
