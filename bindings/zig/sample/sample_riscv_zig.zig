//! Based on: ../../../samples/sample_riscv.c

const unicorn = @import("unicorn");
const unicornC = unicorn.c;
const log = unicorn.log;

const RISCV_CODE = "\x13\x05\x10\x00\x93\x85\x05\x02";
const ADDRESS = 0x10000;

pub fn main() !void {
    try test_recover_from_illegal();
    log.info("------------------", .{});
    try test_riscv2();
    log.info("------------------", .{});
    try test_riscv_func_return();
}

fn hook_block(uc: ?*unicornC.uc_engine, address: u64, size: u32, user_data: ?*anyopaque) callconv(.C) void {
    _ = user_data;
    _ = uc;
    log.info(">>> Tracing basic block at 0x{}, block size = 0x{}", .{ address, size });
}

fn hook_code(uc: ?*unicornC.uc_engine, address: u64, size: u32, user_data: ?*anyopaque) callconv(.C) void {
    _ = user_data;
    _ = uc;
    log.info(">>> Tracing instruction at 0x{}, instruction size = 0x{}", .{ address, size });
}

fn hook_code3(uc: ?*unicornC.uc_engine, address: u64, size: u32, user_data: ?*anyopaque) callconv(.C) void {
    _ = user_data;
    log.info(">>> Tracing instruction at 0x{}, instruction size = 0x{}", .{ address, size });
    if (address == ADDRESS) {
        log.info("stop emulation");
        unicorn.uc_emu_stop(uc) catch |err| log.err("Error: {}", .{err});
    }
}
fn hook_memalloc(uc: ?*unicornC.uc_engine, @"type": unicornC.uc_mem_type, address: u64, size: u32, user_data: ?*anyopaque) callconv(.C) bool {
    _ = user_data;
    _ = @"type";
    var algined_address = address & 0xFFFFFFFFFFFFF000;
    var aligned_size = (@as(u32, @intCast(size / 0x1000)) + 1) * 0x1000;

    log.info(">>> Allocating block at 0x{} (0x{}), block size = 0x{} (0x{})", .{ address, algined_address, size, aligned_size });

    unicorn.uc_mem_map(uc, algined_address, aligned_size, unicornC.UC_PROT_ALL) catch |err| log.err("Error: {}", .{err});

    // this recovers from missing memory, so we return true
    return true;
}

fn test_recover_from_illegal() !void {
    var uc: ?*unicornC.uc_engine = null;
    var trace1: unicornC.uc_hook = undefined;
    var trace2: unicornC.uc_hook = undefined;
    var mem_alloc: unicornC.uc_hook = undefined;
    var a0: u64 = 0x1234;
    var a1: u64 = 0x7890;

    log.info("Emulate RISCV code: recover_from_illegal", .{});

    // Initialize emulator in RISCV64 mode
    unicorn.uc_open(unicornC.UC_ARCH_RISCV, unicornC.UC_MODE_RISCV64, &uc) catch |err| {
        log.err("Failed on uc_open() with error returned: {}", .{err});
        return;
    };

    try unicorn.uc_reg_write(uc, unicornC.UC_RISCV_REG_A0, &a0);
    try unicorn.uc_reg_write(uc, unicornC.UC_RISCV_REG_A1, &a1);

    // map 2MB memory for this emulation
    try unicorn.uc_mem_map(uc, ADDRESS, 2 * 1024 * 1024, unicornC.UC_PROT_ALL);

    // auto-allocate memory on access
    try unicorn.uc_hook_add(uc, &mem_alloc, unicornC.UC_HOOK_MEM_UNMAPPED, @as(?*anyopaque, @ptrCast(@constCast(&hook_memalloc))), null, 1, 0);

    // tracing all basic blocks with customized callback
    try unicorn.uc_hook_add(uc, &trace1, unicornC.UC_HOOK_BLOCK, @as(?*anyopaque, @ptrCast(@constCast(&hook_block))), null, 1, 0);

    // tracing all instruction
    try unicorn.uc_hook_add(uc, &trace2, unicornC.UC_HOOK_CODE, @as(?*anyopaque, @ptrCast(@constCast(&hook_code))), null, 1, 0);

    // write machine code to be emulated to memory
    try unicorn.uc_mem_write(uc, ADDRESS, RISCV_CODE, RISCV_CODE.len - 1);

    // emulate 1 instruction, wrong address, illegal code
    unicorn.uc_emu_start(uc, 0x1000, @as(u64, @bitCast(@as(i64, -1))), 0, 1) catch |err|
        log.err("Expected Illegal Instruction error, got: {} ({s})", .{ err, unicorn.uc_strerror(err) });

    // emulate 1 instruction, correct address, valid code
    unicorn.uc_emu_start(uc, ADDRESS, @as(u64, @bitCast(@as(i64, -1))), 0, 1) catch |err|
        log.err("Failed on uc_emu_start() with error returned: {}", .{err});

    // now print out some registers
    log.info(">>> Emulation done. Below is the CPU context", .{});

    try unicorn.uc_reg_read(uc, unicornC.UC_RISCV_REG_A0, @as(?*anyopaque, @ptrCast(@constCast(&a0))));
    try unicorn.uc_reg_read(uc, unicornC.UC_RISCV_REG_A1, @as(?*anyopaque, @ptrCast(@constCast(&a1))));

    log.info(">>> A0 = 0x{}", .{a0});
    log.info(">>> A1 = 0x{}", .{a1});

    try unicorn.uc_close(uc);
}

fn test_riscv_func_return() !void {
    var uc: ?*unicornC.uc_engine = null;
    var trace1: unicornC.uc_hook = undefined;
    var trace2: unicornC.uc_hook = undefined;
    var pc: u64 = 0;
    var ra: u64 = 0;

    const CODE = "\x67\x80\x00\x00\x82\x80\x01\x00\x01\x00";

    log.info("Emulate RISCV code: return from func", .{});

    // Initialize emulator in RISCV64 mode
    unicorn.uc_open(unicornC.UC_ARCH_RISCV, unicornC.UC_MODE_RISCV64, &uc) catch |err| {
        log.err("Failed on uc_open() with error returned: {} ({s})", .{ err, unicorn.uc_strerror(err) });
        return;
    };

    // map 2MB memory for this emulation
    try unicorn.uc_mem_map(uc, ADDRESS, 2 * 1024 * 1024, unicornC.UC_PROT_ALL);

    // write machine code to be emulated to memory
    try unicorn.uc_mem_write(uc, ADDRESS, CODE, CODE.len - 1);

    // tracing all basic blocks with customized callback
    try unicorn.uc_hook_add(uc, &trace1, unicornC.UC_HOOK_BLOCK, @as(?*anyopaque, @ptrCast(@constCast(&hook_block))), null, 1, 0);

    // tracing all instruction
    try unicorn.uc_hook_add(uc, &trace2, unicornC.UC_HOOK_CODE, @as(?*anyopaque, @ptrCast(@constCast(&hook_code))), null, 1, 0);

    ra = 0x10006;
    try unicorn.uc_reg_write(uc, unicornC.UC_RISCV_REG_RA, @as(?*anyopaque, @ptrCast(@constCast(&ra))));

    log.info("========", .{});
    // execute c.ret instruction
    unicorn.uc_emu_start(uc, 0x10004, @as(u64, @bitCast(@as(i64, -1))), 0, 1) catch |err| {
        log.err("Failed on uc_emu_start() with error returned: {}", .{err});
    };

    try unicorn.uc_reg_read(uc, unicornC.UC_RISCV_REG_PC, @as(?*anyopaque, @ptrCast(@constCast(&pc))));
    if (pc != ra) {
        log.info("Error after execution: PC is: 0x{}, expected was 0x{}", .{ pc, ra });
        if (pc == 0x10004) {
            log.info("  PC did not change during execution", .{});
        }
    } else {
        log.info("Good, PC == RA", .{});
    }

    // now print out some registers
    log.info(">>> Emulation done.", .{});

    try unicorn.uc_close(uc);
}

fn test_riscv2() !void {
    var uc: ?*unicornC.uc_engine = null;
    var trace1: unicornC.uc_hook = undefined;
    var trace2: unicornC.uc_hook = undefined;

    var a0: u32 = 0x1234;
    var a1: u32 = 0x7890;

    log.info("Emulate RISCV code: split emulation", .{});

    // Initialize emulator in RISCV64 mode
    unicorn.uc_open(unicornC.UC_ARCH_RISCV, unicornC.UC_MODE_RISCV32, &uc) catch |err| {
        log.err("Failed on unicornC.uc_open() with error returned: {} ({s})", .{ err, unicorn.uc_strerror(err) });
        return;
    };

    // map 2MB memory for this emulation
    try unicorn.uc_mem_map(uc, ADDRESS, 2 * 1024 * 1024, unicornC.UC_PROT_ALL);

    // write machine code to be emulated to memory
    try unicorn.uc_mem_write(uc, ADDRESS, RISCV_CODE, RISCV_CODE.len - 1);

    // initialize machine registers
    try unicorn.uc_reg_write(uc, unicornC.UC_RISCV_REG_A0, @as(?*anyopaque, @ptrCast(@constCast(&a0))));
    try unicorn.uc_reg_write(uc, unicornC.UC_RISCV_REG_A1, @as(?*anyopaque, @ptrCast(@constCast(&a1))));

    // tracing all basic blocks with customized callback
    try unicorn.uc_hook_add(uc, &trace1, unicornC.UC_HOOK_BLOCK, @as(?*anyopaque, @ptrCast(@constCast(&hook_block))), null, 1, 0);

    // tracing all instruction
    try unicorn.uc_hook_add(uc, &trace2, unicornC.UC_HOOK_CODE, @as(?*anyopaque, @ptrCast(@constCast(&hook_block))), null, 1, 0);

    // emulate 1 instruction
    unicorn.uc_emu_start(uc, ADDRESS, ADDRESS + 4, 0, 0) catch |err| {
        log.err("Failed on unicornC.uc_emu_start() with error returned: {}", .{err});
    };

    try unicorn.uc_reg_read(uc, unicornC.UC_RISCV_REG_A0, @as(?*anyopaque, @ptrCast(@constCast(&a0))));
    try unicorn.uc_reg_read(uc, unicornC.UC_RISCV_REG_A1, @as(?*anyopaque, @ptrCast(@constCast(&a1))));

    log.info(">>> A0 = 0x{}", .{a0});
    log.info(">>> A1 = 0x{}", .{a1});

    // emulate one more instruction
    unicorn.uc_emu_start(uc, ADDRESS + 4, ADDRESS + 8, 0, 0) catch |err| {
        log.err("Failed on unicornC.uc_emu_start() with error returned: {}", .{err});
    };

    // now print out some registers
    log.info(">>> Emulation done. Below is the CPU context", .{});

    try unicorn.uc_reg_read(uc, unicornC.UC_RISCV_REG_A0, @as(?*anyopaque, @ptrCast(@constCast(&a0))));
    try unicorn.uc_reg_read(uc, unicornC.UC_RISCV_REG_A1, @as(?*anyopaque, @ptrCast(@constCast(&a1))));

    log.info(">>> A0 = 0x{}", .{a0});
    log.info(">>> A1 = 0x{}", .{a1});

    try unicorn.uc_close(uc);
}
