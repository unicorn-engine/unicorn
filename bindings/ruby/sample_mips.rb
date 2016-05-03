#!/usr/bin/env ruby
# Sample code for MIPS of Unicorn. Nguyen Anh Quynh <aquynh@gmail.com>
# Ruby sample ported by Sascha Schirra <sashs82@gmail.com>
require 'unicorn'
require 'unicorn/mips_const'

include Unicorn

# code to be emulated
MIPS_CODE_EB = "\x34\x21\x34\x56" # ori $at, $at, 0x3456;
MIPS_CODE_EL = "\x56\x34\x21\x34" # ori $at, $at, 0x3456;

# memory address where emulation starts
ADDRESS      = 0x10000


# callback for tracing basic blocks
$hook_block = Proc.new do |uc, address, size, user_data|
    puts(">>> Tracing basic block at 0x%x, block size = 0x%x" % [address, size])
end


# callback for tracing instructions
$hook_code = Proc.new do |uc, address, size, user_data|
    puts(">>> Tracing instruction at 0x%x, instruction size = %u" % [address, size])
end

# Test MIPS EB
def test_mips_eb()
    puts("Emulate MIPS code (big-endian)")
    begin
        # Initialize emulator in MIPS32 + EB mode
        mu = Uc.new UC_ARCH_MIPS, UC_MODE_MIPS32 + UC_MODE_BIG_ENDIAN

        # map 2MB memory for this emulation
        mu.mem_map(ADDRESS, 2 * 1024 * 1024)

        # write machine code to be emulated to memory
        mu.mem_write(ADDRESS, MIPS_CODE_EB)

        # initialize machine registers
        mu.reg_write(UC_MIPS_REG_1, 0x6789)

        # tracing all basic blocks with customized callback
        mu.hook_add(UC_HOOK_BLOCK, $hook_block)

        # tracing all instructions with customized callback
        mu.hook_add(UC_HOOK_CODE, $hook_code)

        # emulate machine code in infinite time
        mu.emu_start(ADDRESS, ADDRESS + MIPS_CODE_EB.bytesize)

        # now puts out some registers
        puts(">>> Emulation done. Below is the CPU context")

        r1 = mu.reg_read(UC_MIPS_REG_1)
        puts(">>> r1 = 0x%x" % r1)

    rescue UcError => e
        puts("ERROR: %s" % e)
    end
end


# Test MIPS EL
def test_mips_el()
    puts("Emulate MIPS code (little-endian)")
    begin
        # Initialize emulator in MIPS32 + EL mode
        mu = Uc.new UC_ARCH_MIPS, UC_MODE_MIPS32 + UC_MODE_LITTLE_ENDIAN

        # map 2MB memory for this emulation
        mu.mem_map(ADDRESS, 2 * 1024 * 1024)

        # write machine code to be emulated to memory
        mu.mem_write(ADDRESS, MIPS_CODE_EL)

        # initialize machine registers
        mu.reg_write(UC_MIPS_REG_1, 0x6789)

        # tracing all basic blocks with customized callback
        mu.hook_add(UC_HOOK_BLOCK, $hook_block)

        # tracing all instructions with customized callback
        mu.hook_add(UC_HOOK_CODE, $hook_code)

        # emulate machine code in infinite time
        mu.emu_start(ADDRESS, ADDRESS + MIPS_CODE_EL.bytesize)

        # now puts out some registers
        puts(">>> Emulation done. Below is the CPU context")

        r1 = mu.reg_read(UC_MIPS_REG_1)
        puts(">>> r1 = 0x%x" % r1)

    rescue UcError => e
        puts("ERROR: %s" % e)
    end
end


test_mips_eb()
puts("=" * 20)
test_mips_el()
