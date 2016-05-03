#!/usr/bin/env ruby
# Sample code for ARM64 of Unicorn. Nguyen Anh Quynh <aquynh@gmail.com>
# Ruby sample ported by Sascha Schirra <sashs82@gmail.com>
require 'unicorn'
require 'unicorn/arm64_const'

include Unicorn

# code to be emulated
ARM64_CODE = "\xab\x01\x0f\x8b" #add x11, x13, x15

# memory address where emulation starts
ADDRESS    = 0x10000


# callback for tracing basic blocks
$hook_block = Proc.new do |uc, address, size, user_data|
    puts(">>> Tracing basic block at 0x%x, block size = 0x%x" % [address, size])
end


# callback for tracing instructions
$hook_code = Proc.new do |uc, address, size, user_data|
    puts(">>> Tracing instruction at 0x%x, instruction size = %u" % [address, size])
end


# Test ARM64
def test_arm64()
    puts("Emulate ARM64 code")
    begin
        # Initialize emulator in ARM mode
        mu = Uc.new UC_ARCH_ARM64, UC_MODE_ARM

        # map 2MB memory for this emulation
        mu.mem_map(ADDRESS, 2 * 1024 * 1024)

        # write machine code to be emulated to memory
        mu.mem_write(ADDRESS, ARM64_CODE)

        # initialize machine registers
        mu.reg_write(UC_ARM64_REG_X11, 0x1234)
        mu.reg_write(UC_ARM64_REG_X13, 0x6789)
        mu.reg_write(UC_ARM64_REG_X15, 0x3333)

        # tracing all basic blocks with customized callback
        mu.hook_add(UC_HOOK_BLOCK, $hook_block)

        # tracing all instructions with customized callback
        mu.hook_add(UC_HOOK_CODE, $hook_code)

        # emulate machine code in infinite time
        mu.emu_start(ADDRESS, ADDRESS + ARM64_CODE.bytesize)

        # now print out some registers
        puts(">>> Emulation done. Below is the CPU context")

        x11 = mu.reg_read(UC_ARM64_REG_X11)
        x13 = mu.reg_read(UC_ARM64_REG_X13)
        x15 = mu.reg_read(UC_ARM64_REG_X15)
        puts(">>> X11 = 0x%x" % x11)

    rescue UcError => e
        puts("ERROR: %s" % e)
    end
end


test_arm64()
