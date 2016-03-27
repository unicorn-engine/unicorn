#!/usr/bin/env ruby
# Sample code for ARM of Unicorn. Nguyen Anh Quynh <aquynh@gmail.com>
# Ruby sample ported by Sascha Schirra <sashs82@gmail.com>

require 'unicorn'
require 'unicorn/m68k_const'

include Unicorn

# code to be emulated
M68K_CODE  = "\x76\xed" # movq #-19, %d3
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


# Test m68k
def test_m68k()
    puts("Emulate M68K code")
    begin
        # Initialize emulator in m68k mode
        mu = Uc.new UC_ARCH_M68K, UC_MODE_BIG_ENDIAN

        # map 2MB memory for this emulation
        mu.mem_map(ADDRESS, 2 * 1024 * 1024)

        # write machine code to be emulated to memory
        mu.mem_write(ADDRESS, M68K_CODE)

        # initialize machine registers
        mu.reg_write(UC_M68K_REG_D3, 0x1234)

        # tracing all basic blocks with customized callback
        mu.hook_add(UC_HOOK_BLOCK, $hook_block)

        # tracing all instructions with customized callback
        mu.hook_add(UC_HOOK_CODE, $hook_code)

        # emulate machine code in infinite time
        mu.emu_start(ADDRESS, ADDRESS + M68K_CODE.bytesize)

        # now print out some registers
        puts(">>> Emulation done. Below is the CPU context")

        d3 = mu.reg_read(UC_M68K_REG_D3)
        puts(">>> D3 = 0x%x" % d3)

    rescue UcError => e
        puts("ERROR: %s" % e)
    end
end


test_m68k()
