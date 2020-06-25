#!/usr/bin/env ruby
# Sample code for MIPS of Unicorn. Nguyen Anh Quynh <aquynh@gmail.com>
# Ruby sample ported by Sascha Schirra <sashs82@gmail.com>
require 'unicorn'
require 'unicorn/ppc_const'

include Unicorn

# code to be emulated
PPC_CODE_EB = "\x39\x20\x00\x04" + # li        r9, 4
              "\x91\x3F\x00\x08" + # stw       r9, 8(r31)
              "\x39\x20\x00\x05" + # li        r9, 5
              "\x91\x3F\x00\x0C" + # stw       r9, 0xC(r31)
              "\x81\x5F\x00\x08" + # lwz       r10, 8(r31)
              "\x81\x3F\x00\x0C" + # lwz       r9, 0xC(r31)
              "\x7D\x2A\x4A\x14";  # add       r9, r10, r9" # ori $at, $at, 0x3456;

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

# Test PPC EB
def test_ppc_eb()
    puts("Emulate MIPS code (big-endian)")
    begin
        # Initialize emulator in MIPS32 + EB mode
        mu = Uc.new UC_ARCH_PPC, UC_MODE_PPC32 + UC_MODE_BIG_ENDIAN

        # map 2MB memory for this emulation
        mu.mem_map(ADDRESS, 2 * 1024 * 1024)

        # write machine code to be emulated to memory
        mu.mem_write(ADDRESS, PPC_CODE_EB)

        # initialize machine registers
        mu.reg_write(UC_PPC_REG_GPR_31, ADDRESS)

        # tracing all basic blocks with customized callback
        mu.hook_add(UC_HOOK_BLOCK, $hook_block)

        # tracing all instructions with customized callback
        mu.hook_add(UC_HOOK_CODE, $hook_code)

        # emulate machine code in infinite time
        mu.emu_start(ADDRESS, ADDRESS + PPC_CODE_EB.bytesize)

        # now puts out some registers
        puts(">>> Emulation done. Below is the CPU context")

        r9 = mu.reg_read(UC_PPC_REG_GPR_9)
        puts(">>> r1 = 0x%x" % r9)
        if r9 != 9
          puts("INVALID RETURN VALUE")
        end

    rescue UcError => e
        puts("ERROR: %s" % e)
    end
end


test_ppc_eb()
