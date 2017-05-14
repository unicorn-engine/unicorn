#!/usr/bin/env ruby
require 'unicorn'
require 'unicorn/x86_const'

include Unicorn

X86_CODE32 = "\x41\x4a" # INC ecx; DEC edx

# memory address where emulation starts
ADDRESS = 0x1000000

# callback for tracing instructions
hook_code = Proc.new do |uc, address, size, user_data|
    puts("proc was not collected, test passed")
    exit 0
end

begin
    # Initialize emulator in X86-32bit mode
    mu = Uc.new UC_ARCH_X86, UC_MODE_32
    # map 2MB memory for this emulation
    mu.mem_map(ADDRESS, 2 * 1024 * 1024)

    # write machine code to be emulated to memory
    mu.mem_write(ADDRESS, X86_CODE32)

    # initialize machine registers
    mu.reg_write(UC_X86_REG_ECX, 0x1234)
    mu.reg_write(UC_X86_REG_EDX, 0x7890)

    # tracing all instructions with customized callback
    mu.hook_add(UC_HOOK_CODE, hook_code)

    hook_code = nil # erase reference to proc
        
    GC.start() # force garbage collection to test if proc is garbage collected
        
    # emulate machine code in infinite time
    mu.emu_start(ADDRESS, ADDRESS + X86_CODE32.bytesize)

    puts("we should not reach this point. the hook is supposed to exit")
    exit 1
rescue UcError => e
    puts("ERROR: %s" % e)
    exit 1
rescue NoMethodError => e
    puts("proc was garbage collected and we tried to invoke `call` on something strange")
    exit 1
end
