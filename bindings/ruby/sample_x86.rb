#!/usr/bin/env ruby
require 'unicorn'
require 'unicorn/x86_const'

include Unicorn

X86_CODE32 = "\x41\x4a" # INC ecx; DEC edx
X86_CODE32_LOOP = "\x41\x4a\xeb\xfe" # INC ecx; DEC edx; JMP self-loop
X86_CODE32_MEM_READ = "\x8B\x0D\xAA\xAA\xAA\xAA\x41\x4a" # mov ecx,[0xaaaaaaaa]; INC ecx; DEC edx
X86_CODE32_MEM_WRITE = "\x89\x0D\xAA\xAA\xAA\xAA\x41\x4a" # mov [0xaaaaaaaa], ecx; INC ecx; DEC edx
X86_CODE64 = "\x41\xBC\x3B\xB0\x28\x2A\x49\x0F\xC9\x90\x4D\x0F\xAD\xCF\x49\x87\xFD\x90\x48\x81\xD2\x8A\xCE\x77\x35\x48\xF7\xD9\x4D\x29\xF4\x49\x81\xC9\xF6\x8A\xC6\x53\x4D\x87\xED\x48\x0F\xAD\xD2\x49\xF7\xD4\x48\xF7\xE1\x4D\x19\xC5\x4D\x89\xC5\x48\xF7\xD6\x41\xB8\x4F\x8D\x6B\x59\x4D\x87\xD0\x68\x6A\x1E\x09\x3C\x59"
X86_CODE32_INOUT = "\x41\xE4\x3F\x4a\xE6\x46\x43" # INC ecx; IN AL, 0x3f; DEC edx; OUT 0x46, AL; INC ebx
X86_CODE64_SYSCALL = "\x0f\x05" # SYSCALL
X86_CODE16 = "\x00\x00" # add   byte ptr [bx + si], al

# memory address where emulation starts
ADDRESS = 0x1000000


# callback for tracing basic blocks
HOOK_BLOCK = Proc.new do |uc, address, size, user_data |
    puts(">>> Tracing basic block at 0x%x, block size = 0x%x" % [address, size])
end

# callback for tracing instructions
HOOK_CODE = Proc.new do |uc, address, size, user_data|
    puts(">>> Tracing instruction at 0x%x, instruction size = %u" % [address, size])
end


# callback for tracing invalid memory access (READ or WRITE)
HOOK_MEM_INVALID = lambda do |uc, access, address, size, value, user_data|
    if access == UC_MEM_WRITE_UNMAPPED
        puts(">>> Missing memory is being WRITE at 0x%x, data size = %u, data value = 0x%x" % [address, size, value])
        # map this memory in with 2MB in size
        uc.mem_map(0xaaaa0000, 2 * 1024*1024)
        # return True to indicate we want to continue emulation
        return true
    else
        puts(">>> Missing memory is being READ at 0x%x" % address)
        # return False to indicate we want to stop emulation
        return false
    end
end


# callback for tracing memory access (READ or WRITE)
HOOK_MEM_ACCESS = Proc.new do |uc, access, address, size, value, user_data|
    if access == UC_MEM_WRITE
        puts(">>> Memory is being WRITE at 0x%x, data size = %u, data value = 0x%x" % [address, size, value])
    else   # READ
        puts(">>> Memory is being READ at 0x%x, data size = %u" % [address, size])
    end
end

# callback for IN instruction
HOOK_IN = lambda do |uc, port, size, user_data|
    eip = uc.reg_read(UC_X86_REG_EIP)
    puts("--- reading from port 0x%x, size: %u, address: 0x%x" % [port, size, eip])
    if size == 1
        # read 1 byte to AL
        return 0xf1
    end
    if size == 2
        # read 2 byte to AX
        return 0xf2
    end
    if size == 4
        # read 4 byte to EAX
        return 0xf4
    end
    # we should never reach here
    return 0
end


# callback for OUT instruction
HOOK_OUT = Proc.new do |uc, port, size, value, user_data|
    eip = uc.reg_read(UC_X86_REG_EIP)
    puts("--- writing to port 0x%x, size: %u, value: 0x%x, address: 0x%x" % [port, size, value, eip])

    # confirm that value is indeed the value of AL/AX/EAX
    v = 0
    if size == 1
        # read 1 byte in AL
        v = uc.reg_read(UC_X86_REG_AL)
    end
    if size == 2
        # read 2 bytes in AX
        v = uc.reg_read(UC_X86_REG_AX)
    end
    if size == 4
        # read 4 bytes in EAX
        v = uc.reg_read(UC_X86_REG_EAX)
    end

    puts("--- register value = 0x%x" %v)
end


# Test X86 32 bit
def test_i386()
    puts("Emulate i386 code")
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

    # tracing all basic blocks with customized callback
    mu.hook_add(UC_HOOK_BLOCK, HOOK_BLOCK)

    # tracing all instructions with customized callback
    mu.hook_add(UC_HOOK_CODE, HOOK_CODE)
    mu.hook_add(UC_HOOK_MEM_READ_UNMAPPED, HOOK_MEM_INVALID)

    # emulate machine code in infinite time
    mu.emu_start(ADDRESS, ADDRESS + X86_CODE32.bytesize)

    # now print out some registers
    puts(">>> Emulation done. Below is the CPU context")

    r_ecx = mu.reg_read(UC_X86_REG_ECX)
    r_edx = mu.reg_read(UC_X86_REG_EDX)
    puts(">>> ECX = 0x%x" % r_ecx)
    puts(">>> EDX = 0x%x" % r_edx)

    # read from memory
    tmp = mu.mem_read(ADDRESS, 2)
    print(">>> Read 2 bytes from [0x%x] =" % (ADDRESS))
    tmp.each_byte { |i| print(" 0x%x" % i) }

    puts

    rescue UcError => e
        puts("ERROR: %s" % e)
    end
end


def test_i386_loop()
    puts("Emulate i386 code with infinite loop - wait for 2 seconds then stop emulation")
    begin
        # Initialize emulator in X86-32bit mode
        mu = Uc.new UC_ARCH_X86, UC_MODE_32

        # map 2MB memory for this emulation
        mu.mem_map(ADDRESS, 2 * 1024 * 1024)

        # write machine code to be emulated to memory
        mu.mem_write(ADDRESS, X86_CODE32_LOOP)

        # initialize machine registers
        mu.reg_write(UC_X86_REG_ECX, 0x1234)
        mu.reg_write(UC_X86_REG_EDX, 0x7890)

        # emulate machine code in infinite time
        mu.emu_start(ADDRESS, ADDRESS + X86_CODE32_LOOP.bytesize, 2 * UC_SECOND_SCALE)

        # now print out some registers
        puts(">>> Emulation done. Below is the CPU context")

        r_ecx = mu.reg_read(UC_X86_REG_ECX)
        r_edx = mu.reg_read(UC_X86_REG_EDX)
        puts(">>> ECX = 0x%x" % r_ecx)
        puts(">>> EDX = 0x%x" % r_edx)

    rescue UcError => e
        puts("ERROR: %s" % e)
    end
end


def test_i386_invalid_mem_read()
    puts("Emulate i386 code that read from invalid memory")
    begin
        # Initialize emulator in X86-32bit mode
        mu = Uc.new UC_ARCH_X86, UC_MODE_32

        # map 2MB memory for this emulation
        mu.mem_map(ADDRESS, 2 * 1024 * 1024)

        # write machine code to be emulated to memory
        mu.mem_write(ADDRESS, X86_CODE32_MEM_READ)

        # initialize machine registers
        mu.reg_write(UC_X86_REG_ECX, 0x1234)
        mu.reg_write(UC_X86_REG_EDX, 0x7890)

        # tracing all basic blocks with customized callback
        mu.hook_add(UC_HOOK_BLOCK, HOOK_BLOCK)

        # tracing all instructions with customized callback
        mu.hook_add(UC_HOOK_CODE, HOOK_CODE)

        begin
            # emulate machine code in infinite time
            mu.emu_start(ADDRESS, ADDRESS + X86_CODE32_MEM_READ.bytesize)
        rescue UcError => e
            puts("ERROR: %s" % e)
        end

        # now print out some registers
        puts(">>> Emulation done. Below is the CPU context")

        r_ecx = mu.reg_read(UC_X86_REG_ECX)
        r_edx = mu.reg_read(UC_X86_REG_EDX)
        puts(">>> ECX = 0x%x" % r_ecx)
        puts(">>> EDX = 0x%x" % r_edx)

    rescue UcError => e
        print("ERROR: %s" % e)
    end
end


def test_i386_invalid_mem_write()
    puts("Emulate i386 code that write to invalid memory")
    begin
        # Initialize emulator in X86-32bit mode
        mu = Uc.new UC_ARCH_X86, UC_MODE_32

        # map 2MB memory for this emulation
        mu.mem_map(ADDRESS, 2 * 1024 * 1024)

        # write machine code to be emulated to memory
        mu.mem_write(ADDRESS, X86_CODE32_MEM_WRITE)

        # initialize machine registers
        mu.reg_write(UC_X86_REG_ECX, 0x1234)
        mu.reg_write(UC_X86_REG_EDX, 0x7890)

        # tracing all basic blocks with customized callback
        #mu.hook_add(UC_HOOK_BLOCK, HOOK_BLOCK)

        # tracing all instructions with customized callback
        #mu.hook_add(UC_HOOK_CODE, HOOK_CODE)

        # intercept invalid memory events
        mu.hook_add(UC_HOOK_MEM_READ_UNMAPPED | UC_HOOK_MEM_WRITE_UNMAPPED, HOOK_MEM_INVALID)

        begin
            # emulate machine code in infinite time
            mu.emu_start(ADDRESS, ADDRESS + X86_CODE32_MEM_WRITE.bytesize)
        rescue UcError => e
            puts "ERROR: %s" % e
        end

        # now print out some registers
        puts ">>> Emulation done. Below is the CPU context"

        r_ecx = mu.reg_read(UC_X86_REG_ECX)
        r_edx = mu.reg_read(UC_X86_REG_EDX)
        puts ">>> ECX = 0x%x" % r_ecx 
        puts ">>> EDX = 0x%x" % r_edx

        begin
            # read from memory
            print ">>> Read 4 bytes from [0x%x] = " % (0xaaaaaaaa)
            tmp = mu.mem_read(0xaaaaaaaa, 4)
            tmp.each_byte { |i| print(" 0x%x" % i) }
            puts

            print ">>> Read 4 bytes from [0x%x] = " % 0xffffffaa
            tmp = mu.mem_read(0xffffffaa, 4)
            tmp.each_byte { |i| puts(" 0x%x" % i) }
            puts

        rescue UcError => e
            puts "ERROR: %s" % e
        end

    rescue UcError => e
        puts "ERROR: %s" % e
    end
end

# Test X86 32 bit with IN/OUT instruction
def test_i386_inout()
    puts("Emulate i386 code with IN/OUT instructions")
    begin
        # Initialize emulator in X86-32bit mode
        mu = Uc.new UC_ARCH_X86, UC_MODE_32

        # map 2MB memory for this emulation
        mu.mem_map(ADDRESS, 2 * 1024 * 1024)

        # write machine code to be emulated to memory
        mu.mem_write(ADDRESS, X86_CODE32_INOUT)

        # initialize machine registers
        mu.reg_write(UC_X86_REG_EAX, 0x1234)
        mu.reg_write(UC_X86_REG_ECX, 0x6789)

        # tracing all basic blocks with customized callback
        mu.hook_add(UC_HOOK_BLOCK, HOOK_BLOCK)

        # tracing all instructions with customized callback
        mu.hook_add(UC_HOOK_CODE, HOOK_CODE)

        # handle IN & OUT instruction
        mu.hook_add(UC_HOOK_INSN, HOOK_IN, nil, 1, 0, UC_X86_INS_IN)
        mu.hook_add(UC_HOOK_INSN, HOOK_OUT, nil, 1, 0, UC_X86_INS_OUT)

        # emulate machine code in infinite time
        mu.emu_start(ADDRESS, ADDRESS + X86_CODE32_INOUT.bytesize)

        # now print out some registers
        puts(">>> Emulation done. Below is the CPU context")

        r_ecx = mu.reg_read(UC_X86_REG_ECX)
        r_eax = mu.reg_read(UC_X86_REG_EAX)
        puts ">>> EAX = 0x%x" % r_eax
        puts ">>> ECX = 0x%x" % r_ecx
    rescue UcError => e
        puts("ERROR: %s" % e)
    end
end


def test_x86_64()
    puts("Emulate x86_64 code")
    begin
        # Initialize emulator in X86-64bit mode
        mu = Uc.new UC_ARCH_X86, UC_MODE_64

        # map 2MB memory for this emulation
        mu.mem_map(ADDRESS, 2 * 1024 * 1024)

        # write machine code to be emulated to memory
        mu.mem_write(ADDRESS, X86_CODE64)

        # initialize machine registers
        mu.reg_write(UC_X86_REG_RAX, 0x71f3029efd49d41d)
        mu.reg_write(UC_X86_REG_RBX, 0xd87b45277f133ddb)
        mu.reg_write(UC_X86_REG_RCX, 0xab40d1ffd8afc461)
        mu.reg_write(UC_X86_REG_RDX, 0x919317b4a733f01)
        mu.reg_write(UC_X86_REG_RSI, 0x4c24e753a17ea358)
        mu.reg_write(UC_X86_REG_RDI, 0xe509a57d2571ce96)
        mu.reg_write(UC_X86_REG_R8, 0xea5b108cc2b9ab1f)
        mu.reg_write(UC_X86_REG_R9, 0x19ec097c8eb618c1)
        mu.reg_write(UC_X86_REG_R10, 0xec45774f00c5f682)
        mu.reg_write(UC_X86_REG_R11, 0xe17e9dbec8c074aa)
        mu.reg_write(UC_X86_REG_R12, 0x80f86a8dc0f6d457)
        mu.reg_write(UC_X86_REG_R13, 0x48288ca5671c5492)
        mu.reg_write(UC_X86_REG_R14, 0x595f72f6e4017f6e)
        mu.reg_write(UC_X86_REG_R15, 0x1efd97aea331cccc)

        # setup stack
        mu.reg_write(UC_X86_REG_RSP, ADDRESS + 0x200000)

        # tracing all basic blocks with customized callback
        mu.hook_add(UC_HOOK_BLOCK, HOOK_BLOCK)

        # tracing all instructions in range [ADDRESS, ADDRESS+20]
        mu.hook_add(UC_HOOK_CODE, HOOK_CODE, 0, ADDRESS, ADDRESS+20)

        # tracing all memory READ & WRITE access
        mu.hook_add(UC_HOOK_MEM_WRITE, HOOK_MEM_ACCESS)
        mu.hook_add(UC_HOOK_MEM_READ, HOOK_MEM_ACCESS)
        # actually you can also use READ_WRITE to trace all memory access
        #mu.hook_add(UC_HOOK_MEM_READ | UC_HOOK_MEM_WRITE, hook_mem_access)

        begin
            # emulate machine code in infinite time
            mu.emu_start(ADDRESS, ADDRESS + X86_CODE64.bytesize)
        rescue UcError => e
            puts("ERROR: %s" % e)
        end
        # now print out some registers
        puts(">>> Emulation done. Below is the CPU context")
        rax = mu.reg_read(UC_X86_REG_RAX)
        rbx = mu.reg_read(UC_X86_REG_RBX)
        rcx = mu.reg_read(UC_X86_REG_RCX)
        rdx = mu.reg_read(UC_X86_REG_RDX)
        rsi = mu.reg_read(UC_X86_REG_RSI)
        rdi = mu.reg_read(UC_X86_REG_RDI)
        r8 = mu.reg_read(UC_X86_REG_R8)
        r9 = mu.reg_read(UC_X86_REG_R9)
        r10 = mu.reg_read(UC_X86_REG_R10)
        r11 = mu.reg_read(UC_X86_REG_R11)
        r12 = mu.reg_read(UC_X86_REG_R12)
        r13 = mu.reg_read(UC_X86_REG_R13)
        r14 = mu.reg_read(UC_X86_REG_R14)
        r15 = mu.reg_read(UC_X86_REG_R15)

        puts(">>> RAX = %d" % rax)
        puts(">>> RBX = %d" % rbx)
        puts(">>> RCX = %d" % rcx)
        puts(">>> RDX = %d" % rdx)
        puts(">>> RSI = %d" % rsi)
        puts(">>> RDI = %d" % rdi)
        puts(">>> R8 = %d" % r8)
        puts(">>> R9 = %d" % r9)
        puts(">>> R10 = %d" % r10)
        puts(">>> R11 = %d" % r11)
        puts(">>> R12 = %d" % r12)
        puts(">>> R13 = %d" % r13)
        puts(">>> R14 = %d" % r14)
        puts(">>> R15 = %d" % r15)
        #BUG
        mu.emu_start(ADDRESS, ADDRESS + X86_CODE64.bytesize)

    rescue UcError => e
        puts("ERROR: %s" % e)
    end
end


def test_x86_64_syscall()
    puts("Emulate x86_64 code with 'syscall' instruction")
    begin
        # Initialize emulator in X86-64bit mode
        mu = Uc.new UC_ARCH_X86, UC_MODE_64

        # map 2MB memory for this emulation
        mu.mem_map(ADDRESS, 2 * 1024 * 1024)

        # write machine code to be emulated to memory
        mu.mem_write(ADDRESS, X86_CODE64_SYSCALL)

        hook_syscall = Proc.new do |mu, user_data|
            rax = mu.reg_read(UC_X86_REG_RAX)
            if rax == 0x100
                mu.reg_write(UC_X86_REG_RAX, 0x200)
            else
                puts('ERROR: was not expecting rax=%d in syscall' % rax)
            end
        end

        # hook interrupts for syscall
        mu.hook_add(UC_HOOK_INSN, hook_syscall, nil, 1, 0, UC_X86_INS_SYSCALL)

        # syscall handler is expecting rax=0x100
        mu.reg_write(UC_X86_REG_RAX, 0x100)

        begin
            # emulate machine code in infinite time
            mu.emu_start(ADDRESS, ADDRESS + X86_CODE64_SYSCALL.bytesize)
        rescue UcError => e
            puts("ERROR: %s" % e)
        end

        # now print out some registers
        puts(">>> Emulation done. Below is the CPU context")

        rax = mu.reg_read(UC_X86_REG_RAX)
        puts(">>> RAX = 0x%x" % rax)

    rescue UcError => e
        puts("ERROR: %s" % e)
    end
end


def test_x86_16()
    puts("Emulate x86 16-bit code")
    begin
        # Initialize emulator in X86-16bit mode
        mu = Uc.new UC_ARCH_X86, UC_MODE_16

        # map 8KB memory for this emulation
        mu.mem_map(0, 8 * 1024)

        # set CPU registers
        mu.reg_write(UC_X86_REG_EAX, 7)
        mu.reg_write(UC_X86_REG_EBX, 5)
        mu.reg_write(UC_X86_REG_ESI, 6)

        # write machine code to be emulated to memory
        mu.mem_write(0, X86_CODE16)

        # emulate machine code in infinite time
        mu.emu_start(0, X86_CODE16.bytesize)

        # now print out some registers
        puts(">>> Emulation done. Below is the CPU context")

        tmp = mu.mem_read(11, 1)
        puts("[0x%x] = 0x%x" % [11, tmp[0].ord])

    rescue UcError => e
        puts("ERROR: %s" % e)
    end
end


test_i386()
puts("=" * 20)
test_i386_loop()
puts("=" * 20)
test_i386_invalid_mem_read()
puts("=" * 20)
test_i386_invalid_mem_write()
puts("=" * 20)
test_i386_inout()
puts("=" * 20)
test_x86_64()
puts("=" * 20)
test_x86_64_syscall()
puts("=" * 20)
test_x86_16()
