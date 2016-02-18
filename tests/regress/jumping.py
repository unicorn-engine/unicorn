#!/usr/bin/env python
# Mariano Graziano

from unicorn import *
from unicorn.x86_const import *

import regress

#echo -ne "\x48\x31\xc0\x48\xb8\x04\x00\x00\x00\x00\x00\x00\x00\x48\x3d\x05\x00\x00\x00\x74\x05\xe9\x0f\x00\x00\x00\x48\xba\xbe\xba\x00\x00\x00\x00\x00\x00\xe9\x0f\x00\x00\x00\x48\xba\xca\xc0\x00\x00\x00\x00\x00\x00\xe9\x00\x00\x00\x00\x90" | ndisasm - -b64
#00000000  4831C0            xor rax,rax
#00000003  48B8040000000000  mov rax,0x4
#         -0000
#0000000D  483D05000000      cmp rax,0x5
#00000013  7405              jz 0x1a
#00000015  E90F000000        jmp qword 0x29
#0000001A  48BABEBA00000000  mov rdx,0xbabe
#         -0000
#00000024  E90F000000        jmp qword 0x38
#00000029  48BACAC000000000  mov rdx,0xc0ca
#         -0000
#00000033  E900000000        jmp qword 0x38
#00000038  90                nop


mu = 0
zf = 1 # (0:clear, 1:set)


class Init(regress.RegressTest):
    def clear_zf(self):
        eflags_cur = mu.reg_read(UC_X86_REG_EFLAGS)
        eflags = eflags_cur & ~(1 << 6)
        #eflags = 0x0
        print "[clear_zf] - eflags from %x to %x" % (eflags_cur, eflags)
        if eflags != eflags_cur:
            print "[clear_zf] - writing new eflags..."
            mu.reg_write(UC_X86_REG_EFLAGS, eflags)

    def set_zf(self):
        eflags_cur = mu.reg_read(UC_X86_REG_EFLAGS)
        eflags = eflags_cur | (1 << 6)
        #eflags = 0xFFFFFFFF
        print "[set_zf] - eflags from %x to %x" % (eflags_cur, eflags)
        if eflags != eflags_cur:
            print "[set_zf] - writing new eflags..."
            mu.reg_write(UC_X86_REG_EFLAGS, eflags)

    def handle_zf(self, zf): 
        print "[handle_zf] - eflags " , zf
        if zf == 0: self.clear_zf()
        else: self.set_zf()

    def multipath(self):
        print "[multipath] - handling ZF (%s) - default" % zf
        self.handle_zf(zf)

    # callback for tracing basic blocks
    def hook_block(self, uc, address, size, user_data):
        print(">>> Tracing basic block at 0x%x, block size = 0x%x" %(address, size))

    # callback for tracing instructions
    def hook_code(self, uc, address, size, user_data):
        print(">>> Tracing instruction at 0x%x, instruction size = %u" %(address, size))
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
        eflags = mu.reg_read(UC_X86_REG_EFLAGS)
        
        print(">>> RAX = %x" %rax)
        print(">>> RBX = %x" %rbx)
        print(">>> RCX = %x" %rcx)
        print(">>> RDX = %x" %rdx)
        print(">>> RSI = %x" %rsi)
        print(">>> RDI = %x" %rdi)
        print(">>> R8 = %x" %r8)
        print(">>> R9 = %x" %r9)
        print(">>> R10 = %x" %r10)
        print(">>> R11 = %x" %r11)
        print(">>> R12 = %x" %r12)
        print(">>> R13 = %x" %r13)
        print(">>> R14 = %x" %r14)
        print(">>> R15 = %x" %r15)
        print(">>> ELAGS = %x" %eflags)
        print "-"*11
        self.multipath()
        print "-"*11

    # callback for tracing memory access (READ or WRITE)
    def hook_mem_access(self, uc, access, address, size, value, user_data):
        if access == UC_MEM_WRITE:
            print(">>> Memory is being WRITE at 0x%x, data size = %u, data value = 0x%x" \
                    %(address, size, value))
        else:   # READ
            print(">>> Memory is being READ at 0x%x, data size = %u" \
                    %(address, size))

    # callback for tracing invalid memory access (READ or WRITE)
    def hook_mem_invalid(self, uc, access, address, size, value, user_data):
        print("[ HOOK_MEM_INVALID - Address: %s ]" % hex(address))
        if access == UC_MEM_WRITE_UNMAPPED:
            print(">>> Missing memory is being WRITE at 0x%x, data size = %u, data value = 0x%x" %(address, size, value))
            return True
        else:
            print(">>> Missing memory is being READ at 0x%x, data size = %u, data value = 0x%x" %(address, size, value))
            return True


    def hook_mem_fetch_unmapped(self, uc, access, address, size, value, user_data):
        print("[ HOOK_MEM_FETCH - Address: %s ]" % hex(address))
        print("[ mem_fetch_unmapped: faulting address at %s ]" % hex(address).strip("L"))
        return True

    def runTest(self):
        global mu
 
        JUMP = "\x48\x31\xc0\x48\xb8\x04\x00\x00\x00\x00\x00\x00\x00\x48\x3d\x05\x00\x00\x00\x74\x05\xe9\x0f\x00\x00\x00\x48\xba\xbe\xba\x00\x00\x00\x00\x00\x00\xe9\x0f\x00\x00\x00\x48\xba\xca\xc0\x00\x00\x00\x00\x00\x00\xe9\x00\x00\x00\x00\x90"

        ADDRESS = 0x1000000

        print("Emulate x86_64 code")
        # Initialize emulator in X86-64bit mode
        mu = Uc(UC_ARCH_X86, UC_MODE_64)

        # map 2MB memory for this emulation
        mu.mem_map(ADDRESS, 2 * 1024 * 1024)

        # write machine code to be emulated to memory
        mu.mem_write(ADDRESS, JUMP)

        # setup stack
        mu.reg_write(UC_X86_REG_RSP, ADDRESS + 0x200000)

        # tracing all basic blocks with customized callback
        mu.hook_add(UC_HOOK_BLOCK, self.hook_block)

        # tracing all instructions in range [ADDRESS, ADDRESS+0x60]
        mu.hook_add(UC_HOOK_CODE, self.hook_code, None, ADDRESS, ADDRESS+0x60)

        # tracing all memory READ & WRITE access
        mu.hook_add(UC_HOOK_MEM_WRITE, self.hook_mem_access)
        mu.hook_add(UC_HOOK_MEM_READ, self.hook_mem_access)
        mu.hook_add(UC_HOOK_MEM_FETCH_UNMAPPED, self.hook_mem_fetch_unmapped)
        mu.hook_add(UC_HOOK_MEM_READ_UNMAPPED | UC_HOOK_MEM_WRITE_UNMAPPED, self.hook_mem_invalid)

        try:
            # emulate machine code in infinite time
            mu.emu_start(ADDRESS, ADDRESS + len(JUMP))
        except UcError as e:
            print("ERROR: %s" % e)

        rdx = mu.reg_read(UC_X86_REG_RDX)
        self.assertEqual(rdx, 0xbabe, "RDX contains the wrong value. Eflags modification failed.")


if __name__ == '__main__':
    regress.main()
