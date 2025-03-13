import binascii
import regress
from unicorn import *
from unicorn.x86_const import *


# callback for tracing instructions
def hook_code(uc, address, size, user_data):
    # invalid instruction?
    if size == 0xf1f1f1f1:
        return

    regress.logger.debug("[%#x] = %s", address, binascii.hexlify(uc.mem_read(address, size)))


# callback for tracing Linux interrupt
def hook_intr(uc, intno, user_data):
    # only handle Linux syscall
    rip = uc.reg_read(UC_X86_REG_RIP)

    regress.logger.debug("[%#x]: got interrupt %#x", rip, intno)
    regress.logger.debug("  EAX = %#010x", uc.reg_read(UC_X86_REG_EAX))
    regress.logger.debug("  EBX = %#010x", uc.reg_read(UC_X86_REG_EBX))
    regress.logger.debug("  ECX = %#010x", uc.reg_read(UC_X86_REG_ECX))
    regress.logger.debug("  EDX = %#010x", uc.reg_read(UC_X86_REG_EDX))

    uc.emu_stop()


class Hang(regress.RegressTest):

    def runTest(self):
        # self modifying shellcode execve('/bin/sh')
        shellcode = (
            b'\xeb\x1c'                                  #  00:   jmp    0x1e
            b'\x5a'                                      #  02:   pop    rdx
            b'\x89\xd6'                                  #  03:   mov    esi, edx
            b'\x8b\x02'                                  #  05:   mov    eax, [rdx]
            b'\x66\x3d\xca\x7d'                          #  07:   cmp    ax, 0x7dca
            b'\x75\x06'                                  #  0b:   jne    0x13
            b'\x66\x05\x03\x03'                          #  0d:   add    ax,0x303
            b'\x89\x02'                                  #  11:   mov    [rdx], eax
            b'\xfe\xc2'                                  #  13:   inc    dl
            b'\x3d\x41\x41\x41\x41'                      #  15:   cmp    eax, 0x41414141
            b'\x75\xe9'                                  #  1a:   jne    0x5
            b'\xff\xe6'                                  #  1c:   jmp    rsi
            b'\xe8\xdf\xff\xff\xff'                      #  1e:   call   0x2
            b'\x31\xd2'                                  #  23:   xor    edx, edx
            b'\x6a\x0b'                                  #  25:   push   0xb
            b'\x58'                                      #  27:   pop    rax
            b'\x99'                                      #  28:   cdq
            b'\x52'                                      #  29:   push   rdx
            b'\x68\x2f\x2f\x73\x68'                      #  2a:   push   0x68732f2f
            b'\x68\x2f\x62\x69\x6e'                      #  2f:   push   0x6e69622f
            b'\x89\xe3'                                  #  34:   mov    ebx, esp
            b'\x52'                                      #  36:   push   rdx
            b'\x53'                                      #  37:   push   rbx
            b'\x89\xe1'                                  #  38:   mov    ecx, esp
            b'\xca\x7d\x41\x41\x41\x41\x41\x41\x41\x41'  #  3a:   .db ca 7d 41 41 41 41 41 41 41 41
        )

        address = 0x00000000

        mu = Uc(UC_ARCH_X86, UC_MODE_64)

        mu.mem_map(address, 0x1000)

        # tracing all instructions with customized callback
        mu.hook_add(UC_HOOK_CODE, hook_code)

        # handle interrupt ourself
        mu.hook_add(UC_HOOK_INTR, hook_intr)

        # setup stack
        mu.reg_write(UC_X86_REG_RSP, 0x1000 - 8)

        # write machine code to be emulated to memory
        mu.mem_write(address, shellcode)

        regress.logger.debug('Starting emulation')

        mu.emu_start(address, address + len(shellcode))


if __name__ == '__main__':
    regress.main()
