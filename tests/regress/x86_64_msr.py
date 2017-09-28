#!/usr/bin/env python
from unicorn import *
from unicorn.x86_const import *
from struct import pack

import regress


CODE_ADDR = 0x40000
CODE_SIZE = 0x1000

SCRATCH_ADDR = 0x80000
SCRATCH_SIZE = 0x1000

SEGMENT_ADDR = 0x5000
SEGMENT_SIZE = 0x1000


FSMSR = 0xC0000100
GSMSR = 0xC0000101


def set_msr(uc, msr, value, scratch=SCRATCH_ADDR):
    '''
    set the given model-specific register (MSR) to the given value.
    this will clobber some memory at the given scratch address, as it emits some code.
    '''
    # save clobbered registers
    orax = uc.reg_read(UC_X86_REG_RAX)
    ordx = uc.reg_read(UC_X86_REG_RDX)
    orcx = uc.reg_read(UC_X86_REG_RCX)
    orip = uc.reg_read(UC_X86_REG_RIP)

    # x86: wrmsr
    buf = '\x0f\x30'
    uc.mem_write(scratch, buf)
    uc.reg_write(UC_X86_REG_RAX, value & 0xFFFFFFFF)
    uc.reg_write(UC_X86_REG_RDX, (value >> 32) & 0xFFFFFFFF)
    uc.reg_write(UC_X86_REG_RCX, msr & 0xFFFFFFFF)
    uc.emu_start(scratch, scratch+len(buf), count=1)

    # restore clobbered registers
    uc.reg_write(UC_X86_REG_RAX, orax)
    uc.reg_write(UC_X86_REG_RDX, ordx)
    uc.reg_write(UC_X86_REG_RCX, orcx)
    uc.reg_write(UC_X86_REG_RIP, orip)


def get_msr(uc, msr, scratch=SCRATCH_ADDR):
    '''
    fetch the contents of the given model-specific register (MSR).
    this will clobber some memory at the given scratch address, as it emits some code.
    '''
    # save clobbered registers
    orax = uc.reg_read(UC_X86_REG_RAX)
    ordx = uc.reg_read(UC_X86_REG_RDX)
    orcx = uc.reg_read(UC_X86_REG_RCX)
    orip = uc.reg_read(UC_X86_REG_RIP)

    # x86: rdmsr
    buf = '\x0f\x32'
    uc.mem_write(scratch, buf)
    uc.reg_write(UC_X86_REG_RCX, msr & 0xFFFFFFFF)
    uc.emu_start(scratch, scratch+len(buf), count=1)
    eax = uc.reg_read(UC_X86_REG_EAX)
    edx = uc.reg_read(UC_X86_REG_EDX)

    # restore clobbered registers
    uc.reg_write(UC_X86_REG_RAX, orax)
    uc.reg_write(UC_X86_REG_RDX, ordx)
    uc.reg_write(UC_X86_REG_RCX, orcx)
    uc.reg_write(UC_X86_REG_RIP, orip)

    return (edx << 32) | (eax & 0xFFFFFFFF)


def set_gs(uc, addr):
    '''
    set the GS.base hidden descriptor-register field to the given address.
    this enables referencing the gs segment on x86-64.
    '''
    return set_msr(uc, GSMSR, addr)


def get_gs(uc):
    '''
    fetch the GS.base hidden descriptor-register field.
    '''
    return get_msr(uc, GSMSR)


def set_fs(uc, addr):
    '''
    set the FS.base hidden descriptor-register field to the given address.
    this enables referencing the fs segment on x86-64.
    '''
    return set_msr(uc, FSMSR, addr)


def get_fs(uc):
    '''
    fetch the FS.base hidden descriptor-register field.
    '''
    return get_msr(uc, FSMSR)


class TestGetSetMSR(regress.RegressTest):
    def test_msr(self):
        uc = Uc(UC_ARCH_X86, UC_MODE_64)
        uc.mem_map(SCRATCH_ADDR, SCRATCH_SIZE)

        set_msr(uc, FSMSR, 0x1000)
        self.assertEqual(0x1000, get_msr(uc, FSMSR))

        set_msr(uc, GSMSR, 0x2000)
        self.assertEqual(0x2000, get_msr(uc, GSMSR))

    def test_gs(self):
        uc = Uc(UC_ARCH_X86, UC_MODE_64)

        uc.mem_map(SEGMENT_ADDR, SEGMENT_SIZE)
        uc.mem_map(CODE_ADDR, CODE_SIZE)
        uc.mem_map(SCRATCH_ADDR, SCRATCH_SIZE)

        code = '6548330C2518000000'.decode('hex')  # x86-64: xor rcx, qword ptr gs:[0x18]
        uc.mem_write(CODE_ADDR, code)
        uc.mem_write(SEGMENT_ADDR+0x18, 'AAAAAAAA')

        set_gs(uc, SEGMENT_ADDR)
        self.assertEqual(SEGMENT_ADDR, get_gs(uc))

        uc.emu_start(CODE_ADDR, CODE_ADDR+len(code))

        self.assertEqual(uc.reg_read(UC_X86_REG_RCX), 0x4141414141414141)

    def test_fs(self):
        uc = Uc(UC_ARCH_X86, UC_MODE_64)

        uc.mem_map(SEGMENT_ADDR, SEGMENT_SIZE)
        uc.mem_map(CODE_ADDR, CODE_SIZE)
        uc.mem_map(SCRATCH_ADDR, SCRATCH_SIZE)

        code = '6448330C2518000000'.decode('hex')  # x86-64: xor rcx, qword ptr fs:[0x18]
        uc.mem_write(CODE_ADDR, code)
        uc.mem_write(SEGMENT_ADDR+0x18, 'AAAAAAAA')

        set_fs(uc, SEGMENT_ADDR)
        self.assertEqual(SEGMENT_ADDR, get_fs(uc))

        uc.emu_start(CODE_ADDR, CODE_ADDR+len(code))

        self.assertEqual(uc.reg_read(UC_X86_REG_RCX), 0x4141414141414141)

if __name__ == '__main__':
    regress.main()
