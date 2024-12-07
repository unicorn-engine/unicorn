#!/usr/bin/env python
# Sample code for Unicorn.
# By Lazymio(@wtdcode), 2021

import pytest
import sys
from unicorn import *
from unicorn.x86_const import *
from datetime import datetime


def test_uc_ctl_read():
    uc = Uc(UC_ARCH_X86, UC_MODE_32)

    print("Reading some properties by uc_ctl.")

    arch = uc.ctl_get_arch()

    mode = uc.ctl_get_mode()

    page_size = uc.ctl_get_page_size()

    timeout = uc.ctl_get_timeout()

    print(">>> arch={arch} mode={mode} page size={page_size} timeout={timeout}".format(arch=arch, mode=mode,
                                                                                       page_size=page_size,
                                                                                       timeout=timeout))


def time_emulation(uc, start, end):
    n = datetime.now()

    uc.emu_start(start, end)

    return (datetime.now() - n).total_seconds() * 1e6


# TODO: Check if worth adapting the ctl_request_cache method for py2 bindings
@pytest.mark.skipif(sys.version_info < (3, 7), reason="requires python3.7 or higher")
def test_uc_ctl_tb_cache():
    # Initialize emulator in X86-32bit mode
    uc = Uc(UC_ARCH_X86, UC_MODE_32)
    addr = 0x10000

    # Fill the code buffer with NOP.
    code = b"\x90" * 8 * 512

    print("Controlling the TB cache in a finer granularity by uc_ctl.")

    uc.mem_map(addr, 0x10000)

    # Write our code to the memory.
    uc.mem_write(addr, code)

    # Do emulation without any cache.
    standard = time_emulation(uc, addr, addr + len(code))

    # Now we request cache for all TBs.
    for i in range(8):
        tb = uc.ctl_request_cache(addr + i * 512)
        print(">>> TB is cached at {:#x} which has {} instructions with {} bytes".format(tb[0], tb[1], tb[2]))

    # Do emulation with all TB cached.
    cached = time_emulation(uc, addr, addr + len(code))

    # Now we clear cache for all TBs.
    for i in range(8):
        uc.ctl_remove_cache(addr + i * 512, addr + i * 512 + 1)

    evicted = time_emulation(uc, addr, addr + len(code))

    print(">>> Run time: First time {standard}, Cached: {cached}, Cached evicted: {evicted}".format(standard=standard,
                                                                                                    cached=cached,
                                                                                                    evicted=evicted))


def trace_new_edge(uc, cur, prev, data):
    print(">>> Getting a new edge from {:#x} to {:#x}".format(prev.pc + prev.size - 1, cur.pc))


def trace_tcg_sub(uc, address, arg1, arg2, size, data):
    print(">>> Get a tcg sub opcode at {address:#x} with args: {arg1} and {arg2}".format(address=address, arg1=arg1,
                                                                                         arg2=arg2))


# TODO: Check if worth adapting the hook_add method for py2 bindings
@pytest.mark.skipif(sys.version_info < (3, 7), reason="requires python3.7 or higher")
def test_uc_ctl_exits():
    uc = Uc(UC_ARCH_X86, UC_MODE_32)
    addr = 0x1000
    #   cmp eax, 0;
    #   jg lb;
    #   inc eax;
    #   nop;
    # lb:
    #   inc ebx;
    #   nop;
    code = b"\x83\xf8\x00\x7f\x02\x40\x90\x43\x90"
    exits = [addr + 6, addr + 8]

    print("Using multiple exits by uc_ctl")

    uc.mem_map(addr, 0x1000)

    # Write our code to the memory.
    uc.mem_write(addr, code)

    # We trace if any new edge is generated.
    uc.hook_add(UC_HOOK_EDGE_GENERATED, trace_new_edge)

    # Trace cmp instruction.
    uc.hook_add(UC_HOOK_TCG_OPCODE, trace_tcg_sub, aux1=UC_TCG_OP_SUB, aux2=UC_TCG_OP_FLAG_CMP)

    uc.ctl_exits_enabled(True)

    uc.ctl_set_exits(exits)

    # This should stop at ADDRESS + 6 and increase eax, even though we don't provide an exit.
    uc.emu_start(addr, 0)

    eax = uc.reg_read(UC_X86_REG_EAX)
    ebx = uc.reg_read(UC_X86_REG_EBX)

    print(">>> eax = {eax:#x} and ebx = {ebx:#x} after the first emulation".format(eax=eax, ebx=ebx))

    # This should stop at ADDRESS + 8, even though we don't provide an exit.
    uc.emu_start(addr, 0)

    eax = uc.reg_read(UC_X86_REG_EAX)
    ebx = uc.reg_read(UC_X86_REG_EBX)

    print(">>> eax = {eax:#x} and ebx = {ebx:#x} after the first emulation".format(eax=eax, ebx=ebx))


if __name__ == "__main__":
    test_uc_ctl_read()
    print("=" * 32)
    test_uc_ctl_tb_cache()
    print("=" * 32)
    test_uc_ctl_exits()
