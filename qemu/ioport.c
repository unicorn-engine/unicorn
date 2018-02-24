/*
 * QEMU System Emulator
 *
 * Copyright (c) 2003-2008 Fabrice Bellard
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
 * THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */
/*
 * splitted out ioport related stuffs from vl.c.
 */

/* Modified for Unicorn Engine by Nguyen Anh Quynh, 2015 */

#include "qemu/osdep.h"
#include "qemu-common.h"
#include "cpu.h"
#include "exec/ioport.h"
#include "exec/memory.h"
#include "exec/address-spaces.h"

#include "uc_priv.h"

typedef struct MemoryRegionPortioList {
    MemoryRegion mr;
    void *portio_opaque;
    MemoryRegionPortio ports[];
} MemoryRegionPortioList;

static uint64_t unassigned_io_read(struct uc_struct* uc, void *opaque, hwaddr addr, unsigned size)
{
    return 0-1ULL;
}

static void unassigned_io_write(struct uc_struct* uc, void *opaque, hwaddr addr, uint64_t val,
                                unsigned size)
{
}

static MemTxResult unassigned_io_read_with_attrs(struct uc_struct* uc, void *opaque, hwaddr addr,
                                                 uint64_t *data, unsigned size, MemTxAttrs attrs)
{
    return MEMTX_OK;
}

static MemTxResult unassigned_write_with_attrs(struct uc_struct* uc, void *opaque,
                                               hwaddr addr, uint64_t data, unsigned size,
                                               MemTxAttrs attrs)
{
    return MEMTX_OK;
}


const MemoryRegionOps unassigned_io_ops = {
    unassigned_io_read,
    unassigned_io_write,
    unassigned_io_read_with_attrs,
    unassigned_write_with_attrs,
    DEVICE_NATIVE_ENDIAN,
};

void cpu_outb(struct uc_struct *uc, pio_addr_t addr, uint8_t val)
{
    // Unicorn: commented out
    //trace_cpu_out(addr, 'b', val);
    // Unicorn: call registered OUT callbacks
    struct hook *hook;
    HOOK_FOREACH_VAR_DECLARE;
    HOOK_FOREACH(uc, hook, UC_HOOK_INSN) {
        if (hook->insn == UC_X86_INS_OUT)
            ((uc_cb_insn_out_t)hook->callback)(uc, addr, 1, val, hook->user_data);
    }
}

void cpu_outw(struct uc_struct *uc, pio_addr_t addr, uint16_t val)
{
    // Unicorn: commented out
    //trace_cpu_out(addr, 'w', val);
    // Unicorn: call registered OUT callbacks
    struct hook *hook;
    HOOK_FOREACH_VAR_DECLARE;
    HOOK_FOREACH(uc, hook, UC_HOOK_INSN) {
        if (hook->insn == UC_X86_INS_OUT)
            ((uc_cb_insn_out_t)hook->callback)(uc, addr, 2, val, hook->user_data);
    }
}

void cpu_outl(struct uc_struct *uc, pio_addr_t addr, uint32_t val)
{
    // Unicorn: commented out
    //trace_cpu_out(addr, 'l', val);
    // Unicorn: call registered OUT callbacks
    struct hook *hook;
    HOOK_FOREACH_VAR_DECLARE;
    HOOK_FOREACH(uc, hook, UC_HOOK_INSN) {
        if (hook->insn == UC_X86_INS_OUT)
            ((uc_cb_insn_out_t)hook->callback)(uc, addr, 4, val, hook->user_data);
    }
}

uint8_t cpu_inb(struct uc_struct *uc, pio_addr_t addr)
{
    // Unicorn: commented out
    //trace_cpu_in(addr, 'b', val);
    // Unicorn: call registered IN callbacks
    struct hook *hook;
    HOOK_FOREACH_VAR_DECLARE;
    HOOK_FOREACH(uc, hook, UC_HOOK_INSN) {
        if (hook->insn == UC_X86_INS_IN)
            return ((uc_cb_insn_in_t)hook->callback)(uc, addr, 1, hook->user_data);
    }

    return 0;
}

uint16_t cpu_inw(struct uc_struct *uc, pio_addr_t addr)
{
    // Unicorn: commented out
    //trace_cpu_in(addr, 'w', val);
    // Unicorn: call registered IN callbacks
    struct hook *hook;
    HOOK_FOREACH_VAR_DECLARE;
    HOOK_FOREACH(uc, hook, UC_HOOK_INSN) {
        if (hook->insn == UC_X86_INS_IN)
            return ((uc_cb_insn_in_t)hook->callback)(uc, addr, 2, hook->user_data);
    }

    return 0;
}

uint32_t cpu_inl(struct uc_struct *uc, pio_addr_t addr)
{
    // Unicorn: commented out
    //trace_cpu_in(addr, 'l', val);
    // Unicorn: call registered IN callbacks
    struct hook *hook;
    HOOK_FOREACH_VAR_DECLARE;
    HOOK_FOREACH(uc, hook, UC_HOOK_INSN) {
        if (hook->insn == UC_X86_INS_IN)
            return ((uc_cb_insn_in_t)hook->callback)(uc, addr, 4, hook->user_data);
    }

    return 0;
}
