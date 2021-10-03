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

#include "qemu/osdep.h"
#include "cpu.h"
#include "exec/memory.h"
#include "uc_priv.h"

static uint64_t unassigned_io_read(struct uc_struct *uc, void* opaque, hwaddr addr, unsigned size)
{
#ifdef _MSC_VER
    return (uint64_t)0xffffffffffffffffULL;
#else
    return (uint64_t)-1ULL;
#endif
}

static void unassigned_io_write(struct uc_struct *uc, void* opaque, hwaddr addr, uint64_t data, unsigned size)
{
}

const MemoryRegionOps unassigned_io_ops = {
    .read = unassigned_io_read,
    .write = unassigned_io_write,
    .endianness = DEVICE_NATIVE_ENDIAN,
};

void cpu_outb(struct uc_struct *uc, uint32_t addr, uint8_t val)
{
    // address_space_write(&uc->address_space_io, addr, MEMTXATTRS_UNSPECIFIED,
    //                     &val, 1);

    //LOG_IOPORT("outb: %04"FMT_pioaddr" %02"PRIx8"\n", addr, val);
    // Unicorn: call registered OUT callbacks
    struct hook *hook;
    HOOK_FOREACH_VAR_DECLARE;
    HOOK_FOREACH(uc, hook, UC_HOOK_INSN) {
        if (hook->to_delete)
            continue;
        if (hook->insn == UC_X86_INS_OUT)
            ((uc_cb_insn_out_t)hook->callback)(uc, addr, 1, val, hook->user_data);
    }
}

void cpu_outw(struct uc_struct *uc, uint32_t addr, uint16_t val)
{
    // uint8_t buf[2];

    // stw_p(buf, val);
    // address_space_write(&uc->address_space_io, addr, MEMTXATTRS_UNSPECIFIED,
    //                     buf, 2);

    //LOG_IOPORT("outw: %04"FMT_pioaddr" %04"PRIx16"\n", addr, val);
    // Unicorn: call registered OUT callbacks
    struct hook *hook;
    HOOK_FOREACH_VAR_DECLARE;
    HOOK_FOREACH(uc, hook, UC_HOOK_INSN) {
        if (hook->to_delete)
            continue;
        if (hook->insn == UC_X86_INS_OUT)
            ((uc_cb_insn_out_t)hook->callback)(uc, addr, 2, val, hook->user_data);
    }
}

void cpu_outl(struct uc_struct *uc, uint32_t addr, uint32_t val)
{
    // uint8_t buf[4];

    // stl_p(buf, val);
    // address_space_write(&uc->address_space_io, addr, MEMTXATTRS_UNSPECIFIED,
    //                     buf, 4);

    //LOG_IOPORT("outl: %04"FMT_pioaddr" %08"PRIx32"\n", addr, val);
    // Unicorn: call registered OUT callbacks
    struct hook *hook;
    HOOK_FOREACH_VAR_DECLARE;
    HOOK_FOREACH(uc, hook, UC_HOOK_INSN) {
        if (hook->to_delete)
            continue;
        if (hook->insn == UC_X86_INS_OUT)
            ((uc_cb_insn_out_t)hook->callback)(uc, addr, 4, val, hook->user_data);
    }
}

uint8_t cpu_inb(struct uc_struct *uc, uint32_t addr)
{
    // uint8_t val;

    // address_space_read(&uc->address_space_io, addr, MEMTXATTRS_UNSPECIFIED,
    //                    &val, 1);

    //LOG_IOPORT("inb : %04"FMT_pioaddr" %02"PRIx8"\n", addr, val);
    // Unicorn: call registered IN callbacks
    struct hook *hook;
    HOOK_FOREACH_VAR_DECLARE;
    HOOK_FOREACH(uc, hook, UC_HOOK_INSN) {
        if (hook->to_delete)
            continue;
        if (hook->insn == UC_X86_INS_IN)
            return ((uc_cb_insn_in_t)hook->callback)(uc, addr, 1, hook->user_data);
    }

    return 0;
}

uint16_t cpu_inw(struct uc_struct *uc, uint32_t addr)
{
    // uint8_t buf[2];
    // uint16_t val;

    // address_space_read(&uc->address_space_io, addr, MEMTXATTRS_UNSPECIFIED, buf, 2);
    // val = lduw_p(buf);

    //LOG_IOPORT("inw : %04"FMT_pioaddr" %04"PRIx16"\n", addr, val);
    // Unicorn: call registered IN callbacks
    struct hook *hook;
    HOOK_FOREACH_VAR_DECLARE;
    HOOK_FOREACH(uc, hook, UC_HOOK_INSN) {
        if (hook->to_delete)
            continue;
        if (hook->insn == UC_X86_INS_IN)
            return ((uc_cb_insn_in_t)hook->callback)(uc, addr, 2, hook->user_data);
    }

    return 0;
}

uint32_t cpu_inl(struct uc_struct *uc, uint32_t addr)
{
    // uint8_t buf[4];
    // uint32_t val;

    // printf("inl_addr=%x\n", addr);

    // address_space_read(&uc->address_space_io, addr, MEMTXATTRS_UNSPECIFIED, buf, 4);
    // val = ldl_p(buf);

    //LOG_IOPORT("inl : %04"FMT_pioaddr" %08"PRIx32"\n", addr, val);
    // Unicorn: call registered IN callbacks
    struct hook *hook;
    HOOK_FOREACH_VAR_DECLARE;
    HOOK_FOREACH(uc, hook, UC_HOOK_INSN) {
        if (hook->to_delete)
            continue;
        if (hook->insn == UC_X86_INS_IN)
            return ((uc_cb_insn_in_t)hook->callback)(uc, addr, 4, hook->user_data);
    }

    return 0;
}
