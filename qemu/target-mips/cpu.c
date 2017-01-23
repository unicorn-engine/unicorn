/*
 * QEMU MIPS CPU
 *
 * Copyright (c) 2012 SUSE LINUX Products GmbH
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, see
 * <http://www.gnu.org/licenses/lgpl-2.1.html>
 */

#include "cpu.h"
#include "qemu-common.h"
#include "hw/mips/mips.h"


static void mips_cpu_set_pc(CPUState *cs, vaddr value)
{
    MIPSCPU *cpu = MIPS_CPU(cs->uc, cs);
    CPUMIPSState *env = &cpu->env;

    env->active_tc.PC = value & ~(target_ulong)1;
    if (value & 1) {
        env->hflags |= MIPS_HFLAG_M16;
    } else {
        env->hflags &= ~(MIPS_HFLAG_M16);
    }
}

static void mips_cpu_synchronize_from_tb(CPUState *cs, TranslationBlock *tb)
{
    MIPSCPU *cpu = MIPS_CPU(cs->uc, cs);
    CPUMIPSState *env = &cpu->env;

    env->active_tc.PC = tb->pc;
    env->hflags &= ~MIPS_HFLAG_BMASK;
    env->hflags |= tb->flags & MIPS_HFLAG_BMASK;
}

static bool mips_cpu_has_work(CPUState *cs)
{
    MIPSCPU *cpu = MIPS_CPU(cs->uc, cs);
    CPUMIPSState *env = &cpu->env;
    bool has_work = false;

    /* It is implementation dependent if non-enabled interrupts
       wake-up the CPU, however most of the implementations only
       check for interrupts that can be taken. */
    if ((cs->interrupt_request & CPU_INTERRUPT_HARD) &&
        cpu_mips_hw_interrupts_pending(env)) {
        has_work = true;
    }

    /* MIPS-MT has the ability to halt the CPU.  */
    if (env->CP0_Config3 & (1 << CP0C3_MT)) {
        /* The QEMU model will issue an _WAKE request whenever the CPUs
           should be woken up.  */
        if (cs->interrupt_request & CPU_INTERRUPT_WAKE) {
            has_work = true;
        }

        if (!mips_vpe_active(env)) {
            has_work = false;
        }
    }
    return has_work;
}

/* CPUClass::reset() */
static void mips_cpu_reset(CPUState *s)
{
    MIPSCPU *cpu = MIPS_CPU(s->uc, s);
    MIPSCPUClass *mcc = MIPS_CPU_GET_CLASS(s->uc, cpu);
    CPUMIPSState *env = &cpu->env;

    mcc->parent_reset(s);

    memset(env, 0, offsetof(CPUMIPSState, mvp));
    tlb_flush(s, 1);

    cpu_state_reset(env);
}

static int mips_cpu_realizefn(struct uc_struct *uc, DeviceState *dev, Error **errp)
{
    CPUState *cs = CPU(dev);
    MIPSCPUClass *mcc = MIPS_CPU_GET_CLASS(uc, dev);

    cpu_reset(cs);
    qemu_init_vcpu(cs);

    mcc->parent_realize(uc, dev, errp);

    return 0;
}

static void mips_cpu_initfn(struct uc_struct *uc, Object *obj, void *opaque)
{
    CPUState *cs = CPU(obj);
    MIPSCPU *cpu = MIPS_CPU(uc, obj);
    CPUMIPSState *env = &cpu->env;

    cs->env_ptr = env;
    cpu_exec_init(env, opaque);

    if (tcg_enabled(uc)) {
        mips_tcg_init(uc);
    }
}

static void mips_cpu_class_init(struct uc_struct *uc, ObjectClass *c, void *data)
{
    MIPSCPUClass *mcc = MIPS_CPU_CLASS(uc, c);
    CPUClass *cc = CPU_CLASS(uc, c);
    DeviceClass *dc = DEVICE_CLASS(uc, c);

    mcc->parent_realize = dc->realize;
    dc->realize = mips_cpu_realizefn;

    mcc->parent_reset = cc->reset;
    cc->reset = mips_cpu_reset;

    cc->has_work = mips_cpu_has_work;
    cc->do_interrupt = mips_cpu_do_interrupt;
    cc->cpu_exec_interrupt = mips_cpu_exec_interrupt;
    cc->set_pc = mips_cpu_set_pc;
    cc->synchronize_from_tb = mips_cpu_synchronize_from_tb;
#ifdef CONFIG_USER_ONLY
    cc->handle_mmu_fault = mips_cpu_handle_mmu_fault;
#else
    cc->do_unassigned_access = mips_cpu_unassigned_access;
    cc->do_unaligned_access = mips_cpu_do_unaligned_access;
    cc->get_phys_page_debug = mips_cpu_get_phys_page_debug;
#endif
}

void mips_cpu_register_types(void *opaque)
{
    const TypeInfo mips_cpu_type_info = {
        TYPE_MIPS_CPU,
        TYPE_CPU,
        
        sizeof(MIPSCPUClass),
        sizeof(MIPSCPU),
        opaque,
        
        mips_cpu_initfn,
        NULL,
        NULL,

        NULL,

        mips_cpu_class_init,
        NULL,
        NULL,

        false,
    };

    type_register_static(opaque, &mips_cpu_type_info);
}
