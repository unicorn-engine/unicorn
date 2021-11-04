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

#include "qemu/osdep.h"
#include "cpu.h"
#include "internal.h"
#include "exec/exec-all.h"

#include <uc_priv.h>

static void mips_cpu_set_pc(CPUState *cs, vaddr value)
{
    MIPSCPU *cpu = MIPS_CPU(cs);
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
    MIPSCPU *cpu = MIPS_CPU(cs);
    CPUMIPSState *env = &cpu->env;

    env->active_tc.PC = tb->pc;
    env->hflags &= ~MIPS_HFLAG_BMASK;
    env->hflags |= tb->flags & MIPS_HFLAG_BMASK;
}

static bool mips_cpu_has_work(CPUState *cs)
{
    MIPSCPU *cpu = MIPS_CPU(cs);
    CPUMIPSState *env = &cpu->env;
    bool has_work = false;

    /*
     * Prior to MIPS Release 6 it is implementation dependent if non-enabled
     * interrupts wake-up the CPU, however most of the implementations only
     * check for interrupts that can be taken.
     */
    if ((cs->interrupt_request & CPU_INTERRUPT_HARD) &&
        cpu_mips_hw_interrupts_pending(env)) {
        if (cpu_mips_hw_interrupts_enabled(env) ||
            (env->insn_flags & ISA_MIPS32R6)) {
            has_work = true;
        }
    }

    /* MIPS-MT has the ability to halt the CPU.  */
    if (env->CP0_Config3 & (1 << CP0C3_MT)) {
        /*
         * The QEMU model will issue an _WAKE request whenever the CPUs
         * should be woken up.
         */
        if (cs->interrupt_request & CPU_INTERRUPT_WAKE) {
            has_work = true;
        }

        if (!mips_vpe_active(env)) {
            has_work = false;
        }
    }

    /* MIPS Release 6 has the ability to halt the CPU.  */
    if (env->CP0_Config5 & (1 << CP0C5_VP)) {
        if (cs->interrupt_request & CPU_INTERRUPT_WAKE) {
            has_work = true;
        }
        if (!mips_vp_active(env, cs)) {
            has_work = false;
        }
    }

    return has_work;
}

static void mips_cpu_reset(CPUState *dev)
{
    CPUState *s = CPU(dev);
    MIPSCPU *cpu = MIPS_CPU(s);
    MIPSCPUClass *mcc = MIPS_CPU_GET_CLASS(cpu);
    CPUMIPSState *env = &cpu->env;

    mcc->parent_reset(dev);

    memset(env, 0, offsetof(CPUMIPSState, end_reset_fields));

    cpu_state_reset(env);
}

static void mips_cpu_realizefn(CPUState *dev)
{
    CPUState *cs = CPU(dev);
    MIPSCPU *cpu = MIPS_CPU(dev);

    cpu_exec_realizefn(cs);

    cpu_mips_realize_env(&cpu->env);

    cpu_reset(cs);
}

static void mips_cpu_initfn(struct uc_struct *uc, CPUState *obj)
{
    MIPSCPU *cpu = MIPS_CPU(obj);
    CPUMIPSState *env = &cpu->env;

    env->uc = uc;
    cpu_set_cpustate_pointers(cpu);
}

static void mips_cpu_class_init(CPUClass *c)
{
    MIPSCPUClass *mcc = MIPS_CPU_CLASS(c);
    CPUClass *cc = CPU_CLASS(c);

    /* parent class is CPUClass, parent_reset() is cpu_common_reset(). */
    mcc->parent_reset = cc->reset;
    /* overwrite the CPUClass->reset to arch reset: x86_cpu_reset(). */
    cc->reset = mips_cpu_reset;
    cc->has_work = mips_cpu_has_work;
    cc->do_interrupt = mips_cpu_do_interrupt;
    cc->cpu_exec_interrupt = mips_cpu_exec_interrupt;
    cc->set_pc = mips_cpu_set_pc;
    cc->synchronize_from_tb = mips_cpu_synchronize_from_tb;
    cc->do_unaligned_access = mips_cpu_do_unaligned_access;
    cc->get_phys_page_debug = mips_cpu_get_phys_page_debug;
    cc->tcg_initialize = mips_tcg_init;
    cc->tlb_fill = mips_cpu_tlb_fill;
}

MIPSCPU *cpu_mips_init(struct uc_struct *uc)
{
    MIPSCPU *cpu;
    CPUState *cs;
    CPUClass *cc;
    CPUMIPSState *env;

    cpu = calloc(1, sizeof(*cpu));
    if (cpu == NULL) {
        return NULL;
    }

#ifdef TARGET_MIPS64
    if (uc->cpu_model == INT_MAX) {
        uc->cpu_model = 17; // R4000
    } else if (uc->cpu_model + UC_CPU_MIPS32_I7200 + 1 >= mips_defs_number ) {
        free(cpu);
        return NULL;
    }
#else
    if (uc->cpu_model == INT_MAX) {
        uc->cpu_model = 10; // 74kf
    } else if (uc->cpu_model >= mips_defs_number) {
        free(cpu);
        return NULL;
    }
#endif

    cs = (CPUState *)cpu;
    cc = (CPUClass *)&cpu->cc;
    cs->cc = cc;
    cs->uc = uc;
    uc->cpu = cs;

    cpu_class_init(uc, cc);

    mips_cpu_class_init(cc);

    cpu_common_initfn(uc, cs);

    mips_cpu_initfn(uc, cs);

    env = &cpu->env;
    env->cpu_model = &(mips_defs[uc->cpu_model]);

    if (env->cpu_model == NULL) {
        free(cpu);
        return NULL;
    }

    mips_cpu_realizefn(cs);

    // init address space
    cpu_address_space_init(cs, 0, cs->memory);

    qemu_init_vcpu(cs);

    return cpu;
}
