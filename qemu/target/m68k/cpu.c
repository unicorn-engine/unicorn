/*
 * QEMU Motorola 68k CPU
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
#include "fpu/softfloat.h"
#include "exec/exec-all.h"

static void m68k_cpu_set_pc(CPUState *cs, vaddr value)
{
    M68kCPU *cpu = M68K_CPU(cs);

    cpu->env.pc = value;
}

static bool m68k_cpu_has_work(CPUState *cs)
{
    return cs->interrupt_request & CPU_INTERRUPT_HARD;
}

static void m68k_set_feature(CPUM68KState *env, int feature)
{
    env->features |= (1u << feature);
}

static void m68k_cpu_reset(CPUState *dev)
{
    CPUState *s = CPU(dev);
    M68kCPU *cpu = M68K_CPU(s);
    M68kCPUClass *mcc = M68K_CPU_GET_CLASS(cpu);
    CPUM68KState *env = &cpu->env;
    floatx80 nan = floatx80_default_nan(NULL);
    int i;

    mcc->parent_reset(dev);

    memset(env, 0, offsetof(CPUM68KState, end_reset_fields));
    cpu_m68k_set_sr(env, SR_S | SR_I);
    for (i = 0; i < 8; i++) {
        env->fregs[i].d = nan;
    }
    cpu_m68k_set_fpcr(env, 0);
    env->fpsr = 0;

    /* TODO: We should set PC from the interrupt vector.  */
    env->pc = 0;
}

/* CPU models */

static void m5206_cpu_initfn(CPUState *obj)
{
    M68kCPU *cpu = M68K_CPU(obj);
    CPUM68KState *env = &cpu->env;

    m68k_set_feature(env, M68K_FEATURE_CF_ISA_A);
}

static void m68000_cpu_initfn(CPUState *obj)
{
    M68kCPU *cpu = M68K_CPU(obj);
    CPUM68KState *env = &cpu->env;

    m68k_set_feature(env, M68K_FEATURE_M68000);
    m68k_set_feature(env, M68K_FEATURE_USP);
    m68k_set_feature(env, M68K_FEATURE_WORD_INDEX);
    m68k_set_feature(env, M68K_FEATURE_MOVEP);
}

/* common features for 68020, 68030 and 68040 */
static void m680x0_cpu_common(CPUM68KState *env)
{
    m68k_set_feature(env, M68K_FEATURE_M68000);
    m68k_set_feature(env, M68K_FEATURE_USP);
    m68k_set_feature(env, M68K_FEATURE_WORD_INDEX);
    m68k_set_feature(env, M68K_FEATURE_QUAD_MULDIV);
    m68k_set_feature(env, M68K_FEATURE_BRAL);
    m68k_set_feature(env, M68K_FEATURE_BCCL);
    m68k_set_feature(env, M68K_FEATURE_BITFIELD);
    m68k_set_feature(env, M68K_FEATURE_EXT_FULL);
    m68k_set_feature(env, M68K_FEATURE_SCALED_INDEX);
    m68k_set_feature(env, M68K_FEATURE_LONG_MULDIV);
    m68k_set_feature(env, M68K_FEATURE_FPU);
    m68k_set_feature(env, M68K_FEATURE_CAS);
    m68k_set_feature(env, M68K_FEATURE_BKPT);
    m68k_set_feature(env, M68K_FEATURE_RTD);
    m68k_set_feature(env, M68K_FEATURE_CHK2);
    m68k_set_feature(env, M68K_FEATURE_MOVEP);
}

static void m68020_cpu_initfn(CPUState *obj)
{
    M68kCPU *cpu = M68K_CPU(obj);
    CPUM68KState *env = &cpu->env;

    m680x0_cpu_common(env);
    m68k_set_feature(env, M68K_FEATURE_M68020);
}

static void m68030_cpu_initfn(CPUState *obj)
{
    M68kCPU *cpu = M68K_CPU(obj);
    CPUM68KState *env = &cpu->env;

    m680x0_cpu_common(env);
    m68k_set_feature(env, M68K_FEATURE_M68030);
}

static void m68040_cpu_initfn(CPUState *obj)
{
    M68kCPU *cpu = M68K_CPU(obj);
    CPUM68KState *env = &cpu->env;

    m680x0_cpu_common(env);
    m68k_set_feature(env, M68K_FEATURE_M68040);
}

static void m68060_cpu_initfn(CPUState *obj)
{
    M68kCPU *cpu = M68K_CPU(obj);
    CPUM68KState *env = &cpu->env;

    m68k_set_feature(env, M68K_FEATURE_M68000);
    m68k_set_feature(env, M68K_FEATURE_USP);
    m68k_set_feature(env, M68K_FEATURE_WORD_INDEX);
    m68k_set_feature(env, M68K_FEATURE_BRAL);
    m68k_set_feature(env, M68K_FEATURE_BCCL);
    m68k_set_feature(env, M68K_FEATURE_BITFIELD);
    m68k_set_feature(env, M68K_FEATURE_EXT_FULL);
    m68k_set_feature(env, M68K_FEATURE_SCALED_INDEX);
    m68k_set_feature(env, M68K_FEATURE_LONG_MULDIV);
    m68k_set_feature(env, M68K_FEATURE_FPU);
    m68k_set_feature(env, M68K_FEATURE_CAS);
    m68k_set_feature(env, M68K_FEATURE_BKPT);
    m68k_set_feature(env, M68K_FEATURE_RTD);
    m68k_set_feature(env, M68K_FEATURE_CHK2);
    m68k_set_feature(env, M68K_FEATURE_M68060);
}

static void m5208_cpu_initfn(CPUState *obj)
{
    M68kCPU *cpu = M68K_CPU(obj);
    CPUM68KState *env = &cpu->env;

    m68k_set_feature(env, M68K_FEATURE_CF_ISA_A);
    m68k_set_feature(env, M68K_FEATURE_CF_ISA_APLUSC);
    m68k_set_feature(env, M68K_FEATURE_BRAL);
    m68k_set_feature(env, M68K_FEATURE_CF_EMAC);
    m68k_set_feature(env, M68K_FEATURE_USP);
}

static void cfv4e_cpu_initfn(CPUState *obj)
{
    M68kCPU *cpu = M68K_CPU(obj);
    CPUM68KState *env = &cpu->env;

    m68k_set_feature(env, M68K_FEATURE_CF_ISA_A);
    m68k_set_feature(env, M68K_FEATURE_CF_ISA_B);
    m68k_set_feature(env, M68K_FEATURE_BRAL);
    m68k_set_feature(env, M68K_FEATURE_CF_FPU);
    m68k_set_feature(env, M68K_FEATURE_CF_EMAC);
    m68k_set_feature(env, M68K_FEATURE_USP);
}

static void any_cpu_initfn(CPUState *obj)
{
    M68kCPU *cpu = M68K_CPU(obj);
    CPUM68KState *env = &cpu->env;

    m68k_set_feature(env, M68K_FEATURE_CF_ISA_A);
    m68k_set_feature(env, M68K_FEATURE_CF_ISA_B);
    m68k_set_feature(env, M68K_FEATURE_CF_ISA_APLUSC);
    m68k_set_feature(env, M68K_FEATURE_BRAL);
    m68k_set_feature(env, M68K_FEATURE_CF_FPU);
    /*
     * MAC and EMAC are mututally exclusive, so pick EMAC.
     * It's mostly backwards compatible.
     */
    m68k_set_feature(env, M68K_FEATURE_CF_EMAC);
    m68k_set_feature(env, M68K_FEATURE_CF_EMAC_B);
    m68k_set_feature(env, M68K_FEATURE_USP);
    m68k_set_feature(env, M68K_FEATURE_EXT_FULL);
    m68k_set_feature(env, M68K_FEATURE_WORD_INDEX);
}

static void m68k_cpu_realizefn(CPUState *dev)
{
    CPUState *cs = CPU(dev);
    M68kCPU *cpu = M68K_CPU(dev);

    register_m68k_insns(&cpu->env);
    cpu_exec_realizefn(cs);
}

static void m68k_cpu_initfn(struct uc_struct *uc, CPUState *obj)
{
    M68kCPU *cpu = M68K_CPU(obj);
    CPUM68KState *env = &cpu->env;

    env->uc = uc;
    cpu_set_cpustate_pointers(cpu);
}

static void m68k_cpu_class_init(CPUClass *c)
{
    M68kCPUClass *mcc = M68K_CPU_CLASS(c);
    CPUClass *cc = CPU_CLASS(c);

    /* parent class is CPUClass, parent_reset() is cpu_common_reset(). */
    mcc->parent_reset = cc->reset;
    /* overwrite the CPUClass->reset to arch reset: x86_cpu_reset(). */
    cc->reset = m68k_cpu_reset;
    cc->has_work = m68k_cpu_has_work;
    cc->do_interrupt = m68k_cpu_do_interrupt;
    cc->cpu_exec_interrupt = m68k_cpu_exec_interrupt;
    cc->set_pc = m68k_cpu_set_pc;
    cc->tlb_fill_cpu = m68k_cpu_tlb_fill;
    cc->get_phys_page_debug = m68k_cpu_get_phys_page_debug;
    cc->tcg_initialize = m68k_tcg_init;
}

#define DEFINE_M68K_CPU_TYPE(cpu_model, initfn) \
    {                                           \
        .name = cpu_model,  \
        .initfn = initfn,                \
    }

struct M68kCPUInfo {
    const char *name;
    void (*initfn)(CPUState *obj);
};

static struct M68kCPUInfo m68k_cpus_type_infos[] = {
    { "m68000", m68000_cpu_initfn },
    { "m68020", m68020_cpu_initfn },
    { "m68030", m68030_cpu_initfn },
    { "m68040", m68040_cpu_initfn },
    { "m68060", m68060_cpu_initfn },
    { "m5206", m5206_cpu_initfn },
    { "m5208", m5208_cpu_initfn },
    { "cfv4e", cfv4e_cpu_initfn },
    { "any", any_cpu_initfn },
};

M68kCPU *cpu_m68k_init(struct uc_struct *uc)
{
    M68kCPU *cpu;
    CPUState *cs;
    CPUClass *cc;

    cpu = calloc(1, sizeof(*cpu));
    if (cpu == NULL) {
        return NULL;
    }

    if (uc->cpu_model == INT_MAX) {
        uc->cpu_model = UC_CPU_M68K_CFV4E; // cfv4e
    } else if (uc->cpu_model >= ARRAY_SIZE(m68k_cpus_type_infos)) {
        free(cpu);
        return NULL;
    }

    cs = (CPUState *)cpu;
    cc = (CPUClass *)&cpu->cc;
    cs->cc = cc;
    cs->uc = uc;
    uc->cpu = cs;

    cpu_class_init(uc, cc);

    m68k_cpu_class_init(cc);

    cpu_common_initfn(uc, cs);

    m68k_cpu_initfn(uc, cs);

    m68k_cpus_type_infos[uc->cpu_model].initfn(cs);

    m68k_cpu_realizefn(cs);

    // init address space
    cpu_address_space_init(cs, 0, cs->memory);

    qemu_init_vcpu(cs);

    return cpu;
}
