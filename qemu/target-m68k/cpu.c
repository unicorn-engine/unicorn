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
/* Modified for Unicorn Engine by Chen Huitao<chenhuitao@hfmrit.com>, 2020 */

#include "cpu.h"
#include "qemu-common.h"
#include "uc_priv.h"


static void m68k_cpu_set_pc(CPUState *cs, vaddr value)
{
    M68kCPU *cpu = M68K_CPU(cs->uc, cs);

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

/* CPUClass::reset() */
static void m68k_cpu_reset(CPUState *s)
{
    M68kCPU *cpu = M68K_CPU(s->uc, s);
    M68kCPUClass *mcc = M68K_CPU_GET_CLASS(s->uc, cpu);
    CPUM68KState *env = &cpu->env;

    mcc->parent_reset(s);

    memset(env, 0, offsetof(CPUM68KState, features));
#if !defined(CONFIG_USER_ONLY)
    env->sr = 0x2700;
#endif
    m68k_switch_sp(env);
    /* ??? FP regs should be initialized to NaN.  */
    env->cc_op = CC_OP_FLAGS;
    /* TODO: We should set PC from the interrupt vector.  */
    env->pc = 0;
    tlb_flush(s, 1);
}

static void m5206_cpu_initfn(struct uc_struct *uc, CPUState *obj, void *opaque)
{
    M68kCPU *cpu = M68K_CPU(uc, obj);
    CPUM68KState *env = &cpu->env;

    m68k_set_feature(env, M68K_FEATURE_CF_ISA_A);
}

static void m5208_cpu_initfn(struct uc_struct *uc, CPUState *obj, void *opaque)
{
    M68kCPU *cpu = M68K_CPU(uc, obj);
    CPUM68KState *env = &cpu->env;

    m68k_set_feature(env, M68K_FEATURE_CF_ISA_A);
    m68k_set_feature(env, M68K_FEATURE_CF_ISA_APLUSC);
    m68k_set_feature(env, M68K_FEATURE_BRAL);
    m68k_set_feature(env, M68K_FEATURE_CF_EMAC);
    m68k_set_feature(env, M68K_FEATURE_USP);
}

static void cfv4e_cpu_initfn(struct uc_struct *uc, CPUState *obj, void *opaque)
{
    M68kCPU *cpu = M68K_CPU(uc, obj);
    CPUM68KState *env = &cpu->env;

    m68k_set_feature(env, M68K_FEATURE_CF_ISA_A);
    m68k_set_feature(env, M68K_FEATURE_CF_ISA_B);
    m68k_set_feature(env, M68K_FEATURE_BRAL);
    m68k_set_feature(env, M68K_FEATURE_CF_FPU);
    m68k_set_feature(env, M68K_FEATURE_CF_EMAC);
    m68k_set_feature(env, M68K_FEATURE_USP);
}

static void any_cpu_initfn(struct uc_struct *uc, CPUState *obj, void *opaque)
{
    M68kCPU *cpu = M68K_CPU(uc, obj);
    CPUM68KState *env = &cpu->env;

    m68k_set_feature(env, M68K_FEATURE_CF_ISA_A);
    m68k_set_feature(env, M68K_FEATURE_CF_ISA_B);
    m68k_set_feature(env, M68K_FEATURE_CF_ISA_APLUSC);
    m68k_set_feature(env, M68K_FEATURE_BRAL);
    m68k_set_feature(env, M68K_FEATURE_CF_FPU);
    /* MAC and EMAC are mututally exclusive, so pick EMAC.
       It's mostly backwards compatible.  */
    m68k_set_feature(env, M68K_FEATURE_CF_EMAC);
    m68k_set_feature(env, M68K_FEATURE_CF_EMAC_B);
    m68k_set_feature(env, M68K_FEATURE_USP);
    m68k_set_feature(env, M68K_FEATURE_EXT_FULL);
    m68k_set_feature(env, M68K_FEATURE_WORD_INDEX);
}

typedef struct M68kCPUInfo {
    const char *name;
    void (*instance_init)(struct uc_struct *uc, CPUState *obj, void *opaque);
} M68kCPUInfo;

static const M68kCPUInfo m68k_cpus[] = {
    { "m5206", m5206_cpu_initfn },
    { "m5208", m5208_cpu_initfn },
    { "cfv4e", cfv4e_cpu_initfn },
    { "any",   any_cpu_initfn },
};

static int m68k_cpu_realizefn(struct uc_struct *uc, CPUState *dev)
{
    CPUState *cs = CPU(dev);

    cpu_reset(cs);
    qemu_init_vcpu(cs);

    return 0;
}

static void m68k_cpu_initfn(struct uc_struct *uc, CPUState *obj, void *opaque)
{
    CPUState *cs = CPU(obj);
    M68kCPU *cpu = M68K_CPU(uc, obj);
    CPUM68KState *env = &cpu->env;

    cs->env_ptr = env;
    cpu_exec_init(env, opaque);

    if (tcg_enabled(uc)) {
        m68k_tcg_init(uc);
    }
}

static void m68k_cpu_class_init(struct uc_struct *uc, CPUClass *c, void *data)
{
    M68kCPUClass *mcc = M68K_CPU_CLASS(uc, c);
    CPUClass *cc = CPU_CLASS(uc, c);

    mcc->parent_reset = cc->reset;
    cc->reset = m68k_cpu_reset;

    cc->has_work = m68k_cpu_has_work;
    cc->do_interrupt = m68k_cpu_do_interrupt;
    cc->cpu_exec_interrupt = m68k_cpu_exec_interrupt;
    cc->set_pc = m68k_cpu_set_pc;
#ifdef CONFIG_USER_ONLY
    cc->handle_mmu_fault = m68k_cpu_handle_mmu_fault;
#else
    cc->get_phys_page_debug = m68k_cpu_get_phys_page_debug;
#endif
    cc->cpu_exec_enter = m68k_cpu_exec_enter;
    cc->cpu_exec_exit = m68k_cpu_exec_exit;
}

M68kCPU *cpu_m68k_init(struct uc_struct *uc, const char *cpu_model)
{
    int i;
    M68kCPU *cpu;
    CPUState *cs;
    CPUClass *cc;
    CPUM68KState *env;

    if (cpu_model == NULL) {
        cpu_model = "cfv4e";
    }

    cpu = malloc(sizeof(*cpu));
    if (cpu == NULL) {
        return NULL;
    }
    memset(cpu, 0, sizeof(*cpu));

    cs = (CPUState *)cpu;
    cc = (CPUClass *)&cpu->cc;
    cs->cc = cc;
    cs->uc = uc;
    /* init CPUClass */
    cpu_klass_init(uc, cc);
    /* init M68kCPUClass */
    m68k_cpu_class_init(uc, cc, NULL);
    /* init CPUState */
#ifdef NEED_CPU_INIT_REALIZE
    cpu_object_init(uc, cs);
#endif
    /* init M68kCPU */
    m68k_cpu_initfn(uc, cs, uc);
    /* init M68k types */
    for (i = 0; i < ARRAY_SIZE(m68k_cpus); i++) {
        if (strcmp(cpu_model, m68k_cpus[i].name) == 0) {
            m68k_cpus[i].instance_init(uc, cs, uc);
            break;
        }
    }
    if (i >= ARRAY_SIZE(m68k_cpus)) {
        free(cpu);
        return NULL;
    }
    /* realize M68kCPU */
    m68k_cpu_realizefn(uc, cs);
    /* realize CPUState */
#ifdef NEED_CPU_INIT_REALIZE
    cpu_object_realize(uc, cs);
#endif

    env = &cpu->env;
    register_m68k_insns(env);

    return cpu;
}
