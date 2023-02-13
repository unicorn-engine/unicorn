/*
 *  TriCore emulation for qemu: main translation routines.
 *
 *  Copyright (c) 2012-2014 Bastian Koppelmann C-Lab/University Paderborn
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
 * License along with this library; if not, see <http://www.gnu.org/licenses/>.
 */

/*
   Modified for Unicorn Engine by Eric Poole <eric.poole@aptiv.com>, 2022
   Copyright 2022 Aptiv 
*/

#include "qemu/osdep.h"
#include "cpu.h"
#include "cpu-qom.h"
#include "exec/exec-all.h"

#include <uc_priv.h>

static inline void set_feature(CPUTriCoreState *env, int feature)
{
    env->features |= 1ULL << feature;
}

static void tricore_cpu_set_pc(CPUState *cs, vaddr value)
{
    TriCoreCPU *cpu = TRICORE_CPU(cs);
    CPUTriCoreState *env = &cpu->env;

    env->PC = value & ~(target_ulong)1;
}

static void tricore_cpu_synchronize_from_tb(CPUState *cs, TranslationBlock *tb)
{
    TriCoreCPU *cpu = TRICORE_CPU(cs);
    CPUTriCoreState *env = &cpu->env;

    env->PC = tb->pc;
}

static void tricore_cpu_reset(CPUState *dev)
{
    CPUState *s = CPU(dev);
    TriCoreCPU *cpu = TRICORE_CPU(s);
    TriCoreCPUClass *tcc = TRICORE_CPU_GET_CLASS(cpu);
    CPUTriCoreState *env = &cpu->env;

    tcc->parent_reset(dev);

    memset(env, 0, offsetof(CPUTriCoreState, end_reset_fields));

    cpu_state_reset(env);
}

static bool tricore_cpu_has_work(CPUState *cs)
{
    return true;
}

static void tricore_cpu_realizefn(CPUState *dev)
{
    CPUState *cs = CPU(dev);
    TriCoreCPU *cpu = TRICORE_CPU(dev);
    CPUTriCoreState *env = &cpu->env;

    cpu_exec_realizefn(cs);

    /* Some features automatically imply others */
    if (tricore_feature(env, TRICORE_FEATURE_161)) {
        set_feature(env, TRICORE_FEATURE_16);
    }

    if (tricore_feature(env, TRICORE_FEATURE_16)) {
        set_feature(env, TRICORE_FEATURE_131);
    }
    if (tricore_feature(env, TRICORE_FEATURE_131)) {
        set_feature(env, TRICORE_FEATURE_13);
    }
    cpu_reset(cs);
}


static void tricore_cpu_initfn(struct uc_struct *uc, CPUState *obj)
{
    TriCoreCPU *cpu = TRICORE_CPU(obj);
    CPUTriCoreState *env = &cpu->env;

    env->uc = uc;
    cpu_set_cpustate_pointers(cpu);
}

static void tc1796_initfn(CPUState *obj)
{
    TriCoreCPU *cpu = TRICORE_CPU(obj);

    set_feature(&cpu->env, TRICORE_FEATURE_13);
}

static void tc1797_initfn(CPUState *obj)
{
    TriCoreCPU *cpu = TRICORE_CPU(obj);

    set_feature(&cpu->env, TRICORE_FEATURE_131);
}

static void tc27x_initfn(CPUState *obj)
{
    TriCoreCPU *cpu = TRICORE_CPU(obj);

    set_feature(&cpu->env, TRICORE_FEATURE_161);
}

static void tricore_cpu_class_init(CPUClass *c)
{
    TriCoreCPUClass *mcc = TRICORE_CPU_CLASS(c);
    CPUClass *cc = CPU_CLASS(c);

    /* parent class is CPUClass, parent_reset() is cpu_common_reset(). */
    mcc->parent_reset = cc->reset;

    cc->reset = tricore_cpu_reset;
    cc->has_work = tricore_cpu_has_work;
    cc->set_pc = tricore_cpu_set_pc;

    cc->synchronize_from_tb = tricore_cpu_synchronize_from_tb;
    cc->get_phys_page_debug = tricore_cpu_get_phys_page_debug;

    cc->tlb_fill_cpu = tricore_cpu_tlb_fill;
    cc->tcg_initialize = tricore_tcg_init;
}

#define DEFINE_TRICORE_CPU_TYPE(cpu_model, initfn) \
    {                                              \
        .parent = TYPE_TRICORE_CPU,                \
        .initfn = initfn,                   \
        .name = TRICORE_CPU_TYPE_NAME(cpu_model),  \
    }

struct TriCoreCPUInfo {
    const char *name;
    void (*initfn)(CPUState *obj);
};

static struct TriCoreCPUInfo tricore_cpus_type_infos[] = {
    { "tc1796", tc1796_initfn },
    { "tc1797", tc1797_initfn },
    { "tc27x", tc27x_initfn },
};

TriCoreCPU *cpu_tricore_init(struct uc_struct *uc)
{
    TriCoreCPU *cpu;
    CPUState *cs;
    CPUClass *cc;

    cpu = calloc(1, sizeof(*cpu));
    if (cpu == NULL) {
        return NULL;
    }

    if (uc->cpu_model == INT_MAX) {
        uc->cpu_model = 2; // tc27x
    } else if (uc->cpu_model >= ARRAY_SIZE(tricore_cpus_type_infos)) {
        free(cpu);
        return NULL;
    }

    cs = (CPUState *)cpu;
    cc = (CPUClass *)&cpu->cc;
    cs->cc = cc;
    cs->uc = uc;
    uc->cpu = cs;

    cpu_class_init(uc, cc);

    tricore_cpu_class_init(cc);

    cpu_common_initfn(uc, cs);

    tricore_cpu_initfn(uc, cs);

    tricore_cpus_type_infos[uc->cpu_model].initfn(cs);

    tricore_cpu_realizefn(cs);

    // init address space
    cpu_address_space_init(cs, 0, cs->memory);

    qemu_init_vcpu(cs);

    return cpu;
}

