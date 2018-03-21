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
#include "qapi/error.h"
#include "hw/m68k/m68k.h"
#include "cpu.h"
#include "qemu-common.h"
#include "exec/exec-all.h"
#include "fpu/softfloat.h"

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
    floatx80 nan = floatx80_default_nan(NULL);
    int i;

    mcc->parent_reset(s);

    memset(env, 0, offsetof(CPUM68KState, end_reset_fields));
#ifdef CONFIG_SOFTMMU
    cpu_m68k_set_sr(env, SR_S | SR_I);
#else
    cpu_m68k_set_sr(env, 0);
#endif
    for (i = 0; i < 8; i++) {
        env->fregs[i].d = nan;
    }
    cpu_m68k_set_fpcr(env, 0);
    env->fpsr = 0;

    /* TODO: We should set PC from the interrupt vector.  */
    env->pc = 0;
}

/* CPU models */

static ObjectClass *m68k_cpu_class_by_name(struct uc_struct *uc, const char *cpu_model)
{
    ObjectClass *oc;
    char *typename;

    if (cpu_model == NULL) {
        return NULL;
    }

    typename = g_strdup_printf(M68K_CPU_TYPE_NAME("%s"), cpu_model);
    oc = object_class_by_name(uc, typename);
    g_free(typename);
    if (oc != NULL && (object_class_dynamic_cast(uc, oc, TYPE_M68K_CPU) == NULL ||
                       object_class_is_abstract(oc))) {
        return NULL;
    }
    return oc;
}

static void m5206_cpu_initfn(struct uc_struct *uc, Object *obj, void *opaque)
{
    M68kCPU *cpu = M68K_CPU(uc, obj);
    CPUM68KState *env = &cpu->env;

    m68k_set_feature(env, M68K_FEATURE_CF_ISA_A);
}

static void m68000_cpu_initfn(struct uc_struct *uc, Object *obj, void *opaque)
{
    M68kCPU *cpu = M68K_CPU(uc, obj);
    CPUM68KState *env = &cpu->env;

    m68k_set_feature(env, M68K_FEATURE_M68000);
    m68k_set_feature(env, M68K_FEATURE_USP);
    m68k_set_feature(env, M68K_FEATURE_WORD_INDEX);
    m68k_set_feature(env, M68K_FEATURE_MOVEP);
}

static void m68020_cpu_initfn(struct uc_struct *uc, Object *obj, void *opaque)
{
    M68kCPU *cpu = M68K_CPU(uc, obj);
    CPUM68KState *env = &cpu->env;

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
#define m68030_cpu_initfn m68020_cpu_initfn

static void m68040_cpu_initfn(struct uc_struct *uc, Object *obj, void *opaque)
{
    M68kCPU *cpu = M68K_CPU(uc, obj);
    CPUM68KState *env = &cpu->env;

    m68020_cpu_initfn(uc, obj, opaque);
    m68k_set_feature(env, M68K_FEATURE_M68040);
}

static void m68060_cpu_initfn(struct uc_struct *uc, Object *obj, void *opaque)
{
    M68kCPU *cpu = M68K_CPU(uc, obj);
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
}

static void m5208_cpu_initfn(struct uc_struct *uc, Object *obj, void *opaque)
{
    M68kCPU *cpu = M68K_CPU(uc, obj);
    CPUM68KState *env = &cpu->env;

    m68k_set_feature(env, M68K_FEATURE_CF_ISA_A);
    m68k_set_feature(env, M68K_FEATURE_CF_ISA_APLUSC);
    m68k_set_feature(env, M68K_FEATURE_BRAL);
    m68k_set_feature(env, M68K_FEATURE_CF_EMAC);
    m68k_set_feature(env, M68K_FEATURE_USP);
}

static void cfv4e_cpu_initfn(struct uc_struct *uc, Object *obj, void *opaque)
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

static void any_cpu_initfn(struct uc_struct *uc, Object *obj, void *opaque)
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

static int m68k_cpu_realizefn(struct uc_struct *uc, DeviceState *dev, Error **errp)
{
    CPUState *cs = CPU(dev);
    M68kCPUClass *mcc = M68K_CPU_GET_CLASS(uc, dev);

    cpu_reset(cs);
    qemu_init_vcpu(cs);

    mcc->parent_realize(cs->uc, dev, errp);

    return 0;
}

static void m68k_cpu_initfn(struct uc_struct *uc, Object *obj, void *opaque)
{
    CPUState *cs = CPU(obj);
    M68kCPU *cpu = M68K_CPU(uc, obj);
    CPUM68KState *env = &cpu->env;

    cs->env_ptr = env;
    cpu_exec_init(cs, &error_abort, opaque);
}

static void m68k_cpu_class_init(struct uc_struct *uc, ObjectClass *c, void *data)
{
    M68kCPUClass *mcc = M68K_CPU_CLASS(uc, c);
    CPUClass *cc = CPU_CLASS(uc, c);
    DeviceClass *dc = DEVICE_CLASS(uc, c);

    mcc->parent_realize = dc->realize;
    dc->realize = m68k_cpu_realizefn;

    mcc->parent_reset = cc->reset;
    cc->reset = m68k_cpu_reset;

    cc->class_by_name = m68k_cpu_class_by_name;
    cc->has_work = m68k_cpu_has_work;
    cc->do_interrupt = m68k_cpu_do_interrupt;
    cc->cpu_exec_interrupt = m68k_cpu_exec_interrupt;
    cc->set_pc = m68k_cpu_set_pc;
    cc->handle_mmu_fault = m68k_cpu_handle_mmu_fault;
#if defined(CONFIG_SOFTMMU)
    cc->do_unassigned_access = m68k_cpu_unassigned_access;
    cc->get_phys_page_debug = m68k_cpu_get_phys_page_debug;
#endif
    cc->tcg_initialize = m68k_tcg_init;
}

#define DEFINE_M68K_CPU_TYPE(cpu_model, initfn) \
    {                                           \
        M68K_CPU_TYPE_NAME(cpu_model),          \
        TYPE_M68K_CPU,                          \
                                                \
        0,                                      \
        0,                                      \
        NULL,                                   \
                                                \
        initfn,                                 \
    }

static const TypeInfo m68k_cpus_type_infos[] = {
    { /* base class should be registered first */
        TYPE_M68K_CPU,
        TYPE_CPU,

        sizeof(M68kCPUClass),
        sizeof(M68kCPU),
        NULL,

        m68k_cpu_initfn,
        NULL,
        NULL,

        NULL,

        m68k_cpu_class_init,
        NULL,
        NULL,

        true,
    },
    DEFINE_M68K_CPU_TYPE("m68000", m68000_cpu_initfn),
    DEFINE_M68K_CPU_TYPE("m68020", m68020_cpu_initfn),
    DEFINE_M68K_CPU_TYPE("m68030", m68030_cpu_initfn),
    DEFINE_M68K_CPU_TYPE("m68040", m68040_cpu_initfn),
    DEFINE_M68K_CPU_TYPE("m68060", m68060_cpu_initfn),
    DEFINE_M68K_CPU_TYPE("m5206", m5206_cpu_initfn),
    DEFINE_M68K_CPU_TYPE("m5208", m5208_cpu_initfn),
    DEFINE_M68K_CPU_TYPE("cfv4e", cfv4e_cpu_initfn),
    DEFINE_M68K_CPU_TYPE("any", any_cpu_initfn),
};

void m68k_cpu_register_types(void *opaque)
{
    type_register_static_array(opaque, m68k_cpus_type_infos, ARRAY_SIZE(m68k_cpus_type_infos));
}
