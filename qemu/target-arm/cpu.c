/*
 * QEMU ARM CPU
 *
 * Copyright (c) 2012 SUSE LINUX Products GmbH
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, see
 * <http://www.gnu.org/licenses/gpl-2.0.html>
 */
/* Modified for Unicorn Engine by Chen Huitao<chenhuitao@hfmrit.com>, 2020 */

#include "cpu.h"
#include "internals.h"
#include "qemu-common.h"
#include "sysemu/sysemu.h"

#include "uc_priv.h"

static void arm_cpu_set_pc(CPUState *cs, vaddr value)
{
    ARMCPU *cpu = ARM_CPU(NULL, cs);

    cpu->env.regs[15] = value;
}

static bool arm_cpu_has_work(CPUState *cs)
{
    ARMCPU *cpu = ARM_CPU(NULL, cs);

    return !cpu->powered_off
        && cs->interrupt_request &
        (CPU_INTERRUPT_FIQ | CPU_INTERRUPT_HARD
         | CPU_INTERRUPT_VFIQ | CPU_INTERRUPT_VIRQ
         | CPU_INTERRUPT_EXITTB);
}

static void cp_reg_reset(gpointer key, gpointer value, gpointer opaque)
{
    /* Reset a single ARMCPRegInfo register */
    ARMCPRegInfo *ri = value;
    ARMCPU *cpu = opaque;

    if (ri->type & ARM_CP_SPECIAL) {
        return;
    }

    if (ri->resetfn) {
        ri->resetfn(&cpu->env, ri);
        return;
    }

    /* A zero offset is never possible as it would be regs[0]
     * so we use it to indicate that reset is being handled elsewhere.
     * This is basically only used for fields in non-core coprocessors
     * (like the pxa2xx ones).
     */
    if (!ri->fieldoffset) {
        return;
    }

    if (cpreg_field_is_64bit(ri)) {
        CPREG_FIELD64(&cpu->env, ri) = ri->resetvalue;
    } else {
        CPREG_FIELD32(&cpu->env, ri) = ri->resetvalue;
    }
}

/* CPUClass::reset() */
static void arm_cpu_reset(CPUState *s)
{
    CPUARMState *env = s->env_ptr;
    ARMCPU *cpu = ARM_CPU(env->uc, s);
    ARMCPUClass *acc = ARM_CPU_GET_CLASS(env->uc, cpu);

    acc->parent_reset(s);

    memset(env, 0, offsetof(CPUARMState, features));
    g_hash_table_foreach(cpu->cp_regs, cp_reg_reset, cpu);
    env->vfp.xregs[ARM_VFP_FPSID] = cpu->reset_fpsid;
    env->vfp.xregs[ARM_VFP_MVFR0] = cpu->mvfr0;
    env->vfp.xregs[ARM_VFP_MVFR1] = cpu->mvfr1;
    env->vfp.xregs[ARM_VFP_MVFR2] = cpu->mvfr2;

    cpu->powered_off = cpu->start_powered_off;
    s->halted = cpu->start_powered_off;

    if (arm_feature(env, ARM_FEATURE_IWMMXT)) {
        env->iwmmxt.cregs[ARM_IWMMXT_wCID] = 0x69051000 | 'Q';
    }

    if (arm_feature(env, ARM_FEATURE_AARCH64)) {
        /* 64 bit CPUs always start in 64 bit mode */
        env->aarch64 = 1;
#if defined(CONFIG_USER_ONLY)
        env->pstate = PSTATE_MODE_EL0t;
        /* Userspace expects access to DC ZVA, CTL_EL0 and the cache ops */
        env->cp15.c1_sys |= SCTLR_UCT | SCTLR_UCI | SCTLR_DZE;
        /* and to the FP/Neon instructions */
        env->cp15.c1_coproc = deposit64(env->cp15.c1_coproc, 20, 2, 3);
#else
        env->pstate = PSTATE_MODE_EL1h;
        env->pc = cpu->rvbar;
#endif
    } else {
#if defined(CONFIG_USER_ONLY)
        /* Userspace expects access to cp10 and cp11 for FP/Neon */
        env->cp15.c1_coproc = deposit64(env->cp15.c1_coproc, 20, 4, 0xf);
#endif
    }

#if defined(CONFIG_USER_ONLY)
    env->uncached_cpsr = ARM_CPU_MODE_USR;
    /* For user mode we must enable access to coprocessors */
    env->vfp.xregs[ARM_VFP_FPEXC] = 1 << 30;
    if (arm_feature(env, ARM_FEATURE_IWMMXT)) {
        env->cp15.c15_cpar = 3;
    } else if (arm_feature(env, ARM_FEATURE_XSCALE)) {
        env->cp15.c15_cpar = 1;
    }
#else
    /* SVC mode with interrupts disabled.  */
    env->uncached_cpsr = ARM_CPU_MODE_SVC;
    env->daif = PSTATE_D | PSTATE_A | PSTATE_I | PSTATE_F;
    /* On ARMv7-M the CPSR_I is the value of the PRIMASK register, and is
     * clear at reset. Initial SP and PC are loaded from ROM.
     */
    if (IS_M(env)) {
        uint32_t initial_msp; /* Loaded from 0x0 */
        uint32_t initial_pc; /* Loaded from 0x4 */

        env->daif &= ~PSTATE_I;
        {
            /* Address zero not covered by a ROM blob, or the ROM blob
             * is in non-modifiable memory and this is a second reset after
             * it got copied into memory. In the latter case, rom_ptr
             * will return a NULL pointer and we should use ldl_phys instead.
             */
            initial_msp = ldl_phys(s->as, 0);
            initial_pc = ldl_phys(s->as, 4);
        }

        env->regs[13] = initial_msp & 0xFFFFFFFC;
        env->regs[15] = initial_pc & ~1;
        env->thumb = initial_pc & 1;
    }

    // Unicorn: force Thumb mode by setting of uc_open()
    env->thumb = env->uc->thumb;

    if (env->cp15.c1_sys & SCTLR_V) {
        env->regs[15] = 0xFFFF0000;
    }

    env->vfp.xregs[ARM_VFP_FPEXC] = 0;
#endif
    set_flush_to_zero(1, &env->vfp.standard_fp_status);
    set_flush_inputs_to_zero(1, &env->vfp.standard_fp_status);
    set_default_nan_mode(1, &env->vfp.standard_fp_status);
    set_float_detect_tininess(float_tininess_before_rounding,
                              &env->vfp.fp_status);
    set_float_detect_tininess(float_tininess_before_rounding,
                              &env->vfp.standard_fp_status);
    tlb_flush(s, 1);

    hw_breakpoint_update_all(cpu);
    hw_watchpoint_update_all(cpu);
}

bool arm_cpu_exec_interrupt(CPUState *cs, int interrupt_request)
{
    CPUClass *cc = CPU_GET_CLASS(cs->uc, cs);
    bool ret = false;

    if (interrupt_request & CPU_INTERRUPT_FIQ
        && arm_excp_unmasked(cs, EXCP_FIQ)) {
        cs->exception_index = EXCP_FIQ;
        cc->do_interrupt(cs);
        ret = true;
    }
    if (interrupt_request & CPU_INTERRUPT_HARD
        && arm_excp_unmasked(cs, EXCP_IRQ)) {
        cs->exception_index = EXCP_IRQ;
        cc->do_interrupt(cs);
        ret = true;
    }
    if (interrupt_request & CPU_INTERRUPT_VIRQ
        && arm_excp_unmasked(cs, EXCP_VIRQ)) {
        cs->exception_index = EXCP_VIRQ;
        cc->do_interrupt(cs);
        ret = true;
    }
    if (interrupt_request & CPU_INTERRUPT_VFIQ
        && arm_excp_unmasked(cs, EXCP_VFIQ)) {
        cs->exception_index = EXCP_VFIQ;
        cc->do_interrupt(cs);
        ret = true;
    }

    return ret;
}

#if !defined(CONFIG_USER_ONLY) || !defined(TARGET_AARCH64)
static bool arm_v7m_cpu_exec_interrupt(CPUState *cs, int interrupt_request)
{
    CPUARMState *env = cs->env_ptr;
    CPUClass *cc = CPU_GET_CLASS(env->uc, cs);
    bool ret = false;


    if (interrupt_request & CPU_INTERRUPT_FIQ
        && !(env->daif & PSTATE_F)) {
        cs->exception_index = EXCP_FIQ;
        cc->do_interrupt(cs);
        ret = true;
    }
    /* ARMv7-M interrupt return works by loading a magic value
     * into the PC.  On real hardware the load causes the
     * return to occur.  The qemu implementation performs the
     * jump normally, then does the exception return when the
     * CPU tries to execute code at the magic address.
     * This will cause the magic PC value to be pushed to
     * the stack if an interrupt occurred at the wrong time.
     * We avoid this by disabling interrupts when
     * pc contains a magic address.
     */
    if (interrupt_request & CPU_INTERRUPT_HARD
        && !(env->daif & PSTATE_I)
        && (env->regs[15] < 0xfffffff0)) {
        cs->exception_index = EXCP_IRQ;
        cc->do_interrupt(cs);
        ret = true;
    }
    return ret;
}
#endif

static inline void set_feature(CPUARMState *env, int feature)
{
    env->features |= 1ULL << feature;
}

void arm_cpu_initfn(struct uc_struct *uc, CPUState *obj, void *opaque)
{
    CPUState *cs = CPU(obj);
    ARMCPU *cpu = ARM_CPU(uc, obj);

    cs->env_ptr = &cpu->env;
    cpu_exec_init(&cpu->env, opaque);
    cpu->cp_regs = g_hash_table_new_full(g_int_hash, g_int_equal,
                                         g_free, g_free);

    /* DTB consumers generally don't in fact care what the 'compatible'
     * string is, so always provide some string and trust that a hypothetical
     * picky DTB consumer will also provide a helpful error message.
     */
    cpu->dtb_compatible = "qemu,unknown";
    cpu->psci_version = 1; /* By default assume PSCI v0.1 */
    cpu->kvm_target = QEMU_KVM_ARM_TARGET_NONE;

    if (tcg_enabled(uc)) {
        cpu->psci_version = 2; /* TCG implements PSCI 0.2 */
        arm_translate_init(uc);
    }
}

void arm_cpu_post_init(struct uc_struct *uc, CPUState *obj)
{
    ARMCPU *cpu = ARM_CPU(uc, obj);

    if (arm_feature(&cpu->env, ARM_FEATURE_CBAR) ||
        arm_feature(&cpu->env, ARM_FEATURE_CBAR_RO)) {
        //qdev_property_add_static(DEVICE(obj), &arm_cpu_reset_cbar_property,
        //                         &error_abort);
    }

    if (!arm_feature(&cpu->env, ARM_FEATURE_M)) {
        //qdev_property_add_static(DEVICE(obj), &arm_cpu_reset_hivecs_property,
        //                         &error_abort);
    }

    if (arm_feature(&cpu->env, ARM_FEATURE_AARCH64)) {
        //qdev_property_add_static(DEVICE(obj), &arm_cpu_rvbar_property,
        //                         &error_abort);
    }
}

int arm_cpu_realizefn(struct uc_struct *uc, CPUState *dev)
{
    CPUState *cs = CPU(dev);
    ARMCPU *cpu = ARM_CPU(uc, dev);
    CPUARMState *env = &cpu->env;

    /* Some features automatically imply others: */
    if (arm_feature(env, ARM_FEATURE_V8)) {
        set_feature(env, ARM_FEATURE_V7);
        set_feature(env, ARM_FEATURE_ARM_DIV);
        set_feature(env, ARM_FEATURE_LPAE);
    }
    if (arm_feature(env, ARM_FEATURE_V7)) {
        set_feature(env, ARM_FEATURE_VAPA);
        set_feature(env, ARM_FEATURE_THUMB2);
        set_feature(env, ARM_FEATURE_MPIDR);
        if (!arm_feature(env, ARM_FEATURE_M)) {
            set_feature(env, ARM_FEATURE_V6K);
        } else {
            set_feature(env, ARM_FEATURE_V6);
        }
    }
    if (arm_feature(env, ARM_FEATURE_V6K)) {
        set_feature(env, ARM_FEATURE_V6);
        set_feature(env, ARM_FEATURE_MVFR);
    }
    if (arm_feature(env, ARM_FEATURE_V6)) {
        set_feature(env, ARM_FEATURE_V5);
        if (!arm_feature(env, ARM_FEATURE_M)) {
            set_feature(env, ARM_FEATURE_AUXCR);
        }
    }
    if (arm_feature(env, ARM_FEATURE_V5)) {
        set_feature(env, ARM_FEATURE_V4T);
    }
    if (arm_feature(env, ARM_FEATURE_M)) {
        set_feature(env, ARM_FEATURE_THUMB_DIV);
    }
    if (arm_feature(env, ARM_FEATURE_ARM_DIV)) {
        set_feature(env, ARM_FEATURE_THUMB_DIV);
    }
    if (arm_feature(env, ARM_FEATURE_VFP4)) {
        set_feature(env, ARM_FEATURE_VFP3);
        set_feature(env, ARM_FEATURE_VFP_FP16);
    }
    if (arm_feature(env, ARM_FEATURE_VFP3)) {
        set_feature(env, ARM_FEATURE_VFP);
    }
    if (arm_feature(env, ARM_FEATURE_LPAE)) {
        set_feature(env, ARM_FEATURE_V7MP);
        set_feature(env, ARM_FEATURE_PXN);
    }
    if (arm_feature(env, ARM_FEATURE_CBAR_RO)) {
        set_feature(env, ARM_FEATURE_CBAR);
    }

    if (cpu->reset_hivecs) {
            cpu->reset_sctlr |= (1 << 13);
    }

    register_cp_regs_for_features(cpu);
    arm_cpu_register_gdb_regs_for_features(cpu);

    init_cpreg_list(cpu);

    qemu_init_vcpu(cs);
    cpu_reset(cs);

    return 0;
}

/* CPU models. These are not needed for the AArch64 linux-user build. */
#if !defined(CONFIG_USER_ONLY) || !defined(TARGET_AARCH64)

static void arm926_initfn(struct uc_struct *uc, CPUState *obj, void *opaque)
{
    ARMCPU *cpu = ARM_CPU(uc, obj);

    cpu->dtb_compatible = "arm,arm926";
    set_feature(&cpu->env, ARM_FEATURE_V5);
    set_feature(&cpu->env, ARM_FEATURE_VFP);
    set_feature(&cpu->env, ARM_FEATURE_DUMMY_C15_REGS);
    set_feature(&cpu->env, ARM_FEATURE_CACHE_TEST_CLEAN);
    cpu->midr = 0x41069265;
    cpu->reset_fpsid = 0x41011090;
    cpu->ctr = 0x1dd20d2;
    cpu->reset_sctlr = 0x00090078;
}

static void arm946_initfn(struct uc_struct *uc, CPUState *obj, void *opaque)
{
    ARMCPU *cpu = ARM_CPU(uc, obj);

    cpu->dtb_compatible = "arm,arm946";
    set_feature(&cpu->env, ARM_FEATURE_V5);
    set_feature(&cpu->env, ARM_FEATURE_MPU);
    set_feature(&cpu->env, ARM_FEATURE_DUMMY_C15_REGS);
    cpu->midr = 0x41059461;
    cpu->ctr = 0x0f004006;
    cpu->reset_sctlr = 0x00000078;
}

static void arm1026_initfn(struct uc_struct *uc, CPUState *obj, void *opaque)
{
    ARMCPU *cpu = ARM_CPU(uc, obj);

    cpu->dtb_compatible = "arm,arm1026";
    set_feature(&cpu->env, ARM_FEATURE_V5);
    set_feature(&cpu->env, ARM_FEATURE_VFP);
    set_feature(&cpu->env, ARM_FEATURE_AUXCR);
    set_feature(&cpu->env, ARM_FEATURE_DUMMY_C15_REGS);
    set_feature(&cpu->env, ARM_FEATURE_CACHE_TEST_CLEAN);
    cpu->midr = 0x4106a262;
    cpu->reset_fpsid = 0x410110a0;
    cpu->ctr = 0x1dd20d2;
    cpu->reset_sctlr = 0x00090078;
    cpu->reset_auxcr = 1;
    {
        /* The 1026 had an IFAR at c6,c0,0,1 rather than the ARMv6 c6,c0,0,2 */
        ARMCPRegInfo ifar = { 0 };
        ifar.name = "IFAR";
        ifar.cp = 15;
        ifar.crn = 6;
        ifar.crm = 0;
        ifar.opc1 = 0;
        ifar.opc2 = 1;
        ifar.access = PL1_RW;
        ifar.fieldoffset = offsetofhigh32(CPUARMState, cp15.far_el[1]);
        ifar.resetvalue = 0;
        define_one_arm_cp_reg(cpu, &ifar);
    }
}

static void arm1136_r2_initfn(struct uc_struct *uc, CPUState *obj, void *opaque)
{
    ARMCPU *cpu = ARM_CPU(uc, obj);
    /* What qemu calls "arm1136_r2" is actually the 1136 r0p2, ie an
     * older core than plain "arm1136". In particular this does not
     * have the v6K features.
     * These ID register values are correct for 1136 but may be wrong
     * for 1136_r2 (in particular r0p2 does not actually implement most
     * of the ID registers).
     */

    cpu->dtb_compatible = "arm,arm1136";
    set_feature(&cpu->env, ARM_FEATURE_V6);
    set_feature(&cpu->env, ARM_FEATURE_VFP);
    set_feature(&cpu->env, ARM_FEATURE_DUMMY_C15_REGS);
    set_feature(&cpu->env, ARM_FEATURE_CACHE_DIRTY_REG);
    set_feature(&cpu->env, ARM_FEATURE_CACHE_BLOCK_OPS);
    cpu->midr = 0x4107b362;
    cpu->reset_fpsid = 0x410120b4;
    cpu->mvfr0 = 0x11111111;
    cpu->mvfr1 = 0x00000000;
    cpu->ctr = 0x1dd20d2;
    cpu->reset_sctlr = 0x00050078;
    cpu->id_pfr0 = 0x111;
    cpu->id_pfr1 = 0x1;
    cpu->id_dfr0 = 0x2;
    cpu->id_afr0 = 0x3;
    cpu->id_mmfr0 = 0x01130003;
    cpu->id_mmfr1 = 0x10030302;
    cpu->id_mmfr2 = 0x01222110;
    cpu->id_isar0 = 0x00140011;
    cpu->id_isar1 = 0x12002111;
    cpu->id_isar2 = 0x11231111;
    cpu->id_isar3 = 0x01102131;
    cpu->id_isar4 = 0x141;
    cpu->reset_auxcr = 7;
}

static void arm1136_initfn(struct uc_struct *uc, CPUState *obj, void *opaque)
{
    ARMCPU *cpu = ARM_CPU(uc, obj);

    cpu->dtb_compatible = "arm,arm1136";
    set_feature(&cpu->env, ARM_FEATURE_V6K);
    set_feature(&cpu->env, ARM_FEATURE_V6);
    set_feature(&cpu->env, ARM_FEATURE_VFP);
    set_feature(&cpu->env, ARM_FEATURE_DUMMY_C15_REGS);
    set_feature(&cpu->env, ARM_FEATURE_CACHE_DIRTY_REG);
    set_feature(&cpu->env, ARM_FEATURE_CACHE_BLOCK_OPS);
    cpu->midr = 0x4117b363;
    cpu->reset_fpsid = 0x410120b4;
    cpu->mvfr0 = 0x11111111;
    cpu->mvfr1 = 0x00000000;
    cpu->ctr = 0x1dd20d2;
    cpu->reset_sctlr = 0x00050078;
    cpu->id_pfr0 = 0x111;
    cpu->id_pfr1 = 0x1;
    cpu->id_dfr0 = 0x2;
    cpu->id_afr0 = 0x3;
    cpu->id_mmfr0 = 0x01130003;
    cpu->id_mmfr1 = 0x10030302;
    cpu->id_mmfr2 = 0x01222110;
    cpu->id_isar0 = 0x00140011;
    cpu->id_isar1 = 0x12002111;
    cpu->id_isar2 = 0x11231111;
    cpu->id_isar3 = 0x01102131;
    cpu->id_isar4 = 0x141;
    cpu->reset_auxcr = 7;
}

static void arm1176_initfn(struct uc_struct *uc, CPUState *obj, void *opaque)
{
    ARMCPU *cpu = ARM_CPU(uc, obj);

    cpu->dtb_compatible = "arm,arm1176";
    set_feature(&cpu->env, ARM_FEATURE_V6K);
    set_feature(&cpu->env, ARM_FEATURE_VFP);
    set_feature(&cpu->env, ARM_FEATURE_VAPA);
    set_feature(&cpu->env, ARM_FEATURE_DUMMY_C15_REGS);
    set_feature(&cpu->env, ARM_FEATURE_CACHE_DIRTY_REG);
    set_feature(&cpu->env, ARM_FEATURE_CACHE_BLOCK_OPS);
    cpu->midr = 0x410fb767;
    cpu->reset_fpsid = 0x410120b5;
    cpu->mvfr0 = 0x11111111;
    cpu->mvfr1 = 0x00000000;
    cpu->ctr = 0x1dd20d2;
    cpu->reset_sctlr = 0x00050078;
    cpu->id_pfr0 = 0x111;
    cpu->id_pfr1 = 0x11;
    cpu->id_dfr0 = 0x33;
    cpu->id_afr0 = 0;
    cpu->id_mmfr0 = 0x01130003;
    cpu->id_mmfr1 = 0x10030302;
    cpu->id_mmfr2 = 0x01222100;
    cpu->id_isar0 = 0x0140011;
    cpu->id_isar1 = 0x12002111;
    cpu->id_isar2 = 0x11231121;
    cpu->id_isar3 = 0x01102131;
    cpu->id_isar4 = 0x01141;
    cpu->reset_auxcr = 7;
}

static void arm11mpcore_initfn(struct uc_struct *uc, CPUState *obj, void *opaque)
{
    ARMCPU *cpu = ARM_CPU(uc, obj);

    cpu->dtb_compatible = "arm,arm11mpcore";
    set_feature(&cpu->env, ARM_FEATURE_V6K);
    set_feature(&cpu->env, ARM_FEATURE_VFP);
    set_feature(&cpu->env, ARM_FEATURE_VAPA);
    set_feature(&cpu->env, ARM_FEATURE_MPIDR);
    set_feature(&cpu->env, ARM_FEATURE_DUMMY_C15_REGS);
    cpu->midr = 0x410fb022;
    cpu->reset_fpsid = 0x410120b4;
    cpu->mvfr0 = 0x11111111;
    cpu->mvfr1 = 0x00000000;
    cpu->ctr = 0x1d192992; /* 32K icache 32K dcache */
    cpu->id_pfr0 = 0x111;
    cpu->id_pfr1 = 0x1;
    cpu->id_dfr0 = 0;
    cpu->id_afr0 = 0x2;
    cpu->id_mmfr0 = 0x01100103;
    cpu->id_mmfr1 = 0x10020302;
    cpu->id_mmfr2 = 0x01222000;
    cpu->id_isar0 = 0x00100011;
    cpu->id_isar1 = 0x12002111;
    cpu->id_isar2 = 0x11221011;
    cpu->id_isar3 = 0x01102131;
    cpu->id_isar4 = 0x141;
    cpu->reset_auxcr = 1;
}

static void cortex_m3_initfn(struct uc_struct *uc, CPUState *obj, void *opaque)
{
    ARMCPU *cpu = ARM_CPU(uc, obj);
    set_feature(&cpu->env, ARM_FEATURE_V7);
    set_feature(&cpu->env, ARM_FEATURE_M);
    cpu->midr = 0x410fc231;
}

static void arm_v7m_class_init(struct uc_struct *uc, CPUClass *oc, void *data)
{
    CPUClass *cc = CPU_CLASS(uc, oc);

#ifndef CONFIG_USER_ONLY
    cc->do_interrupt = arm_v7m_cpu_do_interrupt;
#endif

    cc->cpu_exec_interrupt = arm_v7m_cpu_exec_interrupt;
}

static const ARMCPRegInfo cortexa8_cp_reginfo[] = {
    { "L2LOCKDOWN", 15,9,0, 0,1,0, 0,
      ARM_CP_CONST, PL1_RW,  NULL, 0, },
    { "L2AUXCR",    15,9,0, 0,1,2, 0,
      ARM_CP_CONST, PL1_RW,  NULL, 0, },
    REGINFO_SENTINEL
};

static void cortex_a8_initfn(struct uc_struct *uc, CPUState *obj, void *opaque)
{
    ARMCPU *cpu = ARM_CPU(uc, obj);

    cpu->dtb_compatible = "arm,cortex-a8";
    set_feature(&cpu->env, ARM_FEATURE_V7);
    set_feature(&cpu->env, ARM_FEATURE_VFP3);
    set_feature(&cpu->env, ARM_FEATURE_NEON);
    set_feature(&cpu->env, ARM_FEATURE_THUMB2EE);
    set_feature(&cpu->env, ARM_FEATURE_DUMMY_C15_REGS);
    cpu->midr = 0x410fc080;
    cpu->reset_fpsid = 0x410330c0;
    cpu->mvfr0 = 0x11110222;
    cpu->mvfr1 = 0x00011100;
    cpu->ctr = 0x82048004;
    cpu->reset_sctlr = 0x00c50078;
    cpu->id_pfr0 = 0x1031;
    cpu->id_pfr1 = 0x11;
    cpu->id_dfr0 = 0x400;
    cpu->id_afr0 = 0;
    cpu->id_mmfr0 = 0x31100003;
    cpu->id_mmfr1 = 0x20000000;
    cpu->id_mmfr2 = 0x01202000;
    cpu->id_mmfr3 = 0x11;
    cpu->id_isar0 = 0x00101111;
    cpu->id_isar1 = 0x12112111;
    cpu->id_isar2 = 0x21232031;
    cpu->id_isar3 = 0x11112131;
    cpu->id_isar4 = 0x00111142;
    cpu->dbgdidr = 0x15141000;
    cpu->clidr = (1 << 27) | (2 << 24) | 3;
    cpu->ccsidr[0] = 0xe007e01a; /* 16k L1 dcache. */
    cpu->ccsidr[1] = 0x2007e01a; /* 16k L1 icache. */
    cpu->ccsidr[2] = 0xf0000000; /* No L2 icache. */
    cpu->reset_auxcr = 2;
    define_arm_cp_regs(cpu, cortexa8_cp_reginfo);
}

static const ARMCPRegInfo cortexa9_cp_reginfo[] = {
    /* power_control should be set to maximum latency. Again,
     * default to 0 and set by private hook
     */
    { "A9_PWRCTL", 15,15,0, 0,0,0, 0,
      0,            PL1_RW, NULL, 0, offsetof(CPUARMState, cp15.c15_power_control) },
    { "A9_DIAG",   15,15,0, 0,0,1, 0,
      0,            PL1_RW, NULL, 0, offsetof(CPUARMState, cp15.c15_diagnostic) },
    { "A9_PWRDIAG",15,15,0, 0,0,2, 0,
      0,            PL1_RW, NULL, 0, offsetof(CPUARMState, cp15.c15_power_diagnostic) },
    { "NEONBUSY",  15,15,1, 0,0,0, 0,
      ARM_CP_CONST, PL1_RW, NULL, 0,  },
    /* TLB lockdown control */
    { "TLB_LOCKR", 15,15,4, 0,5,2, 0,
      ARM_CP_NOP,   PL1_W,  NULL, 0 },
    { "TLB_LOCKW", 15,15,4, 0,5,4, 0,
      ARM_CP_NOP,   PL1_W,  NULL, 0, },
    { "TLB_VA",    15,15,5, 0,5,2, 0,
      ARM_CP_CONST, PL1_RW, NULL, 0,  },
    { "TLB_PA",    15,15,6, 0,5,2, 0,
      ARM_CP_CONST, PL1_RW, NULL, 0 },
    { "TLB_ATTR",  15,15,7, 0,5,2, 0,
      ARM_CP_CONST, PL1_RW, NULL, 0,  },
    REGINFO_SENTINEL
};

static void cortex_a9_initfn(struct uc_struct *uc, CPUState *obj, void *opaque)
{
    ARMCPU *cpu = ARM_CPU(uc, obj);

    cpu->dtb_compatible = "arm,cortex-a9";
    set_feature(&cpu->env, ARM_FEATURE_V7);
    set_feature(&cpu->env, ARM_FEATURE_VFP3);
    set_feature(&cpu->env, ARM_FEATURE_VFP_FP16);
    set_feature(&cpu->env, ARM_FEATURE_NEON);
    set_feature(&cpu->env, ARM_FEATURE_THUMB2EE);
    /* Note that A9 supports the MP extensions even for
     * A9UP and single-core A9MP (which are both different
     * and valid configurations; we don't model A9UP).
     */
    set_feature(&cpu->env, ARM_FEATURE_V7MP);
    set_feature(&cpu->env, ARM_FEATURE_CBAR);
    cpu->midr = 0x410fc090;
    cpu->reset_fpsid = 0x41033090;
    cpu->mvfr0 = 0x11110222;
    cpu->mvfr1 = 0x01111111;
    cpu->ctr = 0x80038003;
    cpu->reset_sctlr = 0x00c50078;
    cpu->id_pfr0 = 0x1031;
    cpu->id_pfr1 = 0x11;
    cpu->id_dfr0 = 0x000;
    cpu->id_afr0 = 0;
    cpu->id_mmfr0 = 0x00100103;
    cpu->id_mmfr1 = 0x20000000;
    cpu->id_mmfr2 = 0x01230000;
    cpu->id_mmfr3 = 0x00002111;
    cpu->id_isar0 = 0x00101111;
    cpu->id_isar1 = 0x13112111;
    cpu->id_isar2 = 0x21232041;
    cpu->id_isar3 = 0x11112131;
    cpu->id_isar4 = 0x00111142;
    cpu->dbgdidr = 0x35141000;
    cpu->clidr = (1 << 27) | (1 << 24) | 3;
    cpu->ccsidr[0] = 0xe00fe019; /* 16k L1 dcache. */
    cpu->ccsidr[1] = 0x200fe019; /* 16k L1 icache. */
    define_arm_cp_regs(cpu, cortexa9_cp_reginfo);
}

#ifndef CONFIG_USER_ONLY
static uint64_t a15_l2ctlr_read(CPUARMState *env, const ARMCPRegInfo *ri)
{
    /* Linux wants the number of processors from here.
     * Might as well set the interrupt-controller bit too.
     */
    return ((smp_cpus - 1) << 24) | (1 << 23);
}
#endif

static const ARMCPRegInfo cortexa15_cp_reginfo[] = {
#ifndef CONFIG_USER_ONLY
    { "L2CTLR",  15,9,0, 0,1,2, 0,
      0,            PL1_RW, NULL, 0, 0,
	  NULL, a15_l2ctlr_read, arm_cp_write_ignore, },
#endif
    { "L2ECTLR", 15,9,0, 0,1,3, 0,
      ARM_CP_CONST, PL1_RW, NULL, 0 },
    REGINFO_SENTINEL
};

static void cortex_a15_initfn(struct uc_struct *uc, CPUState *obj, void *opaque)
{
    ARMCPU *cpu = ARM_CPU(uc, obj);

    cpu->dtb_compatible = "arm,cortex-a15";
    set_feature(&cpu->env, ARM_FEATURE_V7);
    set_feature(&cpu->env, ARM_FEATURE_VFP4);
    set_feature(&cpu->env, ARM_FEATURE_NEON);
    set_feature(&cpu->env, ARM_FEATURE_THUMB2EE);
    set_feature(&cpu->env, ARM_FEATURE_ARM_DIV);
    set_feature(&cpu->env, ARM_FEATURE_GENERIC_TIMER);
    set_feature(&cpu->env, ARM_FEATURE_DUMMY_C15_REGS);
    set_feature(&cpu->env, ARM_FEATURE_CBAR_RO);
    set_feature(&cpu->env, ARM_FEATURE_LPAE);
    cpu->kvm_target = QEMU_KVM_ARM_TARGET_CORTEX_A15;
    cpu->midr = 0x412fc0f1;
    cpu->reset_fpsid = 0x410430f0;
    cpu->mvfr0 = 0x10110222;
    cpu->mvfr1 = 0x11111111;
    cpu->ctr = 0x8444c004;
    cpu->reset_sctlr = 0x00c50078;
    cpu->id_pfr0 = 0x00001131;
    cpu->id_pfr1 = 0x00011011;
    cpu->id_dfr0 = 0x02010555;
    cpu->id_afr0 = 0x00000000;
    cpu->id_mmfr0 = 0x10201105;
    cpu->id_mmfr1 = 0x20000000;
    cpu->id_mmfr2 = 0x01240000;
    cpu->id_mmfr3 = 0x02102211;
    cpu->id_isar0 = 0x02101110;
    cpu->id_isar1 = 0x13112111;
    cpu->id_isar2 = 0x21232041;
    cpu->id_isar3 = 0x11112131;
    cpu->id_isar4 = 0x10011142;
    cpu->dbgdidr = 0x3515f021;
    cpu->clidr = 0x0a200023;
    cpu->ccsidr[0] = 0x701fe00a; /* 32K L1 dcache */
    cpu->ccsidr[1] = 0x201fe00a; /* 32K L1 icache */
    cpu->ccsidr[2] = 0x711fe07a; /* 4096K L2 unified cache */
    define_arm_cp_regs(cpu, cortexa15_cp_reginfo);
}

static void ti925t_initfn(struct uc_struct *uc, CPUState *obj, void *opaque)
{
    ARMCPU *cpu = ARM_CPU(uc, obj);
    set_feature(&cpu->env, ARM_FEATURE_V4T);
    set_feature(&cpu->env, ARM_FEATURE_OMAPCP);
    cpu->midr = ARM_CPUID_TI925T;
    cpu->ctr = 0x5109149;
    cpu->reset_sctlr = 0x00000070;
}

static void sa1100_initfn(struct uc_struct *uc, CPUState *obj, void *opaque)
{
    ARMCPU *cpu = ARM_CPU(uc, obj);

    cpu->dtb_compatible = "intel,sa1100";
    set_feature(&cpu->env, ARM_FEATURE_STRONGARM);
    set_feature(&cpu->env, ARM_FEATURE_DUMMY_C15_REGS);
    cpu->midr = 0x4401A11B;
    cpu->reset_sctlr = 0x00000070;
}

static void sa1110_initfn(struct uc_struct *uc, CPUState *obj, void *opaque)
{
    ARMCPU *cpu = ARM_CPU(uc, obj);
    set_feature(&cpu->env, ARM_FEATURE_STRONGARM);
    set_feature(&cpu->env, ARM_FEATURE_DUMMY_C15_REGS);
    cpu->midr = 0x6901B119;
    cpu->reset_sctlr = 0x00000070;
}

static void pxa250_initfn(struct uc_struct *uc, CPUState *obj, void *opaque)
{
    ARMCPU *cpu = ARM_CPU(uc, obj);

    cpu->dtb_compatible = "marvell,xscale";
    set_feature(&cpu->env, ARM_FEATURE_V5);
    set_feature(&cpu->env, ARM_FEATURE_XSCALE);
    cpu->midr = 0x69052100;
    cpu->ctr = 0xd172172;
    cpu->reset_sctlr = 0x00000078;
}

static void pxa255_initfn(struct uc_struct *uc, CPUState *obj, void *opaque)
{
    ARMCPU *cpu = ARM_CPU(uc, obj);

    cpu->dtb_compatible = "marvell,xscale";
    set_feature(&cpu->env, ARM_FEATURE_V5);
    set_feature(&cpu->env, ARM_FEATURE_XSCALE);
    cpu->midr = 0x69052d00;
    cpu->ctr = 0xd172172;
    cpu->reset_sctlr = 0x00000078;
}

static void pxa260_initfn(struct uc_struct *uc, CPUState *obj, void *opaque)
{
    ARMCPU *cpu = ARM_CPU(uc, obj);

    cpu->dtb_compatible = "marvell,xscale";
    set_feature(&cpu->env, ARM_FEATURE_V5);
    set_feature(&cpu->env, ARM_FEATURE_XSCALE);
    cpu->midr = 0x69052903;
    cpu->ctr = 0xd172172;
    cpu->reset_sctlr = 0x00000078;
}

static void pxa261_initfn(struct uc_struct *uc, CPUState *obj, void *opaque)
{
    ARMCPU *cpu = ARM_CPU(uc, obj);

    cpu->dtb_compatible = "marvell,xscale";
    set_feature(&cpu->env, ARM_FEATURE_V5);
    set_feature(&cpu->env, ARM_FEATURE_XSCALE);
    cpu->midr = 0x69052d05;
    cpu->ctr = 0xd172172;
    cpu->reset_sctlr = 0x00000078;
}

static void pxa262_initfn(struct uc_struct *uc, CPUState *obj, void *opaque)
{
    ARMCPU *cpu = ARM_CPU(uc, obj);

    cpu->dtb_compatible = "marvell,xscale";
    set_feature(&cpu->env, ARM_FEATURE_V5);
    set_feature(&cpu->env, ARM_FEATURE_XSCALE);
    cpu->midr = 0x69052d06;
    cpu->ctr = 0xd172172;
    cpu->reset_sctlr = 0x00000078;
}

static void pxa270a0_initfn(struct uc_struct *uc, CPUState *obj, void *opaque)
{
    ARMCPU *cpu = ARM_CPU(uc, obj);

    cpu->dtb_compatible = "marvell,xscale";
    set_feature(&cpu->env, ARM_FEATURE_V5);
    set_feature(&cpu->env, ARM_FEATURE_XSCALE);
    set_feature(&cpu->env, ARM_FEATURE_IWMMXT);
    cpu->midr = 0x69054110;
    cpu->ctr = 0xd172172;
    cpu->reset_sctlr = 0x00000078;
}

static void pxa270a1_initfn(struct uc_struct *uc, CPUState *obj, void *opaque)
{
    ARMCPU *cpu = ARM_CPU(uc, obj);

    cpu->dtb_compatible = "marvell,xscale";
    set_feature(&cpu->env, ARM_FEATURE_V5);
    set_feature(&cpu->env, ARM_FEATURE_XSCALE);
    set_feature(&cpu->env, ARM_FEATURE_IWMMXT);
    cpu->midr = 0x69054111;
    cpu->ctr = 0xd172172;
    cpu->reset_sctlr = 0x00000078;
}

static void pxa270b0_initfn(struct uc_struct *uc, CPUState *obj, void *opaque)
{
    ARMCPU *cpu = ARM_CPU(uc, obj);

    cpu->dtb_compatible = "marvell,xscale";
    set_feature(&cpu->env, ARM_FEATURE_V5);
    set_feature(&cpu->env, ARM_FEATURE_XSCALE);
    set_feature(&cpu->env, ARM_FEATURE_IWMMXT);
    cpu->midr = 0x69054112;
    cpu->ctr = 0xd172172;
    cpu->reset_sctlr = 0x00000078;
}

static void pxa270b1_initfn(struct uc_struct *uc, CPUState *obj, void *opaque)
{
    ARMCPU *cpu = ARM_CPU(uc, obj);

    cpu->dtb_compatible = "marvell,xscale";
    set_feature(&cpu->env, ARM_FEATURE_V5);
    set_feature(&cpu->env, ARM_FEATURE_XSCALE);
    set_feature(&cpu->env, ARM_FEATURE_IWMMXT);
    cpu->midr = 0x69054113;
    cpu->ctr = 0xd172172;
    cpu->reset_sctlr = 0x00000078;
}

static void pxa270c0_initfn(struct uc_struct *uc, CPUState *obj, void *opaque)
{
    ARMCPU *cpu = ARM_CPU(uc, obj);

    cpu->dtb_compatible = "marvell,xscale";
    set_feature(&cpu->env, ARM_FEATURE_V5);
    set_feature(&cpu->env, ARM_FEATURE_XSCALE);
    set_feature(&cpu->env, ARM_FEATURE_IWMMXT);
    cpu->midr = 0x69054114;
    cpu->ctr = 0xd172172;
    cpu->reset_sctlr = 0x00000078;
}

static void pxa270c5_initfn(struct uc_struct *uc, CPUState *obj, void *opaque)
{
    ARMCPU *cpu = ARM_CPU(uc, obj);

    cpu->dtb_compatible = "marvell,xscale";
    set_feature(&cpu->env, ARM_FEATURE_V5);
    set_feature(&cpu->env, ARM_FEATURE_XSCALE);
    set_feature(&cpu->env, ARM_FEATURE_IWMMXT);
    cpu->midr = 0x69054117;
    cpu->ctr = 0xd172172;
    cpu->reset_sctlr = 0x00000078;
}

#ifdef CONFIG_USER_ONLY
static void arm_any_initfn(struct uc_struct *uc, CPUState *obj, void *opaque)
{
    ARMCPU *cpu = ARM_CPU(uc, obj);
    set_feature(&cpu->env, ARM_FEATURE_V8);
    set_feature(&cpu->env, ARM_FEATURE_VFP4);
    set_feature(&cpu->env, ARM_FEATURE_NEON);
    set_feature(&cpu->env, ARM_FEATURE_THUMB2EE);
    set_feature(&cpu->env, ARM_FEATURE_V8_AES);
    set_feature(&cpu->env, ARM_FEATURE_V8_SHA1);
    set_feature(&cpu->env, ARM_FEATURE_V8_SHA256);
    set_feature(&cpu->env, ARM_FEATURE_V8_PMULL);
    set_feature(&cpu->env, ARM_FEATURE_CRC);
    cpu->midr = 0xffffffff;
}
#endif

#endif /* !defined(CONFIG_USER_ONLY) || !defined(TARGET_AARCH64) */

typedef struct ARMCPUInfo {
    const char *name;
    void (*initfn)(struct uc_struct *uc, CPUState *obj, void *opaque);
    void (*class_init)(struct uc_struct *uc, CPUClass *oc, void *data);
} ARMCPUInfo;

static const ARMCPUInfo arm_cpus[] = {
#if !defined(CONFIG_USER_ONLY) || !defined(TARGET_AARCH64)
    { "arm926",      arm926_initfn },
    { "arm946",      arm946_initfn },
    { "arm1026",     arm1026_initfn },
    /* What QEMU calls "arm1136-r2" is actually the 1136 r0p2, i.e. an
     * older core than plain "arm1136". In particular this does not
     * have the v6K features.
     */
    { "arm1136-r2",  arm1136_r2_initfn },
    { "arm1136",     arm1136_initfn },
    { "arm1176",     arm1176_initfn },
    { "arm11mpcore", arm11mpcore_initfn },
    { "cortex-m3",   cortex_m3_initfn, arm_v7m_class_init },
    { "cortex-a8",   cortex_a8_initfn },
    { "cortex-a9",   cortex_a9_initfn },
    { "cortex-a15",  cortex_a15_initfn },
    { "ti925t",      ti925t_initfn },
    { "sa1100",      sa1100_initfn },
    { "sa1110",      sa1110_initfn },
    { "pxa250",      pxa250_initfn },
    { "pxa255",      pxa255_initfn },
    { "pxa260",      pxa260_initfn },
    { "pxa261",      pxa261_initfn },
    { "pxa262",      pxa262_initfn },
    /* "pxa270" is an alias for "pxa270-a0" */
    { "pxa270",      pxa270a0_initfn },
    { "pxa270-a0",   pxa270a0_initfn },
    { "pxa270-a1",   pxa270a1_initfn },
    { "pxa270-b0",   pxa270b0_initfn },
    { "pxa270-b1",   pxa270b1_initfn },
    { "pxa270-c0",   pxa270c0_initfn },
    { "pxa270-c5",   pxa270c5_initfn },
#ifdef CONFIG_USER_ONLY
    { "any",         arm_any_initfn },
#endif
#endif
    { NULL }
};

void arm_cpu_class_init(struct uc_struct *uc, CPUClass *oc, void *data)
{
    ARMCPUClass *acc = ARM_CPU_CLASS(uc, oc);
    CPUClass *cc = CPU_CLASS(uc, acc);

    acc->parent_reset = cc->reset;
    cc->reset = arm_cpu_reset;

    cc->has_work = arm_cpu_has_work;
    cc->cpu_exec_interrupt = arm_cpu_exec_interrupt;
    cc->set_pc = arm_cpu_set_pc;
#ifdef CONFIG_USER_ONLY
    cc->handle_mmu_fault = arm_cpu_handle_mmu_fault;
#else
    cc->do_interrupt = arm_cpu_do_interrupt;
    cc->get_phys_page_debug = arm_cpu_get_phys_page_debug;
#endif
    cc->debug_excp_handler = arm_debug_excp_handler;
}

ARMCPU *cpu_arm_init(struct uc_struct *uc, const char *cpu_model)
{
    int i;
    ARMCPU *cpu;
    CPUState *cs;
    CPUClass *cc;

    if (uc->mode & UC_MODE_MCLASS) {
        cpu_model = "cortex-m3";
    } else if (uc->mode & UC_MODE_ARM926) {
        cpu_model = "arm926";
    } else if (uc->mode & UC_MODE_ARM946) {
        cpu_model = "arm946";
    } else if (uc->mode & UC_MODE_ARM1176) {
        cpu_model = "arm1176";
    } else {
        cpu_model = "cortex-a15";
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
    /* init ARMCPUClass */
    arm_cpu_class_init(uc, cc, NULL);
    /* init CPUState */
#ifdef NEED_CPU_INIT_REALIZE
    cpu_object_init(uc, cs);
#endif
    /* init ARMCPU */
    arm_cpu_initfn(uc, cs, uc);
    /* init ARM types */
    for (i = 0; i < ARRAY_SIZE(arm_cpus); i++) {
        if (strcmp(cpu_model, arm_cpus[i].name) == 0) {
            if (arm_cpus[i].class_init) {
                arm_cpus[i].class_init(uc, cc, uc);
            }
            if (arm_cpus[i].initfn) {
                arm_cpus[i].initfn(uc, cs, uc);
            }
            break;
        }
    }
    /* postinit ARMCPU */
    arm_cpu_post_init(uc, cs);
    /* realize ARMCPU */
    arm_cpu_realizefn(uc, cs);
    /* realize CPUState */
#ifdef NEED_CPU_INIT_REALIZE
    cpu_object_realize(uc, cs);
#endif

    return cpu;
}
