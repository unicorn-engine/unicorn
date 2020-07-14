/*
 * QEMU AArch64 CPU
 *
 * Copyright (c) 2013 Linaro Ltd
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
#include "qemu-common.h"
#include "sysemu/sysemu.h"

static inline void set_feature(CPUARMState *env, int feature)
{
    env->features |= 1ULL << feature;
}

#ifndef CONFIG_USER_ONLY
static uint64_t a57_l2ctlr_read(CPUARMState *env, const ARMCPRegInfo *ri)
{
    /* Number of processors is in [25:24]; otherwise we RAZ */
    return (smp_cpus - 1) << 24;
}
#endif

static const ARMCPRegInfo cortexa57_cp_reginfo[] = {
#ifndef CONFIG_USER_ONLY
    { "L2CTLR_EL1", 0,11,0, 3,1,2, ARM_CP_STATE_AA64,
      0, PL1_RW, NULL, 0, 0,
      NULL, a57_l2ctlr_read, arm_cp_write_ignore, },
    { "L2CTLR", 15,9,0, 0,1,2, 0,
      0, PL1_RW, NULL, 0, 0,
      NULL, a57_l2ctlr_read, arm_cp_write_ignore, },
#endif
    { "L2ECTLR_EL1", 0,11,0, 3,1,3, ARM_CP_STATE_AA64,
      ARM_CP_CONST, PL1_RW, NULL, 0, },
    { "L2ECTLR", 15,9,0, 0,1,3, 0,
      ARM_CP_CONST, PL1_RW, NULL, 0, },
    { "L2ACTLR", 0,15,0, 3,1,0, ARM_CP_STATE_BOTH,
      ARM_CP_CONST, PL1_RW, NULL, 0 },
    { "CPUACTLR_EL1", 0,15,2, 3,1,0, ARM_CP_STATE_AA64,
      ARM_CP_CONST, PL1_RW, NULL, 0 },
    { "CPUACTLR", 15,0,15, 0,0,0, 0,
      ARM_CP_CONST | ARM_CP_64BIT, PL1_RW, NULL, 0, },
    { "CPUECTLR_EL1", 0,15,2, 3,1,1, ARM_CP_STATE_AA64,
      ARM_CP_CONST, PL1_RW, NULL, 0, },
    { "CPUECTLR", 15,0,15, 0,1,0, 0,
      ARM_CP_CONST | ARM_CP_64BIT, PL1_RW, NULL, 0, },
    { "CPUMERRSR_EL1", 0,15,2, 3,1,2, ARM_CP_STATE_AA64,
      ARM_CP_CONST, PL1_RW, NULL, 0 },
    { "CPUMERRSR", 15,0,15, 0,2,0, 0,
      ARM_CP_CONST | ARM_CP_64BIT, PL1_RW, NULL, 0 },
    { "L2MERRSR_EL1", 0,15,2, 3,1,3, ARM_CP_STATE_AA64,
      ARM_CP_CONST, PL1_RW, NULL, 0 },
    { "L2MERRSR", 15,0,15, 0,3,0, 0,
      ARM_CP_CONST | ARM_CP_64BIT, PL1_RW, NULL, 0 },
    REGINFO_SENTINEL
};

static void aarch64_a57_initfn(struct uc_struct *uc, CPUState *obj, void *opaque)
{
    ARMCPU *cpu = ARM_CPU(uc, obj);

    set_feature(&cpu->env, ARM_FEATURE_V8);
    set_feature(&cpu->env, ARM_FEATURE_VFP4);
    set_feature(&cpu->env, ARM_FEATURE_NEON);
    set_feature(&cpu->env, ARM_FEATURE_GENERIC_TIMER);
    set_feature(&cpu->env, ARM_FEATURE_AARCH64);
    set_feature(&cpu->env, ARM_FEATURE_CBAR_RO);
    set_feature(&cpu->env, ARM_FEATURE_V8_AES);
    set_feature(&cpu->env, ARM_FEATURE_V8_SHA1);
    set_feature(&cpu->env, ARM_FEATURE_V8_SHA256);
    set_feature(&cpu->env, ARM_FEATURE_V8_PMULL);
    set_feature(&cpu->env, ARM_FEATURE_CRC);
    cpu->kvm_target = QEMU_KVM_ARM_TARGET_CORTEX_A57;
    cpu->midr = 0x411fd070;
    cpu->reset_fpsid = 0x41034070;
    cpu->mvfr0 = 0x10110222;
    cpu->mvfr1 = 0x12111111;
    cpu->mvfr2 = 0x00000043;
    cpu->ctr = 0x8444c004;
    cpu->reset_sctlr = 0x00c50838;
    cpu->id_pfr0 = 0x00000131;
    cpu->id_pfr1 = 0x00011011;
    cpu->id_dfr0 = 0x03010066;
    cpu->id_afr0 = 0x00000000;
    cpu->id_mmfr0 = 0x10101105;
    cpu->id_mmfr1 = 0x40000000;
    cpu->id_mmfr2 = 0x01260000;
    cpu->id_mmfr3 = 0x02102211;
    cpu->id_isar0 = 0x02101110;
    cpu->id_isar1 = 0x13112111;
    cpu->id_isar2 = 0x21232042;
    cpu->id_isar3 = 0x01112131;
    cpu->id_isar4 = 0x00011142;
    cpu->id_isar5 = 0x00011121;
    cpu->id_aa64pfr0 = 0x00002222;
    cpu->id_aa64dfr0 = 0x10305106;
    cpu->id_aa64isar0 = 0x00011120;
    cpu->id_aa64mmfr0 = 0x00001124;
    cpu->dbgdidr = 0x3516d000;
    cpu->clidr = 0x0a200023;
    cpu->ccsidr[0] = 0x701fe00a; /* 32KB L1 dcache */
    cpu->ccsidr[1] = 0x201fe012; /* 48KB L1 icache */
    cpu->ccsidr[2] = 0x70ffe07a; /* 2048KB L2 cache */
    cpu->dcz_blocksize = 4; /* 64 bytes */
    define_arm_cp_regs(cpu, cortexa57_cp_reginfo);
}

#ifdef CONFIG_USER_ONLY
static void aarch64_any_initfn(struct uc_struct *uc, CPUState *obj, void *opaque)
{
    ARMCPU *cpu = ARM_CPU(uc, obj);

    set_feature(&cpu->env, ARM_FEATURE_V8);
    set_feature(&cpu->env, ARM_FEATURE_VFP4);
    set_feature(&cpu->env, ARM_FEATURE_NEON);
    set_feature(&cpu->env, ARM_FEATURE_AARCH64);
    set_feature(&cpu->env, ARM_FEATURE_V8_AES);
    set_feature(&cpu->env, ARM_FEATURE_V8_SHA1);
    set_feature(&cpu->env, ARM_FEATURE_V8_SHA256);
    set_feature(&cpu->env, ARM_FEATURE_V8_PMULL);
    set_feature(&cpu->env, ARM_FEATURE_CRC);
    cpu->ctr = 0x80038003; /* 32 byte I and D cacheline size, VIPT icache */
    cpu->dcz_blocksize = 7; /*  512 bytes */
}
#endif

typedef struct ARMCPUInfo {
    const char *name;
    void (*initfn)(struct uc_struct *uc, CPUState *obj, void *opaque);
    void (*class_init)(struct uc_struct *uc, CPUClass *oc, void *data);
} ARMCPUInfo;

static const ARMCPUInfo aarch64_cpus[] = {
    { "cortex-a57",  aarch64_a57_initfn },
#ifdef CONFIG_USER_ONLY
    { "any",         aarch64_any_initfn },
#endif
};

static void aarch64_cpu_initfn(struct uc_struct *uc, CPUState *obj, void *opaque)
{
}

static void aarch64_cpu_set_pc(CPUState *cs, vaddr value)
{
    //CPUARMState *env = cs->env_ptr;
    ARMCPU *cpu = ARM_CPU(NULL, cs);
    /* It's OK to look at env for the current mode here, because it's
     * never possible for an AArch64 TB to chain to an AArch32 TB.
     * (Otherwise we would need to use synchronize_from_tb instead.)
     */
    if (is_a64(&cpu->env)) {
        cpu->env.pc = value;
    } else {
        cpu->env.regs[15] = value;
    }
}

static void aarch64_cpu_class_init(struct uc_struct *uc, CPUClass *oc, void *data)
{
    CPUClass *cc = CPU_CLASS(uc, oc);

#if !defined(CONFIG_USER_ONLY)
    cc->do_interrupt = aarch64_cpu_do_interrupt;
#endif
    cc->cpu_exec_interrupt = arm_cpu_exec_interrupt;
    cc->set_pc = aarch64_cpu_set_pc;
}

void arm_cpu_class_init(struct uc_struct *uc, CPUClass *oc, void *data);
void arm_cpu_initfn(struct uc_struct *uc, CPUState *obj, void *opaque);
void arm_cpu_post_init(struct uc_struct *uc, CPUState *obj);
int arm_cpu_realizefn(struct uc_struct *uc, CPUState *dev);

#ifdef TARGET_WORDS_BIGENDIAN
ARMCPU *cpu_aarch64eb_init(struct uc_struct *uc, const char *cpu_model)
#else
ARMCPU *cpu_aarch64_init(struct uc_struct *uc, const char *cpu_model)
#endif
{
    int i;
    ARMCPU *cpu;
    CPUState *cs;
    CPUClass *cc;

    if (cpu_model == NULL) {
        cpu_model = "cortex-a57";
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
    /* init Aarch64CPUClass */
    aarch64_cpu_class_init(uc, cc, NULL);
    /* init CPUState */
#ifdef NEED_CPU_INIT_REALIZE
    cpu_object_init(uc, cs);
#endif
    /* init ARMCPU */
    arm_cpu_initfn(uc, cs, uc);
    /* init Aarch64CPU */
    aarch64_cpu_initfn(uc, cs, uc);
    /* init Aarch64 types */
    for (i = 0; i < ARRAY_SIZE(aarch64_cpus); i++) {
        if (strcmp(cpu_model, aarch64_cpus[i].name) == 0) {
            if (aarch64_cpus[i].class_init) {
                aarch64_cpus[i].class_init(uc, cc, uc);
            }
            if (aarch64_cpus[i].initfn) {
                aarch64_cpus[i].initfn(uc, cs, uc);
            }
            break;
        }
    }
    /* postinit ARMCPU, do nothing. */
    arm_cpu_post_init(uc, cs);
    /* realize ARMCPU */
    arm_cpu_realizefn(uc, cs);
    /* realize CPUState */
#ifdef NEED_CPU_INIT_REALIZE
    cpu_object_realize(uc, cs);
#endif

    return cpu;
}
