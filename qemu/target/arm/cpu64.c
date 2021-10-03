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

#include "qemu/osdep.h"
#include "cpu.h"
#include <exec/exec-all.h>

void arm_cpu_realizefn(struct uc_struct *uc, CPUState *dev);
void arm_cpu_class_init(struct uc_struct *uc, CPUClass *oc);
void arm_cpu_post_init(CPUState *obj);
void arm_cpu_initfn(struct uc_struct *uc, CPUState *obj);
ARMCPU *cpu_arm_init(struct uc_struct *uc);


static inline void set_feature(CPUARMState *env, int feature)
{
    env->features |= 1ULL << feature;
}

static void aarch64_a57_initfn(struct uc_struct *uc, CPUState *obj)
{
    ARMCPU *cpu = ARM_CPU(obj);

    set_feature(&cpu->env, ARM_FEATURE_V8);
    set_feature(&cpu->env, ARM_FEATURE_NEON);
    set_feature(&cpu->env, ARM_FEATURE_GENERIC_TIMER);
    set_feature(&cpu->env, ARM_FEATURE_AARCH64);
    set_feature(&cpu->env, ARM_FEATURE_CBAR_RO);
    set_feature(&cpu->env, ARM_FEATURE_EL2);
    set_feature(&cpu->env, ARM_FEATURE_EL3);
    set_feature(&cpu->env, ARM_FEATURE_PMU);
    cpu->midr = 0x411fd070;
    cpu->revidr = 0x00000000;
    cpu->reset_fpsid = 0x41034070;
    cpu->isar.mvfr0 = 0x10110222;
    cpu->isar.mvfr1 = 0x12111111;
    cpu->isar.mvfr2 = 0x00000043;
    cpu->ctr = 0x8444c004;
    cpu->reset_sctlr = 0x00c50838;
    cpu->id_pfr0 = 0x00000131;
    cpu->id_pfr1 = 0x00011011;
    cpu->isar.id_dfr0 = 0x03010066;
    cpu->id_afr0 = 0x00000000;
    cpu->isar.id_mmfr0 = 0x10101105;
    cpu->isar.id_mmfr1 = 0x40000000;
    cpu->isar.id_mmfr2 = 0x01260000;
    cpu->isar.id_mmfr3 = 0x02102211;
    cpu->isar.id_isar0 = 0x02101110;
    cpu->isar.id_isar1 = 0x13112111;
    cpu->isar.id_isar2 = 0x21232042;
    cpu->isar.id_isar3 = 0x01112131;
    cpu->isar.id_isar4 = 0x00011142;
    cpu->isar.id_isar5 = 0x00011121;
    cpu->isar.id_isar6 = 0;
    cpu->isar.id_aa64pfr0 = 0x00002222;
    cpu->isar.id_aa64dfr0 = 0x10305106;
    cpu->isar.id_aa64isar0 = 0x00011120;
    cpu->isar.id_aa64mmfr0 = 0x00001124;
    cpu->isar.dbgdidr = 0x3516d000;
    cpu->clidr = 0x0a200023;
    cpu->ccsidr[0] = 0x701fe00a; /* 32KB L1 dcache */
    cpu->ccsidr[1] = 0x201fe012; /* 48KB L1 icache */
    cpu->ccsidr[2] = 0x70ffe07a; /* 2048KB L2 cache */
    cpu->dcz_blocksize = 4; /* 64 bytes */
    cpu->gic_num_lrs = 4;
    cpu->gic_vpribits = 5;
    cpu->gic_vprebits = 5;
}

static void aarch64_a53_initfn(struct uc_struct *uc, CPUState *obj)
{
    ARMCPU *cpu = ARM_CPU(obj);

    set_feature(&cpu->env, ARM_FEATURE_V8);
    set_feature(&cpu->env, ARM_FEATURE_NEON);
    set_feature(&cpu->env, ARM_FEATURE_GENERIC_TIMER);
    set_feature(&cpu->env, ARM_FEATURE_AARCH64);
    set_feature(&cpu->env, ARM_FEATURE_CBAR_RO);
    set_feature(&cpu->env, ARM_FEATURE_EL2);
    set_feature(&cpu->env, ARM_FEATURE_EL3);
    set_feature(&cpu->env, ARM_FEATURE_PMU);
    cpu->midr = 0x410fd034;
    cpu->revidr = 0x00000000;
    cpu->reset_fpsid = 0x41034070;
    cpu->isar.mvfr0 = 0x10110222;
    cpu->isar.mvfr1 = 0x12111111;
    cpu->isar.mvfr2 = 0x00000043;
    cpu->ctr = 0x84448004; /* L1Ip = VIPT */
    cpu->reset_sctlr = 0x00c50838;
    cpu->id_pfr0 = 0x00000131;
    cpu->id_pfr1 = 0x00011011;
    cpu->isar.id_dfr0 = 0x03010066;
    cpu->id_afr0 = 0x00000000;
    cpu->isar.id_mmfr0 = 0x10101105;
    cpu->isar.id_mmfr1 = 0x40000000;
    cpu->isar.id_mmfr2 = 0x01260000;
    cpu->isar.id_mmfr3 = 0x02102211;
    cpu->isar.id_isar0 = 0x02101110;
    cpu->isar.id_isar1 = 0x13112111;
    cpu->isar.id_isar2 = 0x21232042;
    cpu->isar.id_isar3 = 0x01112131;
    cpu->isar.id_isar4 = 0x00011142;
    cpu->isar.id_isar5 = 0x00011121;
    cpu->isar.id_isar6 = 0;
    cpu->isar.id_aa64pfr0 = 0x00002222;
    cpu->isar.id_aa64dfr0 = 0x10305106;
    cpu->isar.id_aa64isar0 = 0x00011120;
    cpu->isar.id_aa64mmfr0 = 0x00001122; /* 40 bit physical addr */
    cpu->isar.dbgdidr = 0x3516d000;
    cpu->clidr = 0x0a200023;
    cpu->ccsidr[0] = 0x700fe01a; /* 32KB L1 dcache */
    cpu->ccsidr[1] = 0x201fe00a; /* 32KB L1 icache */
    cpu->ccsidr[2] = 0x707fe07a; /* 1024KB L2 cache */
    cpu->dcz_blocksize = 4; /* 64 bytes */
    cpu->gic_num_lrs = 4;
    cpu->gic_vpribits = 5;
    cpu->gic_vprebits = 5;
}

static void aarch64_a72_initfn(struct uc_struct *uc, CPUState *obj)
{
    ARMCPU *cpu = ARM_CPU(obj);

    set_feature(&cpu->env, ARM_FEATURE_V8);
    set_feature(&cpu->env, ARM_FEATURE_NEON);
    set_feature(&cpu->env, ARM_FEATURE_GENERIC_TIMER);
    set_feature(&cpu->env, ARM_FEATURE_AARCH64);
    set_feature(&cpu->env, ARM_FEATURE_CBAR_RO);
    set_feature(&cpu->env, ARM_FEATURE_EL2);
    set_feature(&cpu->env, ARM_FEATURE_EL3);
    set_feature(&cpu->env, ARM_FEATURE_PMU);
    cpu->midr = 0x410fd083;
    cpu->revidr = 0x00000000;
    cpu->reset_fpsid = 0x41034080;
    cpu->isar.mvfr0 = 0x10110222;
    cpu->isar.mvfr1 = 0x12111111;
    cpu->isar.mvfr2 = 0x00000043;
    cpu->ctr = 0x8444c004;
    cpu->reset_sctlr = 0x00c50838;
    cpu->id_pfr0 = 0x00000131;
    cpu->id_pfr1 = 0x00011011;
    cpu->isar.id_dfr0 = 0x03010066;
    cpu->id_afr0 = 0x00000000;
    cpu->isar.id_mmfr0 = 0x10201105;
    cpu->isar.id_mmfr1 = 0x40000000;
    cpu->isar.id_mmfr2 = 0x01260000;
    cpu->isar.id_mmfr3 = 0x02102211;
    cpu->isar.id_isar0 = 0x02101110;
    cpu->isar.id_isar1 = 0x13112111;
    cpu->isar.id_isar2 = 0x21232042;
    cpu->isar.id_isar3 = 0x01112131;
    cpu->isar.id_isar4 = 0x00011142;
    cpu->isar.id_isar5 = 0x00011121;
    cpu->isar.id_aa64pfr0 = 0x00002222;
    cpu->isar.id_aa64dfr0 = 0x10305106;
    cpu->isar.id_aa64isar0 = 0x00011120;
    cpu->isar.id_aa64mmfr0 = 0x00001124;
    cpu->isar.dbgdidr = 0x3516d000;
    cpu->clidr = 0x0a200023;
    cpu->ccsidr[0] = 0x701fe00a; /* 32KB L1 dcache */
    cpu->ccsidr[1] = 0x201fe012; /* 48KB L1 icache */
    cpu->ccsidr[2] = 0x707fe07a; /* 1MB L2 cache */
    cpu->dcz_blocksize = 4; /* 64 bytes */
    cpu->gic_num_lrs = 4;
    cpu->gic_vpribits = 5;
    cpu->gic_vprebits = 5;
}

/* -cpu max: if KVM is enabled, like -cpu host (best possible with this host);
 * otherwise, a CPU with as many features enabled as our emulation supports.
 * The version of '-cpu max' for qemu-system-arm is defined in cpu.c;
 * this only needs to handle 64 bits.
 */
static void aarch64_max_initfn(struct uc_struct *uc, CPUState *obj)
{

    uint64_t t;
    uint32_t u;
    ARMCPU *cpu = ARM_CPU(obj);

    aarch64_a57_initfn(uc, obj);

    /*
     * Reset MIDR so the guest doesn't mistake our 'max' CPU type for a real
     * one and try to apply errata workarounds or use impdef features we
     * don't provide.
     * An IMPLEMENTER field of 0 means "reserved for software use";
     * ARCHITECTURE must be 0xf indicating "v7 or later, check ID registers
     * to see which features are present";
     * the VARIANT, PARTNUM and REVISION fields are all implementation
     * defined and we choose to define PARTNUM just in case guest
     * code needs to distinguish this QEMU CPU from other software
     * implementations, though this shouldn't be needed.
     */
    FIELD_DP64(0, MIDR_EL1, IMPLEMENTER, 0, t);
    FIELD_DP64(t, MIDR_EL1, ARCHITECTURE, 0xf ,t);
    FIELD_DP64(t, MIDR_EL1, PARTNUM, 'Q', t);
    FIELD_DP64(t, MIDR_EL1, VARIANT, 0, t);
    FIELD_DP64(t, MIDR_EL1, REVISION, 0, t);
    cpu->midr = t;

    t = cpu->isar.id_aa64isar0;
    FIELD_DP64(t, ID_AA64ISAR0, AES, 2, t); /* AES + PMULL */
    FIELD_DP64(t, ID_AA64ISAR0, SHA1, 1, t);
    FIELD_DP64(t, ID_AA64ISAR0, SHA2, 2, t); /* SHA512 */
    FIELD_DP64(t, ID_AA64ISAR0, CRC32, 1, t);
    FIELD_DP64(t, ID_AA64ISAR0, ATOMIC, 2, t);
    FIELD_DP64(t, ID_AA64ISAR0, RDM, 1, t);
    FIELD_DP64(t, ID_AA64ISAR0, SHA3, 1, t);
    FIELD_DP64(t, ID_AA64ISAR0, SM3, 1, t);
    FIELD_DP64(t, ID_AA64ISAR0, SM4, 1, t);
    FIELD_DP64(t, ID_AA64ISAR0, DP, 1, t);
    FIELD_DP64(t, ID_AA64ISAR0, FHM, 1, t);
    FIELD_DP64(t, ID_AA64ISAR0, TS, 2, t); /* v8.5-CondM */
    FIELD_DP64(t, ID_AA64ISAR0, RNDR, 1, t);
    cpu->isar.id_aa64isar0 = t;

    t = cpu->isar.id_aa64isar1;
    FIELD_DP64(t, ID_AA64ISAR1, DPB, 2, t);
    FIELD_DP64(t, ID_AA64ISAR1, JSCVT, 1, t);
    FIELD_DP64(t, ID_AA64ISAR1, FCMA, 1, t);
    FIELD_DP64(t, ID_AA64ISAR1, APA, 1, t); /* PAuth, architected only */
    FIELD_DP64(t, ID_AA64ISAR1, API, 0, t);
    FIELD_DP64(t, ID_AA64ISAR1, GPA, 1, t);
    FIELD_DP64(t, ID_AA64ISAR1, GPI, 0, t);
    FIELD_DP64(t, ID_AA64ISAR1, SB, 1, t);
    FIELD_DP64(t, ID_AA64ISAR1, SPECRES, 1, t);
    FIELD_DP64(t, ID_AA64ISAR1, FRINTTS, 1, t);
    FIELD_DP64(t, ID_AA64ISAR1, LRCPC, 2, t); /* ARMv8.4-RCPC */
    cpu->isar.id_aa64isar1 = t;

    t = cpu->isar.id_aa64pfr0;
    FIELD_DP64(t, ID_AA64PFR0, SVE, 1, t);
    FIELD_DP64(t, ID_AA64PFR0, FP, 1, t);
    FIELD_DP64(t, ID_AA64PFR0, ADVSIMD, 1, t);
    cpu->isar.id_aa64pfr0 = t;

    t = cpu->isar.id_aa64pfr1;
    FIELD_DP64(t, ID_AA64PFR1, BT, 1, t);
    cpu->isar.id_aa64pfr1 = t;

    t = cpu->isar.id_aa64mmfr1;
    FIELD_DP64(t, ID_AA64MMFR1, HPDS, 1, t); /* HPD */
    FIELD_DP64(t, ID_AA64MMFR1, LO, 1, t);
    FIELD_DP64(t, ID_AA64MMFR1, VH, 1, t);
    FIELD_DP64(t, ID_AA64MMFR1, PAN, 2, t); /* ATS1E1 */
    FIELD_DP64(t, ID_AA64MMFR1, VMIDBITS, 2, t); /* VMID16 */
    cpu->isar.id_aa64mmfr1 = t;

    t = cpu->isar.id_aa64mmfr2;
    FIELD_DP64(t, ID_AA64MMFR2, UAO, 1, t);
    FIELD_DP64(t, ID_AA64MMFR2, CNP, 1, t); /* TTCNP */
    cpu->isar.id_aa64mmfr2 = t;

    /* Replicate the same data to the 32-bit id registers.  */
    u = cpu->isar.id_isar5;
    FIELD_DP32(u, ID_ISAR5, AES, 2, u); /* AES + PMULL */
    FIELD_DP32(u, ID_ISAR5, SHA1, 1, u);
    FIELD_DP32(u, ID_ISAR5, SHA2, 1, u);
    FIELD_DP32(u, ID_ISAR5, CRC32, 1, u);
    FIELD_DP32(u, ID_ISAR5, RDM, 1, u);
    FIELD_DP32(u, ID_ISAR5, VCMA, 1, u);
    cpu->isar.id_isar5 = u;

    u = cpu->isar.id_isar6;
    FIELD_DP32(u, ID_ISAR6, JSCVT, 1, u);
    FIELD_DP32(u, ID_ISAR6, DP, 1, u);
    FIELD_DP32(u, ID_ISAR6, FHM, 1, u);
    FIELD_DP32(u, ID_ISAR6, SB, 1, u);
    FIELD_DP32(u, ID_ISAR6, SPECRES, 1, u);
    cpu->isar.id_isar6 = u;

    u = cpu->isar.id_mmfr3;
    FIELD_DP32(u, ID_MMFR3, PAN, 2, u); /* ATS1E1 */
    cpu->isar.id_mmfr3 = u;

    u = cpu->isar.id_mmfr4;
    FIELD_DP32(u, ID_MMFR4, HPDS, 1, u); /* AA32HPD */
    FIELD_DP32(u, ID_MMFR4, AC2, 1, u); /* ACTLR2, HACTLR2 */
    FIELD_DP32(u, ID_MMFR4, CNP, 1, u); /* TTCNP */
    cpu->isar.id_mmfr4 = u;

    u = cpu->isar.id_aa64dfr0;
    FIELD_DP64(u, ID_AA64DFR0, PMUVER, 5, u); /* v8.4-PMU */
    cpu->isar.id_aa64dfr0 = u;

    u = cpu->isar.id_dfr0;
    FIELD_DP32(u, ID_DFR0, PERFMON, 5, u); /* v8.4-PMU */
    cpu->isar.id_dfr0 = u;
}

struct ARMCPUInfo {
    const char *name;
    void (*initfn)(struct uc_struct *uc, CPUState *obj);
};

static const ARMCPUInfo aarch64_cpus[] = {
    { .name = "cortex-a57",         .initfn = aarch64_a57_initfn },
    { .name = "cortex-a53",         .initfn = aarch64_a53_initfn },
    { .name = "cortex-a72",         .initfn = aarch64_a72_initfn },
    { .name = "max",                .initfn = aarch64_max_initfn },
};

ARMCPU *cpu_aarch64_init(struct uc_struct *uc)
{
    int i;
    char *cpu_model = "cortex-a72";
    ARMCPU *cpu;
    CPUState *cs;
    CPUClass *cc;

    cpu = calloc(1, sizeof(*cpu));
    if (cpu == NULL) {
        return NULL;
    }

    cs = (CPUState *)cpu;
    cc = (CPUClass *)&cpu->cc;
    cs->cc = cc;
    cs->uc = uc;
    uc->cpu = (CPUState *)cpu;

    /* init CPUClass */
    cpu_class_init(uc, cc);

    /* init ARMCPUClass */
    arm_cpu_class_init(uc, cc);

    /* init CPUState */
    cpu_common_initfn(uc, cs);

    /* init ARMCPU */
    arm_cpu_initfn(uc, cs);

    for (i = 0; i < ARRAY_SIZE(aarch64_cpus); i++) {
        if (strcmp(cpu_model, aarch64_cpus[i].name) == 0) {
            if (aarch64_cpus[i].initfn) {
                aarch64_cpus[i].initfn(uc, cs);
            }
            break;
        }
    }
    if (i == ARRAY_SIZE(aarch64_cpus)) {
        free(cpu);
        return NULL;
    }

    /* postinit ARMCPU */
    arm_cpu_post_init(cs);

    /*
     * Unicorn: Hack to force to enable EL2/EL3 for aarch64 so that we can
     *          use the full 64bits virtual address space.
     * 
     *          While EL2/EL3 is enabled but running within EL1, we could
     *          get somewhat like "x86 flat mode", though aarch64 only allows
     *          a maximum of 52bits virtual address space.
     */
    ARM_CPU(cs)->has_el2 = true;
    ARM_CPU(cs)->has_el3 = true;

    /* realize ARMCPU */
    arm_cpu_realizefn(uc, cs);

    // init address space
    cpu_address_space_init(cs, 0, cs->memory);

    qemu_init_vcpu(cs);

    return cpu;
}
