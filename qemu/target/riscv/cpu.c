/*
 * QEMU RISC-V CPU
 *
 * Copyright (c) 2016-2017 Sagar Karandikar, sagark@eecs.berkeley.edu
 * Copyright (c) 2017-2018 SiFive, Inc.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms and conditions of the GNU General Public License,
 * version 2 or later, as published by the Free Software Foundation.
 *
 * This program is distributed in the hope it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include "qemu/osdep.h"
#include "qemu/ctype.h"
#include "qemu/log.h"
#include "cpu.h"
#include "exec/exec-all.h"
#include "fpu/softfloat-helpers.h"

#include <uc_priv.h>

/* RISC-V CPU definitions */

// static const char riscv_exts[26] = "IEMAFDQCLBJTPVNSUHKORWXYZG";

const char * const riscv_int_regnames[] = {
  "x0/zero", "x1/ra",  "x2/sp",  "x3/gp",  "x4/tp",  "x5/t0",   "x6/t1",
  "x7/t2",   "x8/s0",  "x9/s1",  "x10/a0", "x11/a1", "x12/a2",  "x13/a3",
  "x14/a4",  "x15/a5", "x16/a6", "x17/a7", "x18/s2", "x19/s3",  "x20/s4",
  "x21/s5",  "x22/s6", "x23/s7", "x24/s8", "x25/s9", "x26/s10", "x27/s11",
  "x28/t3",  "x29/t4", "x30/t5", "x31/t6"
};

const char * const riscv_fpr_regnames[] = {
  "f0/ft0",   "f1/ft1",  "f2/ft2",   "f3/ft3",   "f4/ft4",  "f5/ft5",
  "f6/ft6",   "f7/ft7",  "f8/fs0",   "f9/fs1",   "f10/fa0", "f11/fa1",
  "f12/fa2",  "f13/fa3", "f14/fa4",  "f15/fa5",  "f16/fa6", "f17/fa7",
  "f18/fs2",  "f19/fs3", "f20/fs4",  "f21/fs5",  "f22/fs6", "f23/fs7",
  "f24/fs8",  "f25/fs9", "f26/fs10", "f27/fs11", "f28/ft8", "f29/ft9",
  "f30/ft10", "f31/ft11"
};

static void set_misa(CPURISCVState *env, target_ulong misa)
{
    env->misa_mask = env->misa = misa;
}

static void set_priv_version(CPURISCVState *env, int priv_ver)
{
    env->priv_ver = priv_ver;
}

static void set_feature(CPURISCVState *env, int feature)
{
    env->features |= (1ULL << feature);
}

static void set_resetvec(CPURISCVState *env, int resetvec)
{
    env->resetvec = resetvec;
}

static void riscv_any_cpu_init(CPUState *obj)
{
    CPURISCVState *env = &RISCV_CPU(obj)->env;
    set_misa(env, RVXLEN | RVI | RVM | RVA | RVF | RVD | RVC | RVU);
    set_priv_version(env, PRIV_VERSION_1_11_0);
    set_resetvec(env, DEFAULT_RSTVEC);
}

#if defined(TARGET_RISCV32)
// rv32
static void riscv_base32_cpu_init(CPUState *obj)
{
    CPURISCVState *env = &RISCV_CPU(obj)->env;
    /* We set this in the realise function */
    set_misa(env, 0);
}

// sifive-u34
static void rv32gcsu_priv1_10_0_cpu_init(CPUState *obj)
{
    CPURISCVState *env = &RISCV_CPU(obj)->env;
    set_misa(env, RV32 | RVI | RVM | RVA | RVF | RVD | RVC | RVS | RVU);
    set_priv_version(env, PRIV_VERSION_1_10_0);
    set_resetvec(env, DEFAULT_RSTVEC);
    set_feature(env, RISCV_FEATURE_MMU);
    set_feature(env, RISCV_FEATURE_PMP);
}

// sifive-e31
static void rv32imacu_nommu_cpu_init(CPUState *obj)
{
    CPURISCVState *env = &RISCV_CPU(obj)->env;
    set_misa(env, RV32 | RVI | RVM | RVA | RVC | RVU);
    set_priv_version(env, PRIV_VERSION_1_10_0);
    set_resetvec(env, DEFAULT_RSTVEC);
    set_feature(env, RISCV_FEATURE_PMP);
}

#elif defined(TARGET_RISCV64)
// rv64
static void riscv_base64_cpu_init(CPUState *obj)
{
    CPURISCVState *env = &RISCV_CPU(obj)->env;
    /* We set this in the realise function */
    set_misa(env, 0);
}

// sifive-u54
static void rv64gcsu_priv1_10_0_cpu_init(CPUState *obj)
{
    CPURISCVState *env = &RISCV_CPU(obj)->env;
    set_misa(env, RV64 | RVI | RVM | RVA | RVF | RVD | RVC | RVS | RVU);
    set_priv_version(env, PRIV_VERSION_1_10_0);
    set_resetvec(env, DEFAULT_RSTVEC);
    set_feature(env, RISCV_FEATURE_MMU);
    set_feature(env, RISCV_FEATURE_PMP);
}

// sifive-e51
static void rv64imacu_nommu_cpu_init(CPUState *obj)
{
    CPURISCVState *env = &RISCV_CPU(obj)->env;
    set_misa(env, RV64 | RVI | RVM | RVA | RVC | RVU);
    set_priv_version(env, PRIV_VERSION_1_10_0);
    set_resetvec(env, DEFAULT_RSTVEC);
    set_feature(env, RISCV_FEATURE_PMP);
}
#endif

static void riscv_cpu_set_pc(CPUState *cs, vaddr value)
{
    RISCVCPU *cpu = RISCV_CPU(cs);
    CPURISCVState *env = &cpu->env;
    env->pc = value;
}

static void riscv_cpu_synchronize_from_tb(CPUState *cs, TranslationBlock *tb)
{
    RISCVCPU *cpu = RISCV_CPU(cs);
    CPURISCVState *env = &cpu->env;
    env->pc = tb->pc;
}

static bool riscv_cpu_has_work(CPUState *cs)
{
    RISCVCPU *cpu = RISCV_CPU(cs);
    CPURISCVState *env = &cpu->env;
    /*
     * Definition of the WFI instruction requires it to ignore the privilege
     * mode and delegation registers, but respect individual enables
     */
    return (env->mip & env->mie) != 0;
}

void restore_state_to_opc(CPURISCVState *env, TranslationBlock *tb,
                          target_ulong *data)
{
    env->pc = data[0];
}

static void riscv_cpu_reset(CPUState *dev)
{
    CPUState *cs = CPU(dev);
    RISCVCPU *cpu = RISCV_CPU(cs);
    RISCVCPUClass *mcc = RISCV_CPU_GET_CLASS(cpu);
    CPURISCVState *env = &cpu->env;

    mcc->parent_reset(cs);

    env->priv = PRV_M;
    env->mstatus &= ~(MSTATUS_MIE | MSTATUS_MPRV);
    env->mcause = 0;
    env->pc = env->resetvec;

    cs->exception_index = EXCP_NONE;
    env->load_res = -1;
    set_default_nan_mode(1, &env->fp_status);
}

static void riscv_cpu_realize(struct uc_struct *uc, CPUState *dev)
{
    CPUState *cs = CPU(dev);
    RISCVCPU *cpu = RISCV_CPU(dev);
    CPURISCVState *env = &cpu->env;
    int priv_version = PRIV_VERSION_1_11_0;
    target_ulong target_misa = 0;

    cpu_exec_realizefn(cs);

    if (cpu->cfg.priv_spec) {
        if (!g_strcmp0(cpu->cfg.priv_spec, "v1.11.0")) {
            priv_version = PRIV_VERSION_1_11_0;
        } else if (!g_strcmp0(cpu->cfg.priv_spec, "v1.10.0")) {
            priv_version = PRIV_VERSION_1_10_0;
        } else if (!g_strcmp0(cpu->cfg.priv_spec, "v1.9.1")) {
            priv_version = PRIV_VERSION_1_09_1;
        } else {
            // error_setg(errp, "Unsupported privilege spec version '%s'", cpu->cfg.priv_spec);
            return;
        }
    }

    set_priv_version(env, priv_version);
    set_resetvec(env, DEFAULT_RSTVEC);

    if (cpu->cfg.mmu) {
        set_feature(env, RISCV_FEATURE_MMU);
    }

    if (cpu->cfg.pmp) {
        set_feature(env, RISCV_FEATURE_PMP);
    }

    /* If misa isn't set (rv32 and rv64 machines) set it here */
    if (!env->misa) {
        /* Do some ISA extension error checking */
        if (cpu->cfg.ext_i && cpu->cfg.ext_e) {
            //error_setg(errp, "I and E extensions are incompatible");
            return;
        }

        if (!cpu->cfg.ext_i && !cpu->cfg.ext_e) {
            // error_setg(errp, "Either I or E extension must be set");
            return;
        }

        if (cpu->cfg.ext_g && !(cpu->cfg.ext_i & cpu->cfg.ext_m &
                    cpu->cfg.ext_a & cpu->cfg.ext_f & cpu->cfg.ext_d)) {
            // warn_report("Setting G will also set IMAFD");
            cpu->cfg.ext_i = true;
            cpu->cfg.ext_m = true;
            cpu->cfg.ext_a = true;
            cpu->cfg.ext_f = true;
            cpu->cfg.ext_d = true;
        }

        /* Set the ISA extensions, checks should have happened above */
        if (cpu->cfg.ext_i) {
            target_misa |= RVI;
        }
        if (cpu->cfg.ext_e) {
            target_misa |= RVE;
        }
        if (cpu->cfg.ext_m) {
            target_misa |= RVM;
        }
        if (cpu->cfg.ext_a) {
            target_misa |= RVA;
        }
        if (cpu->cfg.ext_f) {
            target_misa |= RVF;
        }
        if (cpu->cfg.ext_d) {
            target_misa |= RVD;
        }
        if (cpu->cfg.ext_c) {
            target_misa |= RVC;
        }
        if (cpu->cfg.ext_s) {
            target_misa |= RVS;
        }
        if (cpu->cfg.ext_u) {
            target_misa |= RVU;
        }
        if (cpu->cfg.ext_h) {
            target_misa |= RVH;
        }

        set_misa(env, RVXLEN | target_misa);
    }

    cpu_reset(cs);
}

static void riscv_cpu_init(struct uc_struct *uc, CPUState *obj)
{
    RISCVCPU *cpu = RISCV_CPU(obj);
    CPURISCVState *env = &cpu->env;

    // unicorn
    env->uc = uc;

    cpu_set_cpustate_pointers(cpu);
}

static void riscv_cpu_class_init(struct uc_struct *uc, CPUClass *c, void *data)
{
    RISCVCPUClass *mcc = RISCV_CPU_CLASS(c);
    CPUClass *cc = CPU_CLASS(c);

    mcc->parent_reset = cc->reset;
    cc->reset = riscv_cpu_reset;

    cc->has_work = riscv_cpu_has_work;
    cc->do_interrupt = riscv_cpu_do_interrupt;
    cc->cpu_exec_interrupt = riscv_cpu_exec_interrupt;
    cc->set_pc = riscv_cpu_set_pc;
    cc->synchronize_from_tb = riscv_cpu_synchronize_from_tb;
    cc->do_unaligned_access = riscv_cpu_do_unaligned_access;
    cc->tcg_initialize = riscv_translate_init;
    cc->tlb_fill_cpu = riscv_cpu_tlb_fill;
}

typedef struct CPUModelInfo {
    const char *name;
    void (*initfn)(CPUState *obj);
} CPUModelInfo;

static const CPUModelInfo cpu_models[] = {
    {TYPE_RISCV_CPU_ANY,  riscv_any_cpu_init},
#ifdef TARGET_RISCV32
    {TYPE_RISCV_CPU_BASE32, riscv_base32_cpu_init},
    {TYPE_RISCV_CPU_SIFIVE_E31, rv32imacu_nommu_cpu_init},
    {TYPE_RISCV_CPU_SIFIVE_U34, rv32gcsu_priv1_10_0_cpu_init},
#endif
#ifdef TARGET_RISCV64
    {TYPE_RISCV_CPU_BASE64, riscv_base64_cpu_init},
    {TYPE_RISCV_CPU_SIFIVE_E51, rv64imacu_nommu_cpu_init},
    {TYPE_RISCV_CPU_SIFIVE_U54, rv64gcsu_priv1_10_0_cpu_init},
#endif
};

RISCVCPU *cpu_riscv_init(struct uc_struct *uc)
{
    RISCVCPU *cpu;
    CPUState *cs;
    CPUClass *cc;

    cpu = calloc(1, sizeof(*cpu));
    if (cpu == NULL) {
        return NULL;
    }

#ifdef TARGET_RISCV32
    if (uc->cpu_model == INT_MAX) {
        uc->cpu_model = UC_CPU_RISCV32_SIFIVE_U34;
    }
#else
    /* TARGET_RISCV64 */
    if (uc->cpu_model == INT_MAX) {
        uc->cpu_model = UC_CPU_RISCV64_SIFIVE_U54;
    }
#endif

    if (uc->cpu_model >= ARRAY_SIZE(cpu_models)) {
        free(cpu);
        return NULL;
    }

    cs = (CPUState *)cpu;
    cc = (CPUClass *)&cpu->cc;
    cs->cc = cc;
    cs->uc = uc;
    uc->cpu = (CPUState *)cpu;

    /* init CPUClass */
    cpu_class_init(uc, cc);

    /* init RISCVCPUClass */
    riscv_cpu_class_init(uc, cc, NULL);

    /* init device properties*/
    cpu->cfg.ext_i = true;
    cpu->cfg.ext_e = false;
    cpu->cfg.ext_g = true;
    cpu->cfg.ext_m = true;
    cpu->cfg.ext_a = true;
    cpu->cfg.ext_f = true;
    cpu->cfg.ext_d = true;
    cpu->cfg.ext_c = true;
    cpu->cfg.ext_s = true;
    cpu->cfg.ext_u = true;
    cpu->cfg.ext_h = false;
    cpu->cfg.ext_counters = true;
    cpu->cfg.ext_ifencei = true;
    cpu->cfg.ext_icsr = true;
    cpu->cfg.priv_spec = "v1.11.0";
    cpu->cfg.mmu = true;
    cpu->cfg.pmp = true;

    /* init CPUState */
    cpu_common_initfn(uc, cs);

    /* init CPU */
    riscv_cpu_init(uc, cs);

    /* init specific CPU model */
    cpu_models[uc->cpu_model].initfn(cs);

    /* realize CPU */
    riscv_cpu_realize(uc, cs);

    // init addresss space
    cpu_address_space_init(cs, 0, cs->memory);

    qemu_init_vcpu(cs);

    return cpu;
}
