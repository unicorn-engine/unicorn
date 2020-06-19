/* Modified for Unicorn Engine by Chen Huitao<chenhuitao@hfmrit.com>, 2020 */

#include "cpu.h"
#include "internals.h"
#include "exec/helper-proto.h"
#include "qemu/host-utils.h"
#include "sysemu/sysemu.h"
#include "qemu/bitops.h"
#include "qemu/crc32c.h"
#include "exec/cpu_ldst.h"
#include "arm_ldst.h"

#ifndef CONFIG_USER_ONLY
static inline int get_phys_addr(CPUARMState *env, target_ulong address,
                                int access_type, int is_user,
                                hwaddr *phys_ptr, int *prot,
                                target_ulong *page_size);

/* Definitions for the PMCCNTR and PMCR registers */
#define PMCRD   0x8
#define PMCRC   0x4
#define PMCRE   0x1
#endif

static uint64_t raw_read(CPUARMState *env, const ARMCPRegInfo *ri)
{
    if (cpreg_field_is_64bit(ri)) {
        return CPREG_FIELD64(env, ri);
    } else {
        return CPREG_FIELD32(env, ri);
    }
}

static void raw_write(CPUARMState *env, const ARMCPRegInfo *ri,
                      uint64_t value)
{
    if (cpreg_field_is_64bit(ri)) {
        CPREG_FIELD64(env, ri) = value;
    } else {
        CPREG_FIELD32(env, ri) = value;
    }
}

static uint64_t read_raw_cp_reg(CPUARMState *env, const ARMCPRegInfo *ri)
{
    /* Raw read of a coprocessor register (as needed for migration, etc). */
    if (ri->type & ARM_CP_CONST) {
        return ri->resetvalue;
    } else if (ri->raw_readfn) {
        return ri->raw_readfn(env, ri);
    } else if (ri->readfn) {
        return ri->readfn(env, ri);
    } else {
        return raw_read(env, ri);
    }
}

static void write_raw_cp_reg(CPUARMState *env, const ARMCPRegInfo *ri,
                             uint64_t v)
{
    /* Raw write of a coprocessor register (as needed for migration, etc).
     * Note that constant registers are treated as write-ignored; the
     * caller should check for success by whether a readback gives the
     * value written.
     */
    if (ri->type & ARM_CP_CONST) {
        return;
    } else if (ri->raw_writefn) {
        ri->raw_writefn(env, ri, v);
    } else if (ri->writefn) {
        ri->writefn(env, ri, v);
    } else {
        raw_write(env, ri, v);
    }
}

bool write_cpustate_to_list(ARMCPU *cpu)
{
    /* Write the coprocessor state from cpu->env to the (index,value) list. */
    int i;
    bool ok = true;

    for (i = 0; i < cpu->cpreg_array_len; i++) {
        uint32_t regidx = kvm_to_cpreg_id(cpu->cpreg_indexes[i]);
        const ARMCPRegInfo *ri;

        ri = get_arm_cp_reginfo(cpu->cp_regs, regidx);
        if (!ri) {
            ok = false;
            continue;
        }
        if (ri->type & ARM_CP_NO_MIGRATE) {
            continue;
        }
        cpu->cpreg_values[i] = read_raw_cp_reg(&cpu->env, ri);
    }
    return ok;
}

bool write_list_to_cpustate(ARMCPU *cpu)
{
    int i;
    bool ok = true;

    for (i = 0; i < cpu->cpreg_array_len; i++) {
        uint32_t regidx = kvm_to_cpreg_id(cpu->cpreg_indexes[i]);
        uint64_t v = cpu->cpreg_values[i];
        const ARMCPRegInfo *ri;

        ri = get_arm_cp_reginfo(cpu->cp_regs, regidx);
        if (!ri) {
            ok = false;
            continue;
        }
        if (ri->type & ARM_CP_NO_MIGRATE) {
            continue;
        }
        /* Write value and confirm it reads back as written
         * (to catch read-only registers and partially read-only
         * registers where the incoming migration value doesn't match)
         */
        write_raw_cp_reg(&cpu->env, ri, v);
        if (read_raw_cp_reg(&cpu->env, ri) != v) {
            ok = false;
        }
    }
    return ok;
}

static void add_cpreg_to_list(gpointer key, gpointer opaque)
{
    ARMCPU *cpu = opaque;
    uint64_t regidx;
    const ARMCPRegInfo *ri;

    regidx = *(uint32_t *)key;
    ri = get_arm_cp_reginfo(cpu->cp_regs, regidx);

    if (!(ri->type & ARM_CP_NO_MIGRATE)) {
        cpu->cpreg_indexes[cpu->cpreg_array_len] = cpreg_to_kvm_id(regidx);
        /* The value array need not be initialized at this point */
        cpu->cpreg_array_len++;
    }
}

static void count_cpreg(gpointer key, gpointer opaque)
{
    ARMCPU *cpu = opaque;
    uint64_t regidx;
    const ARMCPRegInfo *ri;

    regidx = *(uint32_t *)key;
    ri = get_arm_cp_reginfo(cpu->cp_regs, regidx);

    if (!(ri->type & ARM_CP_NO_MIGRATE)) {
        cpu->cpreg_array_len++;
    }
}

static gint cpreg_key_compare(gconstpointer a, gconstpointer b)
{
    uint64_t aidx = cpreg_to_kvm_id(*(uint32_t *)a);
    uint64_t bidx = cpreg_to_kvm_id(*(uint32_t *)b);

    if (aidx > bidx) {
        return 1;
    }
    if (aidx < bidx) {
        return -1;
    }
    return 0;
}

static void cpreg_make_keylist(gpointer key, gpointer value, gpointer udata)
{
    GList **plist = udata;

    *plist = g_list_prepend(*plist, key);
}

void init_cpreg_list(ARMCPU *cpu)
{
    /* Initialise the cpreg_tuples[] array based on the cp_regs hash.
     * Note that we require cpreg_tuples[] to be sorted by key ID.
     */
    GList *keys = NULL;
    int arraylen;

    g_hash_table_foreach(cpu->cp_regs, cpreg_make_keylist, &keys);

    keys = g_list_sort(keys, cpreg_key_compare);

    cpu->cpreg_array_len = 0;

    g_list_foreach(keys, count_cpreg, cpu);

    arraylen = cpu->cpreg_array_len;
    cpu->cpreg_indexes = g_new(uint64_t, arraylen);
    cpu->cpreg_values = g_new(uint64_t, arraylen);
    cpu->cpreg_vmstate_indexes = g_new(uint64_t, arraylen);
    cpu->cpreg_vmstate_values = g_new(uint64_t, arraylen);
    cpu->cpreg_vmstate_array_len = cpu->cpreg_array_len;
    cpu->cpreg_array_len = 0;

    g_list_foreach(keys, add_cpreg_to_list, cpu);

    assert(cpu->cpreg_array_len == arraylen);

    g_list_free(keys);
}

static void dacr_write(CPUARMState *env, const ARMCPRegInfo *ri, uint64_t value)
{
    ARMCPU *cpu = arm_env_get_cpu(env);

    raw_write(env, ri, value);
    tlb_flush(CPU(cpu), 1); /* Flush TLB as domain not tracked in TLB */
}

static void fcse_write(CPUARMState *env, const ARMCPRegInfo *ri, uint64_t value)
{
    ARMCPU *cpu = arm_env_get_cpu(env);

    if (raw_read(env, ri) != value) {
        /* Unlike real hardware the qemu TLB uses virtual addresses,
         * not modified virtual addresses, so this causes a TLB flush.
         */
        tlb_flush(CPU(cpu), 1);
        raw_write(env, ri, value);
    }
}

static void contextidr_write(CPUARMState *env, const ARMCPRegInfo *ri,
                             uint64_t value)
{
    ARMCPU *cpu = arm_env_get_cpu(env);

    if (raw_read(env, ri) != value && !arm_feature(env, ARM_FEATURE_MPU)
        && !extended_addresses_enabled(env)) {
        /* For VMSA (when not using the LPAE long descriptor page table
         * format) this register includes the ASID, so do a TLB flush.
         * For PMSA it is purely a process ID and no action is needed.
         */
        tlb_flush(CPU(cpu), 1);
    }
    raw_write(env, ri, value);
}

static void tlbiall_write(CPUARMState *env, const ARMCPRegInfo *ri,
                          uint64_t value)
{
    /* Invalidate all (TLBIALL) */
    ARMCPU *cpu = arm_env_get_cpu(env);

    tlb_flush(CPU(cpu), 1);
}

static void tlbimva_write(CPUARMState *env, const ARMCPRegInfo *ri,
                          uint64_t value)
{
    /* Invalidate single TLB entry by MVA and ASID (TLBIMVA) */
    ARMCPU *cpu = arm_env_get_cpu(env);

    tlb_flush_page(CPU(cpu), value & TARGET_PAGE_MASK);
}

static void tlbiasid_write(CPUARMState *env, const ARMCPRegInfo *ri,
                           uint64_t value)
{
    /* Invalidate by ASID (TLBIASID) */
    ARMCPU *cpu = arm_env_get_cpu(env);

    tlb_flush(CPU(cpu), value == 0);
}

static void tlbimvaa_write(CPUARMState *env, const ARMCPRegInfo *ri,
                           uint64_t value)
{
    /* Invalidate single entry by MVA, all ASIDs (TLBIMVAA) */
    ARMCPU *cpu = arm_env_get_cpu(env);

    tlb_flush_page(CPU(cpu), value & TARGET_PAGE_MASK);
}

/* IS variants of TLB operations must affect all cores */
static void tlbiall_is_write(CPUARMState *env, const ARMCPRegInfo *ri,
                             uint64_t value)
{
    //struct uc_struct *uc = env->uc;
    // TODO: issue #642
    // tlb_flush(other_cpu, 1);
}

static void tlbiasid_is_write(CPUARMState *env, const ARMCPRegInfo *ri,
                             uint64_t value)
{
    //struct uc_struct *uc = env->uc;
    // TODO: issue #642
    // tlb_flush(other_cpu, value == 0);
}

static void tlbimva_is_write(CPUARMState *env, const ARMCPRegInfo *ri,
                             uint64_t value)
{
    //struct uc_struct *uc = env->uc;
    // TODO: issue #642
    // tlb_flush(other_cpu, value & TARGET_PAGE_MASK);
}

static void tlbimvaa_is_write(CPUARMState *env, const ARMCPRegInfo *ri,
                             uint64_t value)
{
    //struct uc_struct *uc = env->uc;
    // TODO: issue #642
    // tlb_flush(other_cpu, value & TARGET_PAGE_MASK);
}

static const ARMCPRegInfo cp_reginfo[] = {
    { "FCSEIDR",   15,13,0, 0,0,0, 0,
      0, PL1_RW, NULL, 0, offsetof(CPUARMState, cp15.c13_fcse),
      NULL, NULL, fcse_write, NULL, raw_write, NULL, },
    { "CONTEXTIDR", 0,13,0,  3,0,1, ARM_CP_STATE_BOTH,
      0, PL1_RW, NULL, 0, offsetof(CPUARMState, cp15.contextidr_el1),
      NULL, NULL, contextidr_write, NULL, raw_write, NULL, },
    REGINFO_SENTINEL
};

static const ARMCPRegInfo not_v8_cp_reginfo[] = {
    /* NB: Some of these registers exist in v8 but with more precise
     * definitions that don't use CP_ANY wildcards (mostly in v8_cp_reginfo[]).
     */
    /* MMU Domain access control / MPU write buffer control */
    { "DACR", 15,3,CP_ANY, 0,CP_ANY,CP_ANY, 0,
      0, PL1_RW, NULL, 0, offsetof(CPUARMState, cp15.c3),
      NULL, NULL, dacr_write, NULL, raw_write, NULL, },
    /* ??? This covers not just the impdef TLB lockdown registers but also
     * some v7VMSA registers relating to TEX remap, so it is overly broad.
     */
    { "TLB_LOCKDOWN", 15,10,CP_ANY, 0,CP_ANY,CP_ANY, 0,
      ARM_CP_NOP, PL1_RW,  },
    /* Cache maintenance ops; some of this space may be overridden later. */
    { "CACHEMAINT", 15,7,CP_ANY, 0,0,CP_ANY, 0,
      ARM_CP_NOP | ARM_CP_OVERRIDE, PL1_W, },
    REGINFO_SENTINEL
};

static const ARMCPRegInfo not_v6_cp_reginfo[] = {
    /* Not all pre-v6 cores implemented this WFI, so this is slightly
     * over-broad.
     */
    { "WFI_v5", 15,7,8, 0,0,2, 0,
      ARM_CP_WFI, PL1_W, },
    REGINFO_SENTINEL
};

static const ARMCPRegInfo not_v7_cp_reginfo[] = {
    /* Standard v6 WFI (also used in some pre-v6 cores); not in v7 (which
     * is UNPREDICTABLE; we choose to NOP as most implementations do).
     */
    { "WFI_v6", 15,7,0, 0,0,4, 0,
      ARM_CP_WFI, PL1_W, },
    /* L1 cache lockdown. Not architectural in v6 and earlier but in practice
     * implemented in 926, 946, 1026, 1136, 1176 and 11MPCore. StrongARM and
     * OMAPCP will override this space.
     */
    { "DLOCKDOWN", 15,9,0, 0,0,0, 0,
      0, PL1_RW, NULL, 0, offsetof(CPUARMState, cp15.c9_data), },
    { "ILOCKDOWN", 15,9,0, 0,0,1, 0,
      0, PL1_RW, NULL, 0, offsetof(CPUARMState, cp15.c9_insn), },
    /* v6 doesn't have the cache ID registers but Linux reads them anyway */
    { "DUMMY", 15,0,0, 0,1,CP_ANY, 0,
      ARM_CP_CONST | ARM_CP_NO_MIGRATE, PL1_R, NULL, 0 },
    /* We don't implement pre-v7 debug but most CPUs had at least a DBGDIDR;
     * implementing it as RAZ means the "debug architecture version" bits
     * will read as a reserved value, which should cause Linux to not try
     * to use the debug hardware.
     */
    { "DBGDIDR", 14,0,0, 0,0,0, 0,
      ARM_CP_CONST, PL0_R, NULL, 0 },
    /* MMU TLB control. Note that the wildcarding means we cover not just
     * the unified TLB ops but also the dside/iside/inner-shareable variants.
     */
    { "TLBIALL", 15,8,CP_ANY, 0,CP_ANY,0, 0,
      ARM_CP_NO_MIGRATE, PL1_W, NULL, 0, 0,
      NULL, NULL, tlbiall_write, },
    { "TLBIMVA", 15,8,CP_ANY, 0,CP_ANY,1, 0,
      ARM_CP_NO_MIGRATE, PL1_W, NULL, 0, 0,
      NULL, NULL, tlbimva_write, },
    { "TLBIASID", 15,8,CP_ANY, 0,CP_ANY,2, 0,
      ARM_CP_NO_MIGRATE, PL1_W, NULL, 0, 0,
      NULL, NULL, tlbiasid_write, },
    { "TLBIMVAA", 15,8,CP_ANY, 0,CP_ANY,3, 0,
      ARM_CP_NO_MIGRATE, PL1_W, NULL, 0, 0,
      NULL, NULL, tlbimvaa_write, },
    REGINFO_SENTINEL
};

static void cpacr_write(CPUARMState *env, const ARMCPRegInfo *ri,
                        uint64_t value)
{
    uint32_t mask = 0;

    /* In ARMv8 most bits of CPACR_EL1 are RES0. */
    if (!arm_feature(env, ARM_FEATURE_V8)) {
        /* ARMv7 defines bits for unimplemented coprocessors as RAZ/WI.
         * ASEDIS [31] and D32DIS [30] are both UNK/SBZP without VFP.
         * TRCDIS [28] is RAZ/WI since we do not implement a trace macrocell.
         */
        if (arm_feature(env, ARM_FEATURE_VFP)) {
            /* VFP coprocessor: cp10 & cp11 [23:20] */
            mask |= (1U << 31) | (1 << 30) | (0xf << 20);

            if (!arm_feature(env, ARM_FEATURE_NEON)) {
                /* ASEDIS [31] bit is RAO/WI */
                value |= (1U << 31);
            }

            /* VFPv3 and upwards with NEON implement 32 double precision
             * registers (D0-D31).
             */
            if (!arm_feature(env, ARM_FEATURE_NEON) ||
                    !arm_feature(env, ARM_FEATURE_VFP3)) {
                /* D32DIS [30] is RAO/WI if D16-31 are not implemented. */
                value |= (1 << 30);
            }
        }
        value &= mask;
    }
    env->cp15.c1_coproc = value;
}

static const ARMCPRegInfo v6_cp_reginfo[] = {
    /* prefetch by MVA in v6, NOP in v7 */
    { "MVA_prefetch", 15,7,13, 0,0,1, 0,
      ARM_CP_NOP, PL1_W, },
    { "ISB", 15,7,5, 0,0,4, 0,
      ARM_CP_NOP, PL0_W, },
    { "DSB", 15,7,10, 0,0,4, 0,
      ARM_CP_NOP, PL0_W, },
    { "DMB", 15,7,10, 0,0,5, 0,
      ARM_CP_NOP, PL0_W, },
    { "IFAR", 15,6,0, 0,0,2, 0,
      0, PL1_RW, NULL, 0, offsetofhigh32(CPUARMState, cp15.far_el[1]), },
    /* Watchpoint Fault Address Register : should actually only be present
     * for 1136, 1176, 11MPCore.
     */
    { "WFAR", 15,6,0, 0,0,1, 0,
      ARM_CP_CONST, PL1_RW, NULL, 0, },
    { "CPACR", 0,1,0, 3,0,2, ARM_CP_STATE_BOTH, 
      0, PL1_RW, NULL, 0, offsetof(CPUARMState, cp15.c1_coproc),
      NULL, NULL, cpacr_write },
    REGINFO_SENTINEL
};

static CPAccessResult pmreg_access(CPUARMState *env, const ARMCPRegInfo *ri)
{
    /* Performance monitor registers user accessibility is controlled
     * by PMUSERENR.
     */
    if (arm_current_el(env) == 0 && !env->cp15.c9_pmuserenr) {
        return CP_ACCESS_TRAP;
    }
    return CP_ACCESS_OK;
}

#ifndef CONFIG_USER_ONLY

static inline bool arm_ccnt_enabled(CPUARMState *env)
{
    /* This does not support checking PMCCFILTR_EL0 register */

    if (!(env->cp15.c9_pmcr & PMCRE)) {
        return false;
    }

    return true;
}

void pmccntr_sync(CPUARMState *env)
{
    uint64_t temp_ticks;

    temp_ticks = muldiv64(qemu_clock_get_us(QEMU_CLOCK_VIRTUAL),
                          get_ticks_per_sec(), 1000000);

    if (env->cp15.c9_pmcr & PMCRD) {
        /* Increment once every 64 processor clock cycles */
        temp_ticks /= 64;
    }

    if (arm_ccnt_enabled(env)) {
        env->cp15.c15_ccnt = temp_ticks - env->cp15.c15_ccnt;
    }
}

static void pmcr_write(CPUARMState *env, const ARMCPRegInfo *ri,
                       uint64_t value)
{
    pmccntr_sync(env);

    if (value & PMCRC) {
        /* The counter has been reset */
        env->cp15.c15_ccnt = 0;
    }

    /* only the DP, X, D and E bits are writable */
    env->cp15.c9_pmcr &= ~0x39;
    env->cp15.c9_pmcr |= (value & 0x39);

    pmccntr_sync(env);
}

static uint64_t pmccntr_read(CPUARMState *env, const ARMCPRegInfo *ri)
{
    uint64_t total_ticks;

    if (!arm_ccnt_enabled(env)) {
        /* Counter is disabled, do not change value */
        return env->cp15.c15_ccnt;
    }

    total_ticks = muldiv64(qemu_clock_get_us(QEMU_CLOCK_VIRTUAL),
                           get_ticks_per_sec(), 1000000);

    if (env->cp15.c9_pmcr & PMCRD) {
        /* Increment once every 64 processor clock cycles */
        total_ticks /= 64;
    }
    return total_ticks - env->cp15.c15_ccnt;
}

static void pmccntr_write(CPUARMState *env, const ARMCPRegInfo *ri,
                        uint64_t value)
{
    uint64_t total_ticks;

    if (!arm_ccnt_enabled(env)) {
        /* Counter is disabled, set the absolute value */
        env->cp15.c15_ccnt = value;
        return;
    }

    total_ticks = muldiv64(qemu_clock_get_us(QEMU_CLOCK_VIRTUAL),
                           get_ticks_per_sec(), 1000000);

    if (env->cp15.c9_pmcr & PMCRD) {
        /* Increment once every 64 processor clock cycles */
        total_ticks /= 64;
    }
    env->cp15.c15_ccnt = total_ticks - value;
}

static void pmccntr_write32(CPUARMState *env, const ARMCPRegInfo *ri,
                            uint64_t value)
{
    uint64_t cur_val = pmccntr_read(env, NULL);

    pmccntr_write(env, ri, deposit64(cur_val, 0, 32, value));
}

#else /* CONFIG_USER_ONLY */

void pmccntr_sync(CPUARMState *env)
{
}

#endif

static void pmccfiltr_write(CPUARMState *env, const ARMCPRegInfo *ri,
                            uint64_t value)
{
    pmccntr_sync(env);
    env->cp15.pmccfiltr_el0 = value & 0x7E000000;
    pmccntr_sync(env);
}

static void pmcntenset_write(CPUARMState *env, const ARMCPRegInfo *ri,
                            uint64_t value)
{
    value &= (1U << 31);
    env->cp15.c9_pmcnten |= value;
}

static void pmcntenclr_write(CPUARMState *env, const ARMCPRegInfo *ri,
                             uint64_t value)
{
    value &= (1U << 31);
    env->cp15.c9_pmcnten &= ~value;
}

static void pmovsr_write(CPUARMState *env, const ARMCPRegInfo *ri,
                         uint64_t value)
{
    env->cp15.c9_pmovsr &= ~value;
}

static void pmxevtyper_write(CPUARMState *env, const ARMCPRegInfo *ri,
                             uint64_t value)
{
    env->cp15.c9_pmxevtyper = value & 0xff;
}

static void pmuserenr_write(CPUARMState *env, const ARMCPRegInfo *ri,
                            uint64_t value)
{
    env->cp15.c9_pmuserenr = value & 1;
}

static void pmintenset_write(CPUARMState *env, const ARMCPRegInfo *ri,
                             uint64_t value)
{
    /* We have no event counters so only the C bit can be changed */
    value &= (1U << 31);
    env->cp15.c9_pminten |= value;
}

static void pmintenclr_write(CPUARMState *env, const ARMCPRegInfo *ri,
                             uint64_t value)
{
    value &= (1U << 31);
    env->cp15.c9_pminten &= ~value;
}

static void vbar_write(CPUARMState *env, const ARMCPRegInfo *ri,
                       uint64_t value)
{
    /* Note that even though the AArch64 view of this register has bits
     * [10:0] all RES0 we can only mask the bottom 5, to comply with the
     * architectural requirements for bits which are RES0 only in some
     * contexts. (ARMv8 would permit us to do no masking at all, but ARMv7
     * requires the bottom five bits to be RAZ/WI because they're UNK/SBZP.)
     */
    raw_write(env, ri, value & ~0x1FULL);
}

static void scr_write(CPUARMState *env, const ARMCPRegInfo *ri, uint64_t value)
{
    /* We only mask off bits that are RES0 both for AArch64 and AArch32.
     * For bits that vary between AArch32/64, code needs to check the
     * current execution mode before directly using the feature bit.
     */
    uint32_t valid_mask = SCR_AARCH64_MASK | SCR_AARCH32_MASK;

    if (!arm_feature(env, ARM_FEATURE_EL2)) {
        valid_mask &= ~SCR_HCE;

        /* On ARMv7, SMD (or SCD as it is called in v7) is only
         * supported if EL2 exists. The bit is UNK/SBZP when
         * EL2 is unavailable. In QEMU ARMv7, we force it to always zero
         * when EL2 is unavailable.
         */
        if (arm_feature(env, ARM_FEATURE_V7)) {
            valid_mask &= ~SCR_SMD;
        }
    }

    /* Clear all-context RES0 bits.  */
    value &= valid_mask;
    raw_write(env, ri, value);
}

static uint64_t ccsidr_read(CPUARMState *env, const ARMCPRegInfo *ri)
{
    ARMCPU *cpu = arm_env_get_cpu(env);
    return cpu->ccsidr[env->cp15.c0_cssel];
}

static void csselr_write(CPUARMState *env, const ARMCPRegInfo *ri,
                         uint64_t value)
{
    raw_write(env, ri, value & 0xf);
}

static uint64_t isr_read(CPUARMState *env, const ARMCPRegInfo *ri)
{
    CPUState *cs = ENV_GET_CPU(env);
    uint64_t ret = 0;

    if (cs->interrupt_request & CPU_INTERRUPT_HARD) {
        ret |= CPSR_I;
    }
    if (cs->interrupt_request & CPU_INTERRUPT_FIQ) {
        ret |= CPSR_F;
    }
    /* External aborts are not possible in QEMU so A bit is always clear */
    return ret;
}

static const ARMCPRegInfo v7_cp_reginfo[] = {
    /* the old v6 WFI, UNPREDICTABLE in v7 but we choose to NOP */
    { "NOP", 15,7,0, 0,0,4, 0,
      ARM_CP_NOP, PL1_W,  },
    /* Performance monitors are implementation defined in v7,
     * but with an ARM recommended set of registers, which we
     * follow (although we don't actually implement any counters)
     *
     * Performance registers fall into three categories:
     *  (a) always UNDEF in PL0, RW in PL1 (PMINTENSET, PMINTENCLR)
     *  (b) RO in PL0 (ie UNDEF on write), RW in PL1 (PMUSERENR)
     *  (c) UNDEF in PL0 if PMUSERENR.EN==0, otherwise accessible (all others)
     * For the cases controlled by PMUSERENR we must set .access to PL0_RW
     * or PL0_RO as appropriate and then check PMUSERENR in the helper fn.
     */
    { "PMCNTENSET", 15,9,12, 0,0,1, 0,
      ARM_CP_NO_MIGRATE, PL0_RW, NULL, 0, offsetoflow32(CPUARMState, cp15.c9_pmcnten),
      pmreg_access, NULL, pmcntenset_write, NULL, raw_write },
    { "PMCNTENSET_EL0", 0,9,12, 3,3,1, ARM_CP_STATE_AA64,
      0, PL0_RW, NULL, 0, offsetof(CPUARMState, cp15.c9_pmcnten),
      pmreg_access, NULL, pmcntenset_write, NULL, raw_write },
    { "PMCNTENCLR", 15,9,12, 0,0,2, 0,
      ARM_CP_NO_MIGRATE, PL0_RW, NULL, 0, offsetoflow32(CPUARMState, cp15.c9_pmcnten),
      pmreg_access, NULL, pmcntenclr_write, },
    { "PMCNTENCLR_EL0", 0,9,12, 3,3,2, ARM_CP_STATE_AA64,
      ARM_CP_NO_MIGRATE, PL0_RW, NULL, 0, offsetof(CPUARMState, cp15.c9_pmcnten),
      pmreg_access, NULL, pmcntenclr_write },
    { "PMOVSR", 15,9,12, 0,0,3, 0,
      0, PL0_RW, NULL, 0, offsetof(CPUARMState, cp15.c9_pmovsr),
      pmreg_access, NULL, pmovsr_write, NULL, raw_write },
    /* Unimplemented so WI. */
    { "PMSWINC", 15,9,12, 0,0,4, 0,
      ARM_CP_NOP, PL0_W, NULL, 0, 0,
      pmreg_access, },
    /* Since we don't implement any events, writing to PMSELR is UNPREDICTABLE.
     * We choose to RAZ/WI.
     */
    { "PMSELR", 15,9,12, 0,0,5, 0,
      ARM_CP_CONST, PL0_RW, NULL, 0, 0,
      pmreg_access },
#ifndef CONFIG_USER_ONLY
    { "PMCCNTR", 15,9,13, 0,0,0, 0,
      ARM_CP_IO, PL0_RW, NULL, 0, 0,
      pmreg_access, pmccntr_read, pmccntr_write32, },
    { "PMCCNTR_EL0", 0,9,13, 3,3,0, ARM_CP_STATE_AA64,
      ARM_CP_IO, PL0_RW, NULL, 0, 0,
      pmreg_access, pmccntr_read, pmccntr_write, },
#endif
    { "PMCCFILTR_EL0", 0,14,15, 3,3,7, ARM_CP_STATE_AA64,
      ARM_CP_IO, PL0_RW, NULL, 0, offsetof(CPUARMState, cp15.pmccfiltr_el0),
      pmreg_access, NULL, pmccfiltr_write, },
    { "PMXEVTYPER", 15,9,13, 0,0,1, 0,
      0, PL0_RW, NULL, 0, offsetof(CPUARMState, cp15.c9_pmxevtyper),
      pmreg_access, NULL, pmxevtyper_write, NULL, raw_write },
    /* Unimplemented, RAZ/WI. */
    { "PMXEVCNTR", 15,9,13, 0,0,2, 0,
      ARM_CP_CONST, PL0_RW, NULL, 0, 0,
      pmreg_access },
    { "PMUSERENR", 15,9,14, 0,0,0, 0,
      0, PL0_R | PL1_RW, NULL, 0, offsetof(CPUARMState, cp15.c9_pmuserenr),
      NULL, NULL, pmuserenr_write, NULL, raw_write },
    { "PMINTENSET", 15,9,14, 0,0,1, 0,
      0, PL1_RW, NULL, 0, offsetof(CPUARMState, cp15.c9_pminten),
      NULL, NULL, pmintenset_write, NULL, raw_write },
    { "PMINTENCLR", 15,9,14, 0,0,2, 0,
      ARM_CP_NO_MIGRATE, PL1_RW, NULL, 0, offsetof(CPUARMState, cp15.c9_pminten),
      NULL, NULL, pmintenclr_write, },
    { "VBAR", 0,12,0, 3,0,0, ARM_CP_STATE_BOTH,
      0, PL1_RW, NULL, 0, offsetof(CPUARMState, cp15.vbar_el[1]),
      NULL, NULL, vbar_write, },
    { "SCR", 15,1,1, 0,0,0, 0,
      0, PL1_RW, NULL, 0, offsetoflow32(CPUARMState, cp15.scr_el3),
      NULL, NULL, scr_write },
    { "CCSIDR", 0,0,0, 3,1,0, ARM_CP_STATE_BOTH,
      ARM_CP_NO_MIGRATE, PL1_R, NULL, 0, 0,
      NULL, ccsidr_read, },
    { "CSSELR", 0,0,0, 3,2,0, ARM_CP_STATE_BOTH,
      0, PL1_RW, NULL, 0, offsetof(CPUARMState, cp15.c0_cssel),
      NULL, NULL, csselr_write, },
    /* Auxiliary ID register: this actually has an IMPDEF value but for now
     * just RAZ for all cores:
     */
    { "AIDR", 0,0,0, 3,1,7, ARM_CP_STATE_BOTH,
      ARM_CP_CONST, PL1_R, NULL, 0 },
    /* Auxiliary fault status registers: these also are IMPDEF, and we
     * choose to RAZ/WI for all cores.
     */
    { "AFSR0_EL1", 0,5,1, 3,0,0, ARM_CP_STATE_BOTH,
      ARM_CP_CONST, PL1_RW, NULL, 0 },
    { "AFSR1_EL1", 0,5,1, 3,0,1, ARM_CP_STATE_BOTH,
      ARM_CP_CONST, PL1_RW, NULL, 0 },
    /* MAIR can just read-as-written because we don't implement caches
     * and so don't need to care about memory attributes.
     */
    { "MAIR_EL1", 0,10,2, 3,0,0, ARM_CP_STATE_AA64,
      0, PL1_RW, NULL, 0, offsetof(CPUARMState, cp15.mair_el1), },
    /* For non-long-descriptor page tables these are PRRR and NMRR;
     * regardless they still act as reads-as-written for QEMU.
     * The override is necessary because of the overly-broad TLB_LOCKDOWN
     * definition.
     */
    { "MAIR0", 15,10,2, 0,0,0, ARM_CP_STATE_AA32,
      ARM_CP_OVERRIDE, PL1_RW, NULL, 0, offsetoflow32(CPUARMState, cp15.mair_el1),
      NULL, NULL, NULL, NULL, NULL, arm_cp_reset_ignore },
    { "MAIR1", 15,10,2, 0,0,1, ARM_CP_STATE_AA32,
      ARM_CP_OVERRIDE, PL1_RW, NULL, 0, offsetofhigh32(CPUARMState, cp15.mair_el1),
      NULL, NULL, NULL, NULL, NULL, arm_cp_reset_ignore },
    { "ISR_EL1", 0,12,1, 3,0,0, ARM_CP_STATE_BOTH,
      ARM_CP_NO_MIGRATE, PL1_R, NULL, 0, 0,
      NULL, isr_read },
    /* 32 bit ITLB invalidates */
    { "ITLBIALL", 15,8,5, 0,0,0, 0,
      ARM_CP_NO_MIGRATE, PL1_W, NULL, 0, 0,
      NULL, NULL, tlbiall_write },
    { "ITLBIMVA", 15,8,5, 0,0,1, 0,
      ARM_CP_NO_MIGRATE, PL1_W, NULL, 0, 0,
      NULL, NULL, tlbimva_write },
    { "ITLBIASID", 15,8,5, 0,0,2, 0,
      ARM_CP_NO_MIGRATE, PL1_W, NULL, 0, 0,
      NULL, NULL, tlbiasid_write },
    /* 32 bit DTLB invalidates */
    { "DTLBIALL", 15,8,6, 0,0,0, 0,
      ARM_CP_NO_MIGRATE, PL1_W, NULL, 0, 0,
      NULL, NULL, tlbiall_write },
    { "DTLBIMVA", 15,8,6, 0,0,1, 0,
      ARM_CP_NO_MIGRATE, PL1_W, NULL, 0, 0,
      NULL, NULL, tlbimva_write },
    { "DTLBIASID", 15,8,6, 0,0,2, 0,
      ARM_CP_NO_MIGRATE, PL1_W, NULL, 0, 0,
      NULL, NULL, tlbiasid_write },
    /* 32 bit TLB invalidates */
    { "TLBIALL", 15,8,7, 0,0,0, 0,
      ARM_CP_NO_MIGRATE, PL1_W, NULL, 0, 0,
      NULL, NULL, tlbiall_write },
    { "TLBIMVA", 15,8,7, 0,0,1, 0,
      ARM_CP_NO_MIGRATE, PL1_W, NULL, 0, 0,
      NULL, NULL, tlbimva_write },
    { "TLBIASID", 15,8,7, 0,0,2, 0,
      ARM_CP_NO_MIGRATE, PL1_W, NULL, 0, 0,
      NULL, NULL, tlbiasid_write },
    { "TLBIMVAA", 15,8,7, 0,0,3, 0,
      ARM_CP_NO_MIGRATE, PL1_W, NULL, 0, 0,
      NULL, NULL, tlbimvaa_write },
    REGINFO_SENTINEL
};

static const ARMCPRegInfo v7mp_cp_reginfo[] = {
    /* 32 bit TLB invalidates, Inner Shareable */
    { "TLBIALLIS", 15,8,3, 0,0,0, 0,
      ARM_CP_NO_MIGRATE, PL1_W, NULL, 0, 0,
      NULL, NULL, tlbiall_is_write },
    { "TLBIMVAIS", 15,8,3, 0,0,1, 0,
      ARM_CP_NO_MIGRATE, PL1_W, NULL, 0, 0,
      NULL, NULL, tlbimva_is_write },
    { "TLBIASIDIS", 15,8,3, 0,0,2, 0,
      ARM_CP_NO_MIGRATE, PL1_W, NULL, 0, 0,
      NULL, NULL, tlbiasid_is_write },
    { "TLBIMVAAIS", 15,8,3, 0,0,3, 0,
      ARM_CP_NO_MIGRATE, PL1_W, NULL, 0, 0,
      NULL, NULL, tlbimvaa_is_write },
    REGINFO_SENTINEL
};

static void teecr_write(CPUARMState *env, const ARMCPRegInfo *ri,
                        uint64_t value)
{
    value &= 1;
    env->teecr = value;
}

static CPAccessResult teehbr_access(CPUARMState *env, const ARMCPRegInfo *ri)
{
    if (arm_current_el(env) == 0 && (env->teecr & 1)) {
        return CP_ACCESS_TRAP;
    }
    return CP_ACCESS_OK;
}

static const ARMCPRegInfo t2ee_cp_reginfo[] = {
    { "TEECR", 14,0,0, 0,6,0, 0,
      0, PL1_RW, NULL, 0, offsetof(CPUARMState, teecr),
      NULL, NULL, teecr_write },
    { "TEEHBR", 14,1,0, 0,6,0, 0,
      0, PL0_RW, NULL, 0, offsetof(CPUARMState, teehbr),
      teehbr_access, },
    REGINFO_SENTINEL
};

static const ARMCPRegInfo v6k_cp_reginfo[] = {
    { "TPIDR_EL0", 0,13,0, 3,3,2, ARM_CP_STATE_AA64,
      0, PL0_RW, NULL, 0, offsetof(CPUARMState, cp15.tpidr_el0), },
    { "TPIDRURW", 15,13,0, 0,0,2, 0,
      0, PL0_RW, NULL, 0, offsetoflow32(CPUARMState, cp15.tpidr_el0),
      NULL, NULL, NULL, NULL, NULL, arm_cp_reset_ignore },
    { "TPIDRRO_EL0", 0,13,0, 3,3,3, ARM_CP_STATE_AA64,
      0, PL0_R|PL1_W, NULL, 0, offsetof(CPUARMState, cp15.tpidrro_el0) },
    { "TPIDRURO", 15,13,0, 0,0,3, 0,
      0, PL0_R|PL1_W, NULL, 0, offsetoflow32(CPUARMState, cp15.tpidrro_el0),
      NULL, NULL, NULL, NULL, NULL, arm_cp_reset_ignore },
    { "TPIDR_EL1", 0,13,0, 3,0,4, ARM_CP_STATE_BOTH,
      0, PL1_RW, NULL, 0, offsetof(CPUARMState, cp15.tpidr_el1), },
    REGINFO_SENTINEL
};

#ifndef CONFIG_USER_ONLY

static CPAccessResult gt_cntfrq_access(CPUARMState *env, const ARMCPRegInfo *ri)
{
    /* CNTFRQ: not visible from PL0 if both PL0PCTEN and PL0VCTEN are zero */
    if (arm_current_el(env) == 0 && !extract32(env->cp15.c14_cntkctl, 0, 2)) {
        return CP_ACCESS_TRAP;
    }
    return CP_ACCESS_OK;
}

static CPAccessResult gt_counter_access(CPUARMState *env, int timeridx)
{
    /* CNT[PV]CT: not visible from PL0 if ELO[PV]CTEN is zero */
    if (arm_current_el(env) == 0 &&
        !extract32(env->cp15.c14_cntkctl, timeridx, 1)) {
        return CP_ACCESS_TRAP;
    }
    return CP_ACCESS_OK;
}

static CPAccessResult gt_timer_access(CPUARMState *env, int timeridx)
{
    /* CNT[PV]_CVAL, CNT[PV]_CTL, CNT[PV]_TVAL: not visible from PL0 if
     * EL0[PV]TEN is zero.
     */
    if (arm_current_el(env) == 0 &&
        !extract32(env->cp15.c14_cntkctl, 9 - timeridx, 1)) {
        return CP_ACCESS_TRAP;
    }
    return CP_ACCESS_OK;
}

static CPAccessResult gt_pct_access(CPUARMState *env,
                                         const ARMCPRegInfo *ri)
{
    return gt_counter_access(env, GTIMER_PHYS);
}

static CPAccessResult gt_vct_access(CPUARMState *env,
                                         const ARMCPRegInfo *ri)
{
    return gt_counter_access(env, GTIMER_VIRT);
}

static CPAccessResult gt_ptimer_access(CPUARMState *env, const ARMCPRegInfo *ri)
{
    return gt_timer_access(env, GTIMER_PHYS);
}

static CPAccessResult gt_vtimer_access(CPUARMState *env, const ARMCPRegInfo *ri)
{
    return gt_timer_access(env, GTIMER_VIRT);
}

static uint64_t gt_get_countervalue(CPUARMState *env)
{
    return qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL) / GTIMER_SCALE;
}

static void gt_recalc_timer(ARMCPU *cpu, int timeridx)
{
    ARMGenericTimer *gt = &cpu->env.cp15.c14_timer[timeridx];

    if (gt->ctl & 1) {
        /* Timer enabled: calculate and set current ISTATUS, irq, and
         * reset timer to when ISTATUS next has to change
         */
        uint64_t count = gt_get_countervalue(&cpu->env);
        /* Note that this must be unsigned 64 bit arithmetic: */
        int istatus = count >= gt->cval;
        uint64_t nexttick;

        gt->ctl = deposit32(gt->ctl, 2, 1, istatus);
        //qemu_set_irq(cpu->gt_timer_outputs[timeridx],
        //             (istatus && !(gt->ctl & 2)));
        if (istatus) {
            /* Next transition is when count rolls back over to zero */
            nexttick = UINT64_MAX;
        } else {
            /* Next transition is when we hit cval */
            nexttick = gt->cval;
        }
        /* Note that the desired next expiry time might be beyond the
         * signed-64-bit range of a QEMUTimer -- in this case we just
         * set the timer for as far in the future as possible. When the
         * timer expires we will reset the timer for any remaining period.
         */
        if (nexttick > INT64_MAX / GTIMER_SCALE) {
            nexttick = INT64_MAX / GTIMER_SCALE;
        }
        //timer_mod(cpu->gt_timer[timeridx], nexttick);
    } else {
        /* Timer disabled: ISTATUS and timer output always clear */
        gt->ctl &= ~4;
        //qemu_set_irq(cpu->gt_timer_outputs[timeridx], 0);
        //timer_del(cpu->gt_timer[timeridx]);
    }
}

static void gt_cnt_reset(CPUARMState *env, const ARMCPRegInfo *ri)
{
}

static uint64_t gt_cnt_read(CPUARMState *env, const ARMCPRegInfo *ri)
{
    return gt_get_countervalue(env);
}

static void gt_cval_write(CPUARMState *env, const ARMCPRegInfo *ri,
                          uint64_t value)
{
    int timeridx = ri->opc1 & 1;

    env->cp15.c14_timer[timeridx].cval = value;
    //gt_recalc_timer(arm_env_get_cpu(env), timeridx);
}

static uint64_t gt_tval_read(CPUARMState *env, const ARMCPRegInfo *ri)
{
    int timeridx = ri->crm & 1;

    return (uint32_t)(env->cp15.c14_timer[timeridx].cval -
                      gt_get_countervalue(env));
}

static void gt_tval_write(CPUARMState *env, const ARMCPRegInfo *ri,
                          uint64_t value)
{
    int timeridx = ri->crm & 1;

    env->cp15.c14_timer[timeridx].cval = gt_get_countervalue(env) +
        + sextract64(value, 0, 32);
    gt_recalc_timer(arm_env_get_cpu(env), timeridx);
}

static void gt_ctl_write(CPUARMState *env, const ARMCPRegInfo *ri,
                         uint64_t value)
{
    ARMCPU *cpu = arm_env_get_cpu(env);
    int timeridx = ri->crm & 1;
    uint32_t oldval = env->cp15.c14_timer[timeridx].ctl;

    env->cp15.c14_timer[timeridx].ctl = deposit64(oldval, 0, 2, value);
    if ((oldval ^ value) & 1) {
        /* Enable toggled */
        gt_recalc_timer(cpu, timeridx);
    } else if ((oldval ^ value) & 2) {
        /* IMASK toggled: don't need to recalculate,
         * just set the interrupt line based on ISTATUS
         */
        //qemu_set_irq(cpu->gt_timer_outputs[timeridx],
        //             (oldval & 4) && !(value & 2));
    }
}

void arm_gt_ptimer_cb(void *opaque)
{
    ARMCPU *cpu = opaque;

    gt_recalc_timer(cpu, GTIMER_PHYS);
}

void arm_gt_vtimer_cb(void *opaque)
{
    ARMCPU *cpu = opaque;

    gt_recalc_timer(cpu, GTIMER_VIRT);
}

static const ARMCPRegInfo generic_timer_cp_reginfo[] = {
    /* Note that CNTFRQ is purely reads-as-written for the benefit
     * of software; writing it doesn't actually change the timer frequency.
     * Our reset value matches the fixed frequency we implement the timer at.
     */
    { "CNTFRQ", 15,14,0, 0,0,0, 0,
      ARM_CP_NO_MIGRATE, PL1_RW | PL0_R, NULL, 0, offsetoflow32(CPUARMState, cp15.c14_cntfrq),
      gt_cntfrq_access, NULL,NULL, NULL,NULL, arm_cp_reset_ignore, },
    { "CNTFRQ_EL0", 0,14,0, 3,3,0, ARM_CP_STATE_AA64,
      0, PL1_RW | PL0_R, NULL, (1000 * 1000 * 1000) / GTIMER_SCALE, offsetof(CPUARMState, cp15.c14_cntfrq),
      gt_cntfrq_access, },
    /* overall control: mostly access permissions */
    { "CNTKCTL", 0,14,1, 3,0,0, ARM_CP_STATE_BOTH,
      0, PL1_RW, NULL, 0, offsetof(CPUARMState, cp15.c14_cntkctl), },
    /* per-timer control */
    { "CNTP_CTL", 15,14,2, 0,0,1, 0,
      ARM_CP_IO | ARM_CP_NO_MIGRATE, PL1_RW | PL0_R, NULL, 0, offsetoflow32(CPUARMState, cp15.c14_timer[GTIMER_PHYS].ctl),
      gt_ptimer_access, NULL, gt_ctl_write, NULL,raw_write, arm_cp_reset_ignore, },
    { "CNTP_CTL_EL0", 0,14,2, 3,3,1, ARM_CP_STATE_AA64,
      ARM_CP_IO, PL1_RW | PL0_R, NULL, 0, offsetof(CPUARMState, cp15.c14_timer[GTIMER_PHYS].ctl),
      gt_ptimer_access, NULL,gt_ctl_write, NULL,raw_write, },
    { "CNTV_CTL", 15,14,3, 0,0,1, 0,
      ARM_CP_IO | ARM_CP_NO_MIGRATE, PL1_RW | PL0_R, NULL, 0, offsetoflow32(CPUARMState, cp15.c14_timer[GTIMER_VIRT].ctl),
      gt_vtimer_access, NULL,gt_ctl_write, NULL,raw_write, arm_cp_reset_ignore, },
    { "CNTV_CTL_EL0", 0,14,3, 3,3,1, ARM_CP_STATE_AA64,
      ARM_CP_IO, PL1_RW | PL0_R, NULL, 0, offsetof(CPUARMState, cp15.c14_timer[GTIMER_VIRT].ctl),
      gt_vtimer_access, NULL,gt_ctl_write, NULL,raw_write, },
    /* TimerValue views: a 32 bit downcounting view of the underlying state */
    { "CNTP_TVAL", 15,14,2, 0,0,0, 0,
      ARM_CP_NO_MIGRATE | ARM_CP_IO, PL1_RW | PL0_R, NULL, 0, 0,
      gt_ptimer_access, gt_tval_read, gt_tval_write, },
    { "CNTP_TVAL_EL0", 0,14,2, 3,3,0, ARM_CP_STATE_AA64,
      ARM_CP_NO_MIGRATE | ARM_CP_IO, PL1_RW | PL0_R, NULL, 0, 0,
      NULL, gt_tval_read, gt_tval_write, },
    { "CNTV_TVAL", 15,14,3, 0,0,0, 0,
      ARM_CP_NO_MIGRATE | ARM_CP_IO, PL1_RW | PL0_R, NULL, 0, 0,
      gt_vtimer_access, gt_tval_read, gt_tval_write, },
    { "CNTV_TVAL_EL0", 0,14,3, 3,3,0, ARM_CP_STATE_AA64,
      ARM_CP_NO_MIGRATE | ARM_CP_IO, PL1_RW | PL0_R, NULL, 0, 0,
      NULL, gt_tval_read, gt_tval_write, },
    /* The counter itself */
    { "CNTPCT", 15,0,14, 0,0, 0, 0,
      ARM_CP_64BIT | ARM_CP_NO_MIGRATE | ARM_CP_IO, PL0_R, NULL, 0, 0,
      gt_pct_access, gt_cnt_read,NULL, NULL,NULL, arm_cp_reset_ignore, },
    { "CNTPCT_EL0", 0,14,0, 3,3,1, ARM_CP_STATE_AA64,
      ARM_CP_NO_MIGRATE | ARM_CP_IO, PL0_R, NULL, 0, 0,
      gt_pct_access, gt_cnt_read, NULL, NULL, NULL, gt_cnt_reset, },
    { "CNTVCT", 15,0,14, 0,1,0, 0,
      ARM_CP_64BIT | ARM_CP_NO_MIGRATE | ARM_CP_IO, PL0_R, NULL, 0, 0,
      gt_vct_access, gt_cnt_read,NULL, NULL,NULL, arm_cp_reset_ignore, },
    { "CNTVCT_EL0", 0,14,0, 3,3,2, ARM_CP_STATE_AA64,
      ARM_CP_NO_MIGRATE | ARM_CP_IO, PL0_R, NULL, 0, 0,
      gt_vct_access, gt_cnt_read, NULL, NULL,NULL, gt_cnt_reset, },
    /* Comparison value, indicating when the timer goes off */
    { "CNTP_CVAL", 15, 0,14, 0,2, 0, 0,
      ARM_CP_64BIT | ARM_CP_IO | ARM_CP_NO_MIGRATE, PL1_RW | PL0_R, NULL, 0, offsetof(CPUARMState, cp15.c14_timer[GTIMER_PHYS].cval),
      gt_ptimer_access, NULL, gt_cval_write, NULL, raw_write, arm_cp_reset_ignore, },
    { "CNTP_CVAL_EL0", 0,14,2, 3,3,2, ARM_CP_STATE_AA64,
      ARM_CP_IO, PL1_RW | PL0_R, NULL, 0, offsetof(CPUARMState, cp15.c14_timer[GTIMER_PHYS].cval),
      gt_vtimer_access, NULL, gt_cval_write, NULL, raw_write, },
    { "CNTV_CVAL", 15, 0,14, 0,3,0, 0,
      ARM_CP_64BIT | ARM_CP_IO | ARM_CP_NO_MIGRATE, PL1_RW | PL0_R, NULL, 0, offsetof(CPUARMState, cp15.c14_timer[GTIMER_VIRT].cval),
      gt_vtimer_access, NULL, gt_cval_write, NULL, raw_write, arm_cp_reset_ignore, },
    { "CNTV_CVAL_EL0", 0,14,3, 3,3,2, ARM_CP_STATE_AA64,
      ARM_CP_IO, PL1_RW | PL0_R, NULL, 0, offsetof(CPUARMState, cp15.c14_timer[GTIMER_VIRT].cval),
      gt_vtimer_access, NULL, gt_cval_write, NULL, raw_write, },
    REGINFO_SENTINEL
};

#else
/* In user-mode none of the generic timer registers are accessible,
 * and their implementation depends on QEMU_CLOCK_VIRTUAL and qdev gpio outputs,
 * so instead just don't register any of them.
 */
static const ARMCPRegInfo generic_timer_cp_reginfo[] = {
    REGINFO_SENTINEL
};

#endif

static void par_write(CPUARMState *env, const ARMCPRegInfo *ri, uint64_t value)
{
    if (arm_feature(env, ARM_FEATURE_LPAE)) {
        raw_write(env, ri, value);
    } else if (arm_feature(env, ARM_FEATURE_V7)) {
        raw_write(env, ri, value & 0xfffff6ff);
    } else {
        raw_write(env, ri, value & 0xfffff1ff);
    }
}

#ifndef CONFIG_USER_ONLY
/* get_phys_addr() isn't present for user-mode-only targets */

static CPAccessResult ats_access(CPUARMState *env, const ARMCPRegInfo *ri)
{
    if (ri->opc2 & 4) {
        /* Other states are only available with TrustZone; in
         * a non-TZ implementation these registers don't exist
         * at all, which is an Uncategorized trap. This underdecoding
         * is safe because the reginfo is NO_MIGRATE.
         */
        return CP_ACCESS_TRAP_UNCATEGORIZED;
    }
    return CP_ACCESS_OK;
}

static void ats_write(CPUARMState *env, const ARMCPRegInfo *ri, uint64_t value)
{
    hwaddr phys_addr;
    target_ulong page_size;
    int prot;
    int ret, is_user = ri->opc2 & 2;
    int access_type = ri->opc2 & 1;

    ret = get_phys_addr(env, value, access_type, is_user,
                        &phys_addr, &prot, &page_size);
    if (extended_addresses_enabled(env)) {
        /* ret is a DFSR/IFSR value for the long descriptor
         * translation table format, but with WnR always clear.
         * Convert it to a 64-bit PAR.
         */
        uint64_t par64 = (1 << 11); /* LPAE bit always set */
        if (ret == 0) {
            par64 |= phys_addr & ~0xfffULL;
            /* We don't set the ATTR or SH fields in the PAR. */
        } else {
            par64 |= 1; /* F */
            par64 |= (ret & 0x3f) << 1; /* FS */
            /* Note that S2WLK and FSTAGE are always zero, because we don't
             * implement virtualization and therefore there can't be a stage 2
             * fault.
             */
        }
        env->cp15.par_el1 = par64;
    } else {
        /* ret is a DFSR/IFSR value for the short descriptor
         * translation table format (with WnR always clear).
         * Convert it to a 32-bit PAR.
         */
        if (ret == 0) {
            /* We do not set any attribute bits in the PAR */
            if (page_size == (1 << 24)
                && arm_feature(env, ARM_FEATURE_V7)) {
                env->cp15.par_el1 = (phys_addr & 0xff000000) | 1 << 1;
            } else {
                env->cp15.par_el1 = phys_addr & 0xfffff000;
            }
        } else {
            env->cp15.par_el1 = ((ret & (1 << 10)) >> 5) |
                ((ret & (1 << 12)) >> 6) |
                ((ret & 0xf) << 1) | 1;
        }
    }
}
#endif

static const ARMCPRegInfo vapa_cp_reginfo[] = {
    { "PAR", 15,7,4, 0,0,0, 0,
      0, PL1_RW, NULL, 0, offsetoflow32(CPUARMState, cp15.par_el1),
      NULL, NULL, par_write },
#ifndef CONFIG_USER_ONLY
    { "ATS", 15,7,8, 0,0,CP_ANY, 0,
      ARM_CP_NO_MIGRATE, PL1_W, NULL, 0, 0,
      ats_access, NULL, ats_write },
#endif
    REGINFO_SENTINEL
};

/* Return basic MPU access permission bits.  */
static uint32_t simple_mpu_ap_bits(uint32_t val)
{
    uint32_t ret;
    uint32_t mask;
    int i;
    ret = 0;
    mask = 3;
    for (i = 0; i < 16; i += 2) {
        ret |= (val >> i) & mask;
        mask <<= 2;
    }
    return ret;
}

/* Pad basic MPU access permission bits to extended format.  */
static uint32_t extended_mpu_ap_bits(uint32_t val)
{
    uint32_t ret;
    uint32_t mask;
    int i;
    ret = 0;
    mask = 3;
    for (i = 0; i < 16; i += 2) {
        ret |= (val & mask) << i;
        mask <<= 2;
    }
    return ret;
}

static void pmsav5_data_ap_write(CPUARMState *env, const ARMCPRegInfo *ri,
                                 uint64_t value)
{
    env->cp15.pmsav5_data_ap = extended_mpu_ap_bits(value);
}

static uint64_t pmsav5_data_ap_read(CPUARMState *env, const ARMCPRegInfo *ri)
{
    return simple_mpu_ap_bits(env->cp15.pmsav5_data_ap);
}

static void pmsav5_insn_ap_write(CPUARMState *env, const ARMCPRegInfo *ri,
                                 uint64_t value)
{
    env->cp15.pmsav5_insn_ap = extended_mpu_ap_bits(value);
}

static uint64_t pmsav5_insn_ap_read(CPUARMState *env, const ARMCPRegInfo *ri)
{
    return simple_mpu_ap_bits(env->cp15.pmsav5_insn_ap);
}

static const ARMCPRegInfo pmsav5_cp_reginfo[] = {
    { "DATA_AP", 15,5,0, 0,0,0, 0,
      ARM_CP_NO_MIGRATE, PL1_RW, NULL, 0, offsetof(CPUARMState, cp15.pmsav5_data_ap),
      NULL, pmsav5_data_ap_read, pmsav5_data_ap_write, },
    { "INSN_AP", 15,5,0, 0,0,1, 0,
      ARM_CP_NO_MIGRATE,PL1_RW, NULL, 0, offsetof(CPUARMState, cp15.pmsav5_insn_ap),
      NULL, pmsav5_insn_ap_read, pmsav5_insn_ap_write, },
    { "DATA_EXT_AP", 15,5,0, 0,0,2, 0,
      0, PL1_RW, NULL, 0, offsetof(CPUARMState, cp15.pmsav5_data_ap), },
    { "INSN_EXT_AP", 15,5,0, 0,0,3, 0,
      0, PL1_RW, NULL, 0, offsetof(CPUARMState, cp15.pmsav5_insn_ap), },
    { "DCACHE_CFG", 15,2,0, 0,0,0, 0,
      0, PL1_RW, NULL, 0, offsetof(CPUARMState, cp15.c2_data), },
    { "ICACHE_CFG", 15,2,0, 0,0,1, 0,
      0, PL1_RW, NULL, 0, offsetof(CPUARMState, cp15.c2_insn), },
    /* Protection region base and size registers */
    { "946_PRBS0", 15,6,0, 0,0,CP_ANY, 0,
      0, PL1_RW, NULL, 0, offsetof(CPUARMState, cp15.c6_region[0]) },
    { "946_PRBS1", 15,6,1, 0,0,CP_ANY, 0,
      0, PL1_RW, NULL, 0, offsetof(CPUARMState, cp15.c6_region[1]) },
    { "946_PRBS2", 15,6,2, 0,0,CP_ANY, 0,
      0, PL1_RW, NULL, 0, offsetof(CPUARMState, cp15.c6_region[2]) },
    { "946_PRBS3", 15,6,3, 0,0,CP_ANY, 0,
      0, PL1_RW, NULL, 0, offsetof(CPUARMState, cp15.c6_region[3]) },
    { "946_PRBS4", 15,6,4, 0,0,CP_ANY, 0,
      0, PL1_RW, NULL, 0, offsetof(CPUARMState, cp15.c6_region[4]) },
    { "946_PRBS5", 15,6,5, 0,0,CP_ANY, 0,
      0, PL1_RW, NULL, 0, offsetof(CPUARMState, cp15.c6_region[5]) },
    { "946_PRBS6", 15,6,6, 0,0,CP_ANY, 0,
      0, PL1_RW, NULL, 0, offsetof(CPUARMState, cp15.c6_region[6]) },
    { "946_PRBS7", 15,6,7, 0,0,CP_ANY, 0,
      0, PL1_RW, NULL, 0, offsetof(CPUARMState, cp15.c6_region[7]) },
    REGINFO_SENTINEL
};

static void vmsa_ttbcr_raw_write(CPUARMState *env, const ARMCPRegInfo *ri,
                                 uint64_t value)
{
    int maskshift = extract32(value, 0, 3);

    if (!arm_feature(env, ARM_FEATURE_V8)) {
        if (arm_feature(env, ARM_FEATURE_LPAE) && (value & TTBCR_EAE)) {
            /* Pre ARMv8 bits [21:19], [15:14] and [6:3] are UNK/SBZP when
             * using Long-desciptor translation table format */
            value &= ~((7 << 19) | (3 << 14) | (0xf << 3));
        } else if (arm_feature(env, ARM_FEATURE_EL3)) {
            /* In an implementation that includes the Security Extensions
             * TTBCR has additional fields PD0 [4] and PD1 [5] for
             * Short-descriptor translation table format.
             */
            value &= TTBCR_PD1 | TTBCR_PD0 | TTBCR_N;
        } else {
            value &= TTBCR_N;
        }
    }

    /* Note that we always calculate c2_mask and c2_base_mask, but
     * they are only used for short-descriptor tables (ie if EAE is 0);
     * for long-descriptor tables the TTBCR fields are used differently
     * and the c2_mask and c2_base_mask values are meaningless.
     */
    raw_write(env, ri, value);
    env->cp15.c2_mask = ~(((uint32_t)0xffffffffu) >> maskshift);
    env->cp15.c2_base_mask = ~((uint32_t)0x3fffu >> maskshift);
}

static void vmsa_ttbcr_write(CPUARMState *env, const ARMCPRegInfo *ri,
                             uint64_t value)
{
    ARMCPU *cpu = arm_env_get_cpu(env);

    if (arm_feature(env, ARM_FEATURE_LPAE)) {
        /* With LPAE the TTBCR could result in a change of ASID
         * via the TTBCR.A1 bit, so do a TLB flush.
         */
        tlb_flush(CPU(cpu), 1);
    }
    vmsa_ttbcr_raw_write(env, ri, value);
}

static void vmsa_ttbcr_reset(CPUARMState *env, const ARMCPRegInfo *ri)
{
    env->cp15.c2_base_mask = 0xffffc000u;
    raw_write(env, ri, 0);
    env->cp15.c2_mask = 0;
}

static void vmsa_tcr_el1_write(CPUARMState *env, const ARMCPRegInfo *ri,
                               uint64_t value)
{
    ARMCPU *cpu = arm_env_get_cpu(env);

    /* For AArch64 the A1 bit could result in a change of ASID, so TLB flush. */
    tlb_flush(CPU(cpu), 1);
    raw_write(env, ri, value);
}

static void vmsa_ttbr_write(CPUARMState *env, const ARMCPRegInfo *ri,
                            uint64_t value)
{
    /* 64 bit accesses to the TTBRs can change the ASID and so we
     * must flush the TLB.
     */
    if (cpreg_field_is_64bit(ri)) {
        ARMCPU *cpu = arm_env_get_cpu(env);

        tlb_flush(CPU(cpu), 1);
    }
    raw_write(env, ri, value);
}

static const ARMCPRegInfo vmsa_cp_reginfo[] = {
    { "DFSR", 15,5,0, 0,0,0, 0,
      ARM_CP_NO_MIGRATE, PL1_RW, NULL, 0, offsetoflow32(CPUARMState, cp15.esr_el[1]),
      NULL,NULL,NULL,NULL,NULL, arm_cp_reset_ignore, },
    { "IFSR", 15,5,0, 0,0,1, 0,
      0, PL1_RW, NULL, 0, offsetof(CPUARMState, cp15.ifsr_el2), },
    { "ESR_EL1", 0,5,2, 3,0,0, ARM_CP_STATE_AA64,
      0, PL1_RW, NULL, 0, offsetof(CPUARMState, cp15.esr_el[1]), },
    { "TTBR0_EL1", 0,2,0, 3,0,0, ARM_CP_STATE_BOTH,
      0, PL1_RW, NULL, 0, offsetof(CPUARMState, cp15.ttbr0_el1),
      NULL, NULL, vmsa_ttbr_write, },
    { "TTBR1_EL1", 0,2,0, 3,0,1, ARM_CP_STATE_BOTH,
      0, PL1_RW, NULL, 0, offsetof(CPUARMState, cp15.ttbr1_el1),
      NULL, NULL, vmsa_ttbr_write, },
    { "TCR_EL1", 0,2,0, 3,0,2, ARM_CP_STATE_AA64,
      0, PL1_RW, NULL, 0, offsetof(CPUARMState, cp15.c2_control),
      NULL, NULL,vmsa_tcr_el1_write, NULL,raw_write, vmsa_ttbcr_reset, },
    { "TTBCR", 15,2,0, 0,0,2, 0,
      ARM_CP_NO_MIGRATE, PL1_RW, NULL, 0, offsetoflow32(CPUARMState, cp15.c2_control),
      NULL, NULL, vmsa_ttbcr_write, NULL, vmsa_ttbcr_raw_write, arm_cp_reset_ignore, },
    /* 64-bit FAR; this entry also gives us the AArch32 DFAR */
    { "FAR_EL1", 0,6,0, 3,0,0, ARM_CP_STATE_BOTH,
      0, PL1_RW, NULL, 0, offsetof(CPUARMState, cp15.far_el[1]), },
    REGINFO_SENTINEL
};

static void omap_ticonfig_write(CPUARMState *env, const ARMCPRegInfo *ri,
                                uint64_t value)
{
    env->cp15.c15_ticonfig = value & 0xe7;
    /* The OS_TYPE bit in this register changes the reported CPUID! */
    env->cp15.c0_cpuid = (value & (1 << 5)) ?
        ARM_CPUID_TI915T : ARM_CPUID_TI925T;
}

static void omap_threadid_write(CPUARMState *env, const ARMCPRegInfo *ri,
                                uint64_t value)
{
    env->cp15.c15_threadid = value & 0xffff;
}

static void omap_wfi_write(CPUARMState *env, const ARMCPRegInfo *ri,
                           uint64_t value)
{
    /* Wait-for-interrupt (deprecated) */
    cpu_interrupt(CPU(arm_env_get_cpu(env)), CPU_INTERRUPT_HALT);
}

static void omap_cachemaint_write(CPUARMState *env, const ARMCPRegInfo *ri,
                                  uint64_t value)
{
    /* On OMAP there are registers indicating the max/min index of dcache lines
     * containing a dirty line; cache flush operations have to reset these.
     */
    env->cp15.c15_i_max = 0x000;
    env->cp15.c15_i_min = 0xff0;
}

static const ARMCPRegInfo omap_cp_reginfo[] = {
    { "DFSR", 15,5,CP_ANY, 0,CP_ANY,CP_ANY, 0,
      ARM_CP_OVERRIDE, PL1_RW, NULL, 0, offsetoflow32(CPUARMState, cp15.esr_el[1]), },
    { "", 15,15,0, 0,0,0, 0,
      ARM_CP_NOP, PL1_RW, NULL, 0, 0, },
    { "TICONFIG", 15,15,1, 0,0,0, 0,
      0, PL1_RW, NULL, 0, offsetof(CPUARMState, cp15.c15_ticonfig),
      NULL, NULL, omap_ticonfig_write },
    { "IMAX", 15,15,2, 0,0,0, 0,
      0, PL1_RW, NULL, 0, offsetof(CPUARMState, cp15.c15_i_max), },
    { "IMIN", 15,15,3, 0,0,0, 0,
      0, PL1_RW, NULL, 0xff0, offsetof(CPUARMState, cp15.c15_i_min) },
    { "THREADID", 15,15,4, 0,0,0, 0,
      0, PL1_RW, NULL, 0, offsetof(CPUARMState, cp15.c15_threadid), 
      NULL, NULL, omap_threadid_write },
    { "TI925T_STATUS", 15,15,8, 0,0,0, 0,
      ARM_CP_NO_MIGRATE, PL1_RW, NULL, 0, 0,
      NULL, arm_cp_read_zero, omap_wfi_write, },
    /* TODO: Peripheral port remap register:
     * On OMAP2 mcr p15, 0, rn, c15, c2, 4 sets up the interrupt controller
     * base address at $rn & ~0xfff and map size of 0x200 << ($rn & 0xfff),
     * when MMU is off.
     */
    { "OMAP_CACHEMAINT", 15,7,CP_ANY, 0,0,CP_ANY, 0,
      ARM_CP_OVERRIDE | ARM_CP_NO_MIGRATE, PL1_W, NULL, 0, 0,
      NULL, NULL, omap_cachemaint_write },
    { "C9", 15,9,CP_ANY, 0,CP_ANY,CP_ANY, 0,
      ARM_CP_CONST | ARM_CP_OVERRIDE, PL1_RW, NULL, 0, 0, },
    REGINFO_SENTINEL
};

static void xscale_cpar_write(CPUARMState *env, const ARMCPRegInfo *ri,
                              uint64_t value)
{
    env->cp15.c15_cpar = value & 0x3fff;
}

static const ARMCPRegInfo xscale_cp_reginfo[] = {
    { "XSCALE_CPAR", 15,15,1, 0,0,0, 0,
      0, PL1_RW, NULL, 0, offsetof(CPUARMState, cp15.c15_cpar),
      NULL, NULL, xscale_cpar_write, },
    { "XSCALE_AUXCR", 15,1,0, 0,0,1, 0,
      0, PL1_RW, NULL, 0, offsetof(CPUARMState, cp15.c1_xscaleauxcr), },
    /* XScale specific cache-lockdown: since we have no cache we NOP these
     * and hope the guest does not really rely on cache behaviour.
     */
    { "XSCALE_LOCK_ICACHE_LINE", 15,9,1, 0,0,0, 0,
      ARM_CP_NOP, PL1_W },
    { "XSCALE_UNLOCK_ICACHE", 15,9,1, 0,0,1, 0,
      ARM_CP_NOP, PL1_W, },
    { "XSCALE_DCACHE_LOCK", 15,9,2, 0,0,0, 0,
      ARM_CP_NOP, PL1_RW },
    { "XSCALE_UNLOCK_DCACHE", 15,9,2, 0,0,1, 0,
      ARM_CP_NOP, PL1_W, },
    REGINFO_SENTINEL
};

static const ARMCPRegInfo dummy_c15_cp_reginfo[] = {
    /* RAZ/WI the whole crn=15 space, when we don't have a more specific
     * implementation of this implementation-defined space.
     * Ideally this should eventually disappear in favour of actually
     * implementing the correct behaviour for all cores.
     */
    { "C15_IMPDEF", 15,15,CP_ANY, 0,CP_ANY,CP_ANY, 0,
      ARM_CP_CONST | ARM_CP_NO_MIGRATE | ARM_CP_OVERRIDE, PL1_RW, NULL, 0 },
    REGINFO_SENTINEL
};

static const ARMCPRegInfo cache_dirty_status_cp_reginfo[] = {
    /* Cache status: RAZ because we have no cache so it's always clean */
    { "CDSR", 15,7,10, 0,0,6, 0,
      ARM_CP_CONST | ARM_CP_NO_MIGRATE, PL1_R, NULL, 0 },
    REGINFO_SENTINEL
};

static const ARMCPRegInfo cache_block_ops_cp_reginfo[] = {
    /* We never have a a block transfer operation in progress */
    { "BXSR", 15,7,12, 0,0,4, 0,
      ARM_CP_CONST | ARM_CP_NO_MIGRATE, PL0_R, NULL, 0 },
    /* The cache ops themselves: these all NOP for QEMU */
    { "IICR", 15, 0,5, 0,0, 0, 0,
      ARM_CP_NOP|ARM_CP_64BIT, PL1_W },
    { "IDCR", 15, 0,6, 0,0, 0, 0,
      ARM_CP_NOP|ARM_CP_64BIT, PL1_W, },
    { "CDCR", 15, 0,12, 0,0, 0, 0,
      ARM_CP_NOP|ARM_CP_64BIT, PL0_W, },
    { "PIR", 15, 0,12, 0,1, 0, 0,
      ARM_CP_NOP|ARM_CP_64BIT, PL0_W, },
    { "PDR", 15, 0,12, 0,2, 0, 0,
      ARM_CP_NOP|ARM_CP_64BIT, PL0_W, },
    { "CIDCR", 15, 0,14, 0,0, 0, 0,
      ARM_CP_NOP|ARM_CP_64BIT, PL1_W, },
    REGINFO_SENTINEL
};

static const ARMCPRegInfo cache_test_clean_cp_reginfo[] = {
    /* The cache test-and-clean instructions always return (1 << 30)
     * to indicate that there are no dirty cache lines.
     */
    { "TC_DCACHE", 15,7,10, 0,0,3, 0,
      ARM_CP_CONST | ARM_CP_NO_MIGRATE, PL0_R, NULL, (1 << 30) },
    { "TCI_DCACHE", 15,7,14, 0,0,3, 0,
      ARM_CP_CONST | ARM_CP_NO_MIGRATE, PL0_R, NULL, (1 << 30) },
    REGINFO_SENTINEL
};

static const ARMCPRegInfo strongarm_cp_reginfo[] = {
    /* Ignore ReadBuffer accesses */
    { "C9_READBUFFER", 15,9,CP_ANY, 0,CP_ANY,CP_ANY, 0,
      ARM_CP_CONST | ARM_CP_OVERRIDE | ARM_CP_NO_MIGRATE, PL1_RW, NULL, 0, },
    REGINFO_SENTINEL
};

static uint64_t mpidr_read(CPUARMState *env, const ARMCPRegInfo *ri)
{
    CPUState *cs = CPU(arm_env_get_cpu(env));
    uint32_t mpidr = cs->cpu_index;
    /* We don't support setting cluster ID ([8..11]) (known as Aff1
     * in later ARM ARM versions), or any of the higher affinity level fields,
     * so these bits always RAZ.
     */
    if (arm_feature(env, ARM_FEATURE_V7MP)) {
        mpidr |= (1U << 31);
        /* Cores which are uniprocessor (non-coherent)
         * but still implement the MP extensions set
         * bit 30. (For instance, A9UP.) However we do
         * not currently model any of those cores.
         */
    }
    return mpidr;
}

static const ARMCPRegInfo mpidr_cp_reginfo[] = {
    { "MPIDR", 0,0,0, 3,0,5, ARM_CP_STATE_BOTH,
      ARM_CP_NO_MIGRATE, PL1_R, NULL, 0, 0,
      NULL, mpidr_read, },
    REGINFO_SENTINEL
};

static const ARMCPRegInfo lpae_cp_reginfo[] = {
    /* NOP AMAIR0/1: the override is because these clash with the rather
     * broadly specified TLB_LOCKDOWN entry in the generic cp_reginfo.
     */
    { "AMAIR0", 0,10,3, 3,0,0, ARM_CP_STATE_BOTH,
      ARM_CP_CONST | ARM_CP_OVERRIDE, PL1_RW, NULL, 0 },
    /* AMAIR1 is mapped to AMAIR_EL1[63:32] */
    { "AMAIR1", 15,10,3, 0,0,1, 0,
      ARM_CP_CONST | ARM_CP_OVERRIDE, PL1_RW, NULL, 0 },
    { "PAR", 15, 0,7, 0,0, 0, 0,
      ARM_CP_64BIT, PL1_RW, NULL, 0, offsetof(CPUARMState, cp15.par_el1), },
    { "TTBR0", 15, 0,2, 0,0, 0, 0,
      ARM_CP_64BIT | ARM_CP_NO_MIGRATE, PL1_RW, NULL, 0, offsetof(CPUARMState, cp15.ttbr0_el1),
      NULL, NULL, vmsa_ttbr_write, NULL,NULL, arm_cp_reset_ignore },
    { "TTBR1", 15, 0,2, 0,1, 0, 0,
      ARM_CP_64BIT | ARM_CP_NO_MIGRATE, PL1_RW, NULL, 0, offsetof(CPUARMState, cp15.ttbr1_el1),
      NULL, NULL, vmsa_ttbr_write, NULL,NULL, arm_cp_reset_ignore },
    REGINFO_SENTINEL
};

static uint64_t aa64_fpcr_read(CPUARMState *env, const ARMCPRegInfo *ri)
{
    return vfp_get_fpcr(env);
}

static void aa64_fpcr_write(CPUARMState *env, const ARMCPRegInfo *ri,
                            uint64_t value)
{
    vfp_set_fpcr(env, value);
}

static uint64_t aa64_fpsr_read(CPUARMState *env, const ARMCPRegInfo *ri)
{
    return vfp_get_fpsr(env);
}

static void aa64_fpsr_write(CPUARMState *env, const ARMCPRegInfo *ri,
                            uint64_t value)
{
    vfp_set_fpsr(env, value);
}

static CPAccessResult aa64_daif_access(CPUARMState *env, const ARMCPRegInfo *ri)
{
    if (arm_current_el(env) == 0 && !(env->cp15.c1_sys & SCTLR_UMA)) {
        return CP_ACCESS_TRAP;
    }
    return CP_ACCESS_OK;
}

static void aa64_daif_write(CPUARMState *env, const ARMCPRegInfo *ri,
                            uint64_t value)
{
    env->daif = value & PSTATE_DAIF;
}

static CPAccessResult aa64_cacheop_access(CPUARMState *env,
                                          const ARMCPRegInfo *ri)
{
    /* Cache invalidate/clean: NOP, but EL0 must UNDEF unless
     * SCTLR_EL1.UCI is set.
     */
    if (arm_current_el(env) == 0 && !(env->cp15.c1_sys & SCTLR_UCI)) {
        return CP_ACCESS_TRAP;
    }
    return CP_ACCESS_OK;
}

/* See: D4.7.2 TLB maintenance requirements and the TLB maintenance instructions
 * Page D4-1736 (DDI0487A.b)
 */

static void tlbi_aa64_va_write(CPUARMState *env, const ARMCPRegInfo *ri,
                               uint64_t value)
{
    /* Invalidate by VA (AArch64 version) */
    ARMCPU *cpu = arm_env_get_cpu(env);
    uint64_t pageaddr = sextract64(value << 12, 0, 56);

    tlb_flush_page(CPU(cpu), pageaddr);
}

static void tlbi_aa64_vaa_write(CPUARMState *env, const ARMCPRegInfo *ri,
                                uint64_t value)
{
    /* Invalidate by VA, all ASIDs (AArch64 version) */
    ARMCPU *cpu = arm_env_get_cpu(env);
    uint64_t pageaddr = sextract64(value << 12, 0, 56);

    tlb_flush_page(CPU(cpu), pageaddr);
}

static void tlbi_aa64_asid_write(CPUARMState *env, const ARMCPRegInfo *ri,
                                 uint64_t value)
{
    /* Invalidate by ASID (AArch64 version) */
    ARMCPU *cpu = arm_env_get_cpu(env);
    int asid = extract64(value, 48, 16);
    tlb_flush(CPU(cpu), asid == 0);
}

static void tlbi_aa64_va_is_write(CPUARMState *env, const ARMCPRegInfo *ri,
                                  uint64_t value)
{
    //uint64_t pageaddr = sextract64(value << 12, 0, 56);
    //struct uc_struct *uc = env->uc;
    // TODO: issue #642
    // tlb_flush(other_cpu, pageaddr);
}

static void tlbi_aa64_vaa_is_write(CPUARMState *env, const ARMCPRegInfo *ri,
                                  uint64_t value)
{
    //uint64_t pageaddr = sextract64(value << 12, 0, 56);
    //struct uc_struct *uc = env->uc;
    // TODO: issue #642
    // tlb_flush(other_cpu, pageaddr);
}

static void tlbi_aa64_asid_is_write(CPUARMState *env, const ARMCPRegInfo *ri,
                                  uint64_t value)
{
    //int asid = extract64(value, 48, 16);
    //struct uc_struct *uc = env->uc;
    // TODO: issue #642
    // tlb_flush(other_cpu, asid == 0);
}

static CPAccessResult aa64_zva_access(CPUARMState *env, const ARMCPRegInfo *ri)
{
    /* We don't implement EL2, so the only control on DC ZVA is the
     * bit in the SCTLR which can prohibit access for EL0.
     */
    if (arm_current_el(env) == 0 && !(env->cp15.c1_sys & SCTLR_DZE)) {
        return CP_ACCESS_TRAP;
    }
    return CP_ACCESS_OK;
}

static uint64_t aa64_dczid_read(CPUARMState *env, const ARMCPRegInfo *ri)
{
    ARMCPU *cpu = arm_env_get_cpu(env);
    int dzp_bit = 1 << 4;

    /* DZP indicates whether DC ZVA access is allowed */
    if (aa64_zva_access(env, NULL) == CP_ACCESS_OK) {
        dzp_bit = 0;
    }
    return cpu->dcz_blocksize | dzp_bit;
}

static CPAccessResult sp_el0_access(CPUARMState *env, const ARMCPRegInfo *ri)
{
    if (!(env->pstate & PSTATE_SP)) {
        /* Access to SP_EL0 is undefined if it's being used as
         * the stack pointer.
         */
        return CP_ACCESS_TRAP_UNCATEGORIZED;
    }
    return CP_ACCESS_OK;
}

static uint64_t spsel_read(CPUARMState *env, const ARMCPRegInfo *ri)
{
    return env->pstate & PSTATE_SP;
}

static void spsel_write(CPUARMState *env, const ARMCPRegInfo *ri, uint64_t val)
{
    update_spsel(env, val);
}

static const ARMCPRegInfo v8_cp_reginfo[] = {
    /* Minimal set of EL0-visible registers. This will need to be expanded
     * significantly for system emulation of AArch64 CPUs.
     */
    { "NZCV", 0,4,2, 3,3,0, ARM_CP_STATE_AA64,
      ARM_CP_NZCV, PL0_RW,  },
    { "DAIF", 0,4,2, 3,3,1, ARM_CP_STATE_AA64,
      ARM_CP_NO_MIGRATE, PL0_RW, NULL, 0, offsetof(CPUARMState, daif),
      aa64_daif_access, NULL, aa64_daif_write, NULL,NULL, arm_cp_reset_ignore },
    { "FPCR", 0,4,4, 3,3,0, ARM_CP_STATE_AA64,
      0, PL0_RW, NULL, 0, 0,
      NULL, aa64_fpcr_read, aa64_fpcr_write },
    { "FPSR", 0,4,4, 3,3,1, ARM_CP_STATE_AA64,
      0, PL0_RW, NULL, 0, 0,
      NULL, aa64_fpsr_read, aa64_fpsr_write },
    { "DCZID_EL0", 0,0,0, 3,3,7, ARM_CP_STATE_AA64,
      ARM_CP_NO_MIGRATE, PL0_R, NULL, 0, 0,
      NULL, aa64_dczid_read },
    { "DC_ZVA", 0,7,4, 1,3,1, ARM_CP_STATE_AA64,
      ARM_CP_DC_ZVA, PL0_W, NULL, 0, 0,
#ifndef CONFIG_USER_ONLY
      /* Avoid overhead of an access check that always passes in user-mode */
      aa64_zva_access,
#endif
    },
    { "CURRENTEL", 0,4,2, 3,0,2, ARM_CP_STATE_AA64,
      ARM_CP_CURRENTEL, PL1_R, },
    /* Cache ops: all NOPs since we don't emulate caches */
    { "IC_IALLUIS", 0,7,1, 1,0,0, ARM_CP_STATE_AA64,
      ARM_CP_NOP, PL1_W, },
    { "IC_IALLU", 0,7,5, 1,0,0, ARM_CP_STATE_AA64,
      ARM_CP_NOP, PL1_W, },
    { "IC_IVAU", 0,7,5, 1,3,1, ARM_CP_STATE_AA64,
      ARM_CP_NOP, PL0_W, NULL, 0, 0,
      aa64_cacheop_access },
    { "DC_IVAC", 0,7,6, 1,0,1, ARM_CP_STATE_AA64,
      ARM_CP_NOP, PL1_W, },
    { "DC_ISW", 0,7,6, 1,0,2, ARM_CP_STATE_AA64,
      ARM_CP_NOP, PL1_W, },
    { "DC_CVAC", 0,7,10, 1,3,1, ARM_CP_STATE_AA64,
      ARM_CP_NOP, PL0_W, NULL, 0, 0,
      aa64_cacheop_access },
    { "DC_CSW", 0,7,10, 1,0,2, ARM_CP_STATE_AA64,
      ARM_CP_NOP, PL1_W, },
    { "DC_CVAU", 0,7,11, 1,3,1, ARM_CP_STATE_AA64,
      ARM_CP_NOP, PL0_W, NULL, 0, 0,
      aa64_cacheop_access },
    { "DC_CIVAC", 0,7,14, 1,3,1, ARM_CP_STATE_AA64,
      ARM_CP_NOP, PL0_W,  NULL, 0, 0,
      aa64_cacheop_access },
    { "DC_CISW", 0,7,14, 1,0,2, ARM_CP_STATE_AA64,
      ARM_CP_NOP, PL1_W,  },
    /* TLBI operations */
    { "TLBI_VMALLE1IS", 0,8,3, 1,0,0, ARM_CP_STATE_AA64,
      ARM_CP_NO_MIGRATE, PL1_W, NULL, 0, 0,
      NULL, NULL, tlbiall_is_write },
    { "TLBI_VAE1IS", 0,8,3, 1,0,1, ARM_CP_STATE_AA64,
      ARM_CP_NO_MIGRATE, PL1_W, NULL, 0, 0,
      NULL, NULL, tlbi_aa64_va_is_write },
    { "TLBI_ASIDE1IS", 0,8,3, 1,0,2, ARM_CP_STATE_AA64,
      ARM_CP_NO_MIGRATE, PL1_W, NULL, 0, 0,
      NULL, NULL, tlbi_aa64_asid_is_write },
    { "TLBI_VAAE1IS", 0,8,3, 1,0,3, ARM_CP_STATE_AA64,
      ARM_CP_NO_MIGRATE, PL1_W, NULL, 0, 0,
      NULL, NULL, tlbi_aa64_vaa_is_write },
    { "TLBI_VALE1IS", 0,8,3, 1,0,5, ARM_CP_STATE_AA64,
      ARM_CP_NO_MIGRATE, PL1_W, NULL, 0, 0,
      NULL, NULL, tlbi_aa64_va_is_write },
    { "TLBI_VAALE1IS", 0,8,3, 1,0,7, ARM_CP_STATE_AA64,
      ARM_CP_NO_MIGRATE, PL1_W, NULL, 0, 0,
      NULL, NULL, tlbi_aa64_vaa_is_write },
    { "TLBI_VMALLE1", 0,8,7, 1,0,0, ARM_CP_STATE_AA64,
      ARM_CP_NO_MIGRATE, PL1_W, NULL, 0, 0,
      NULL, NULL, tlbiall_write },
    { "TLBI_VAE1", 0,8,7, 1,0,1, ARM_CP_STATE_AA64,
      ARM_CP_NO_MIGRATE, PL1_W, NULL, 0, 0,
      NULL, NULL, tlbi_aa64_va_write },
    { "TLBI_ASIDE1", 0,8,7, 1,0,2, ARM_CP_STATE_AA64,
      ARM_CP_NO_MIGRATE, PL1_W, NULL, 0, 0,
      NULL, NULL, tlbi_aa64_asid_write },
    { "TLBI_VAAE1", 0,8,7, 1,0,3, ARM_CP_STATE_AA64,
      ARM_CP_NO_MIGRATE, PL1_W, NULL, 0, 0,
      NULL, NULL, tlbi_aa64_vaa_write },
    { "TLBI_VALE1", 0,8,7, 1,0,5, ARM_CP_STATE_AA64,
      ARM_CP_NO_MIGRATE, PL1_W, NULL, 0, 0,
      NULL, NULL, tlbi_aa64_va_write },
    { "TLBI_VAALE1", 0,8,7, 1,0,7, ARM_CP_STATE_AA64,
      ARM_CP_NO_MIGRATE, PL1_W, NULL, 0, 0,
      NULL, NULL, tlbi_aa64_vaa_write },
#ifndef CONFIG_USER_ONLY
    /* 64 bit address translation operations */
    { "AT_S1E1R", 0,7,8, 1,0,0, ARM_CP_STATE_AA64,
      ARM_CP_NO_MIGRATE, PL1_W, NULL, 0, 0,
      NULL, NULL, ats_write },
    { "AT_S1E1W", 0,7,8, 1,0,1, ARM_CP_STATE_AA64,
      ARM_CP_NO_MIGRATE, PL1_W, NULL, 0, 0,
      NULL, NULL, ats_write },
    { "AT_S1E0R", 0,7,8, 1,0,2, ARM_CP_STATE_AA64,
      ARM_CP_NO_MIGRATE, PL1_W, NULL, 0, 0,
      NULL, NULL, ats_write },
    { "AT_S1E0W", 0,7,8, 1,0,3, ARM_CP_STATE_AA64,
      ARM_CP_NO_MIGRATE, PL1_W, NULL, 0, 0,
      NULL, NULL, ats_write },
#endif
    /* TLB invalidate last level of translation table walk */
    { "TLBIMVALIS", 15,8,3, 0,0,5, 0,
      ARM_CP_NO_MIGRATE, PL1_W, NULL, 0, 0,
      NULL, NULL, tlbimva_is_write },
    { "TLBIMVAALIS", 15,8,3, 0,0,7, 0,
      ARM_CP_NO_MIGRATE, PL1_W, NULL, 0, 0,
      NULL, NULL, tlbimvaa_is_write },
    { "TLBIMVAL", 15,8,7, 0,0,5, 0,
      ARM_CP_NO_MIGRATE, PL1_W, NULL, 0, 0,
      NULL, NULL, tlbimva_write },
    { "TLBIMVAAL", 15,8,7, 0,0,7, 0,
      ARM_CP_NO_MIGRATE, PL1_W, NULL, 0, 0,
      NULL, NULL, tlbimvaa_write },
    /* 32 bit cache operations */
    { "ICIALLUIS", 15,7,1, 0,0,0, 0,
      ARM_CP_NOP, PL1_W },
    { "BPIALLUIS", 15,7,1, 0,0,6, 0,
      ARM_CP_NOP, PL1_W },
    { "ICIALLU", 15,7,5, 0,0,0, 0,
      ARM_CP_NOP, PL1_W },
    { "ICIMVAU", 15,7,5, 0,0,1, 0,
      ARM_CP_NOP, PL1_W },
    { "BPIALL", 15,7,5, 0,0,6, 0,
      ARM_CP_NOP, PL1_W },
    { "BPIMVA", 15,7,5, 0,0,7, 0,
      ARM_CP_NOP, PL1_W },
    { "DCIMVAC", 15,7,6, 0,0,1, 0,
      ARM_CP_NOP, PL1_W },
    { "DCISW", 15,7,6, 0,0,2, 0,
      ARM_CP_NOP, PL1_W },
    { "DCCMVAC", 15,7,10, 0,0,1, 0,
      ARM_CP_NOP, PL1_W },
    { "DCCSW", 15,7,10, 0,0,2, 0,
      ARM_CP_NOP, PL1_W },
    { "DCCMVAU", 15,7,11, 0,0,1, 0,
      ARM_CP_NOP, PL1_W },
    { "DCCIMVAC", 15,7,14, 0,0,1, 0,
      ARM_CP_NOP, PL1_W },
    { "DCCISW", 15,7,14, 0,0,2, 0,
      ARM_CP_NOP, PL1_W },
    /* MMU Domain access control / MPU write buffer control */
    { "DACR", 15,3,0, 0,0,0, 0,
      0, PL1_RW, NULL, 0, offsetof(CPUARMState, cp15.c3),
      NULL, NULL,dacr_write, NULL,raw_write, },
    { "ELR_EL1", 0,4,0, 3,0,1, ARM_CP_STATE_AA64,
      ARM_CP_NO_MIGRATE, PL1_RW, NULL, 0, offsetof(CPUARMState, elr_el[1]) },
    { "SPSR_EL1", 0,4,0, 3,0,0, ARM_CP_STATE_AA64,
      ARM_CP_NO_MIGRATE, PL1_RW, NULL, 0, offsetof(CPUARMState, banked_spsr[0]) },
    /* We rely on the access checks not allowing the guest to write to the
     * state field when SPSel indicates that it's being used as the stack
     * pointer.
     */
    { "SP_EL0", 0,4,1, 3,0,0, ARM_CP_STATE_AA64,
      ARM_CP_NO_MIGRATE, PL1_RW, NULL, 0, offsetof(CPUARMState, sp_el[0]),
      sp_el0_access, },
    { "SPSel", 0,4,2, 3,0,0, ARM_CP_STATE_AA64,
      ARM_CP_NO_MIGRATE, PL1_RW, NULL, 0, 0,
      NULL, spsel_read, spsel_write },
    REGINFO_SENTINEL
};

/* Used to describe the behaviour of EL2 regs when EL2 does not exist.  */
static const ARMCPRegInfo v8_el3_no_el2_cp_reginfo[] = {
    { "VBAR_EL2", 0,12,0, 3,4,0, ARM_CP_STATE_AA64,
      0, PL2_RW, NULL, 0, 0,
      NULL, arm_cp_read_zero, arm_cp_write_ignore },
    { "HCR_EL2", 0,1,1, 3,4,0, ARM_CP_STATE_AA64,
      ARM_CP_NO_MIGRATE, PL2_RW, NULL, 0, 0,
      NULL, arm_cp_read_zero, arm_cp_write_ignore },
    REGINFO_SENTINEL
};

static void hcr_write(CPUARMState *env, const ARMCPRegInfo *ri, uint64_t value)
{
    ARMCPU *cpu = arm_env_get_cpu(env);
    uint64_t valid_mask = HCR_MASK;

    if (arm_feature(env, ARM_FEATURE_EL3)) {
        valid_mask &= ~HCR_HCD;
    } else {
        valid_mask &= ~HCR_TSC;
    }

    /* Clear RES0 bits.  */
    value &= valid_mask;

    /* These bits change the MMU setup:
     * HCR_VM enables stage 2 translation
     * HCR_PTW forbids certain page-table setups
     * HCR_DC Disables stage1 and enables stage2 translation
     */
    if ((raw_read(env, ri) ^ value) & (HCR_VM | HCR_PTW | HCR_DC)) {
        tlb_flush(CPU(cpu), 1);
    }
    raw_write(env, ri, value);
}

static const ARMCPRegInfo v8_el2_cp_reginfo[] = {
    { "HCR_EL2", 0,1,1, 3,4,0, ARM_CP_STATE_AA64,
      0, PL2_RW, NULL, 0, offsetof(CPUARMState, cp15.hcr_el2),
      NULL, NULL, hcr_write },
    { "ELR_EL2", 0,4,0, 3,4,1, ARM_CP_STATE_AA64,
      ARM_CP_NO_MIGRATE, PL2_RW, NULL, 0, offsetof(CPUARMState, elr_el[2]) },
    { "ESR_EL2", 0,5,2, 3,4,0, ARM_CP_STATE_AA64,
      ARM_CP_NO_MIGRATE, PL2_RW, NULL, 0, offsetof(CPUARMState, cp15.esr_el[2]) },
    { "FAR_EL2", 0,6,0, 3,4,0, ARM_CP_STATE_AA64,
      0, PL2_RW, NULL, 0, offsetof(CPUARMState, cp15.far_el[2]) },
    { "SPSR_EL2", 0,4,0, 3,4,0, ARM_CP_STATE_AA64,
      ARM_CP_NO_MIGRATE, PL2_RW, NULL, 0, offsetof(CPUARMState, banked_spsr[6]) },
    { "VBAR_EL2", 0,12,0, 3,4,0, ARM_CP_STATE_AA64,
      0, PL2_RW, NULL, 0, offsetof(CPUARMState, cp15.vbar_el[2]),
      NULL, NULL, vbar_write, },
    REGINFO_SENTINEL
};

static const ARMCPRegInfo v8_el3_cp_reginfo[] = {
    { "ELR_EL3", 0,4,0, 3,6,1, ARM_CP_STATE_AA64,
      ARM_CP_NO_MIGRATE, PL3_RW, NULL, 0, offsetof(CPUARMState, elr_el[3]) },
    { "ESR_EL3", 0,5,2, 3,6,0, ARM_CP_STATE_AA64,
      ARM_CP_NO_MIGRATE, PL3_RW, NULL, 0, offsetof(CPUARMState, cp15.esr_el[3]) },
    { "FAR_EL3", 0,6,0, 3,6,0, ARM_CP_STATE_AA64,
      0, PL3_RW, NULL, 0, offsetof(CPUARMState, cp15.far_el[3]) },
    { "SPSR_EL3", 0,4,0, 3,6,0, ARM_CP_STATE_AA64,
      ARM_CP_NO_MIGRATE, PL3_RW, NULL, 0, offsetof(CPUARMState, banked_spsr[7]) },
    { "VBAR_EL3", 0,12,0, 3,6,0, ARM_CP_STATE_AA64,
      0, PL3_RW, NULL, 0, offsetof(CPUARMState, cp15.vbar_el[3]),
      NULL, NULL, vbar_write, },
    { "SCR_EL3", 0,1,1, 3,6,0, ARM_CP_STATE_AA64,
      ARM_CP_NO_MIGRATE, PL3_RW, NULL, 0, offsetof(CPUARMState, cp15.scr_el3),
      NULL, NULL, scr_write },
    REGINFO_SENTINEL
};

static void sctlr_write(CPUARMState *env, const ARMCPRegInfo *ri,
                        uint64_t value)
{
    ARMCPU *cpu = arm_env_get_cpu(env);

    if (raw_read(env, ri) == value) {
        /* Skip the TLB flush if nothing actually changed; Linux likes
         * to do a lot of pointless SCTLR writes.
         */
        return;
    }

    raw_write(env, ri, value);
    /* ??? Lots of these bits are not implemented.  */
    /* This may enable/disable the MMU, so do a TLB flush.  */
    tlb_flush(CPU(cpu), 1);
}

static CPAccessResult ctr_el0_access(CPUARMState *env, const ARMCPRegInfo *ri)
{
    /* Only accessible in EL0 if SCTLR.UCT is set (and only in AArch64,
     * but the AArch32 CTR has its own reginfo struct)
     */
    if (arm_current_el(env) == 0 && !(env->cp15.c1_sys & SCTLR_UCT)) {
        return CP_ACCESS_TRAP;
    }
    return CP_ACCESS_OK;
}

static const ARMCPRegInfo debug_cp_reginfo[] = {
    /* DBGDRAR, DBGDSAR: always RAZ since we don't implement memory mapped
     * debug components. The AArch64 version of DBGDRAR is named MDRAR_EL1;
     * unlike DBGDRAR it is never accessible from EL0.
     * DBGDSAR is deprecated and must RAZ from v8 anyway, so it has no AArch64
     * accessor.
     */
    { "DBGDRAR", 14,1,0, 0,0,0, 0,
      ARM_CP_CONST, PL0_R, NULL, 0 },
    { "MDRAR_EL1", 0,1,0, 2,0,0, ARM_CP_STATE_AA64,
      ARM_CP_CONST, PL1_R, NULL, 0 },
    { "DBGDSAR", 14,2,0, 0,0,0, 0,
      ARM_CP_CONST, PL0_R, NULL, 0 },
    /* Monitor debug system control register; the 32-bit alias is DBGDSCRext. */
    { "MDSCR_EL1", 14,0,2, 2,0,2, ARM_CP_STATE_BOTH,
      0, PL1_RW, NULL, 0, offsetof(CPUARMState, cp15.mdscr_el1), },
    /* MDCCSR_EL0, aka DBGDSCRint. This is a read-only mirror of MDSCR_EL1.
     * We don't implement the configurable EL0 access.
     */
    { "MDCCSR_EL0", 14,0,1, 2,0,0, ARM_CP_STATE_BOTH,
      ARM_CP_NO_MIGRATE, PL1_R, NULL, 0, offsetof(CPUARMState, cp15.mdscr_el1),
      NULL,NULL,NULL,NULL,NULL, arm_cp_reset_ignore },
    /* We define a dummy WI OSLAR_EL1, because Linux writes to it. */
    { "OSLAR_EL1", 14,1,0, 2,0,4, ARM_CP_STATE_BOTH,
      ARM_CP_NOP, PL1_W, },
    /* Dummy OSDLR_EL1: 32-bit Linux will read this */
    { "OSDLR_EL1", 14,1,3, 2,0,4, ARM_CP_STATE_BOTH,
      ARM_CP_NOP, PL1_RW, },
    /* Dummy DBGVCR: Linux wants to clear this on startup, but we don't
     * implement vector catch debug events yet.
     */
    { "DBGVCR", 14,0,7, 0,0,0, 0,
      ARM_CP_NOP, PL1_RW, },
    REGINFO_SENTINEL
};

static const ARMCPRegInfo debug_lpae_cp_reginfo[] = {
    /* 64 bit access versions of the (dummy) debug registers */
    { "DBGDRAR", 14, 0,1, 0,0, 0, 0,
      ARM_CP_CONST|ARM_CP_64BIT, PL0_R, NULL, 0 },
    { "DBGDSAR", 14, 0,2, 0,0, 0, 0,
      ARM_CP_CONST|ARM_CP_64BIT, PL0_R, NULL, 0 },
    REGINFO_SENTINEL
};

void hw_watchpoint_update(ARMCPU *cpu, int n)
{
    CPUARMState *env = &cpu->env;
    vaddr len = 0;
    vaddr wvr = env->cp15.dbgwvr[n];
    uint64_t wcr = env->cp15.dbgwcr[n];
    int mask;
    int flags = BP_CPU | BP_STOP_BEFORE_ACCESS;

    if (env->cpu_watchpoint[n]) {
        cpu_watchpoint_remove_by_ref(CPU(cpu), env->cpu_watchpoint[n]);
        env->cpu_watchpoint[n] = NULL;
    }

    if (!extract64(wcr, 0, 1)) {
        /* E bit clear : watchpoint disabled */
        return;
    }

    switch (extract64(wcr, 3, 2)) {
    case 0:
        /* LSC 00 is reserved and must behave as if the wp is disabled */
        return;
    case 1:
        flags |= BP_MEM_READ;
        break;
    case 2:
        flags |= BP_MEM_WRITE;
        break;
    case 3:
        flags |= BP_MEM_ACCESS;
        break;
    }

    /* Attempts to use both MASK and BAS fields simultaneously are
     * CONSTRAINED UNPREDICTABLE; we opt to ignore BAS in this case,
     * thus generating a watchpoint for every byte in the masked region.
     */
    mask = extract64(wcr, 24, 4);
    if (mask == 1 || mask == 2) {
        /* Reserved values of MASK; we must act as if the mask value was
         * some non-reserved value, or as if the watchpoint were disabled.
         * We choose the latter.
         */
        return;
    } else if (mask) {
        /* Watchpoint covers an aligned area up to 2GB in size */
        len = 1ULL << mask;
        /* If masked bits in WVR are not zero it's CONSTRAINED UNPREDICTABLE
         * whether the watchpoint fires when the unmasked bits match; we opt
         * to generate the exceptions.
         */
        wvr &= ~(len - 1);
    } else {
        /* Watchpoint covers bytes defined by the byte address select bits */
        int bas = extract64(wcr, 5, 8);
        int basstart;

        if (bas == 0) {
            /* This must act as if the watchpoint is disabled */
            return;
        }

        if (extract64(wvr, 2, 1)) {
            /* Deprecated case of an only 4-aligned address. BAS[7:4] are
             * ignored, and BAS[3:0] define which bytes to watch.
             */
            bas &= 0xf;
        }
        /* The BAS bits are supposed to be programmed to indicate a contiguous
         * range of bytes. Otherwise it is CONSTRAINED UNPREDICTABLE whether
         * we fire for each byte in the word/doubleword addressed by the WVR.
         * We choose to ignore any non-zero bits after the first range of 1s.
         */
        basstart = ctz32(bas);
        len = cto32(bas >> (basstart & 0x1f));
        wvr += basstart;
    }

    cpu_watchpoint_insert(CPU(cpu), wvr, len, flags,
                          &env->cpu_watchpoint[n]);
}

void hw_watchpoint_update_all(ARMCPU *cpu)
{
    int i;
    CPUARMState *env = &cpu->env;

    /* Completely clear out existing QEMU watchpoints and our array, to
     * avoid possible stale entries following migration load.
     */
    cpu_watchpoint_remove_all(CPU(cpu), BP_CPU);
    memset(env->cpu_watchpoint, 0, sizeof(env->cpu_watchpoint));

    for (i = 0; i < ARRAY_SIZE(cpu->env.cpu_watchpoint); i++) {
        hw_watchpoint_update(cpu, i);
    }
}

static void dbgwvr_write(CPUARMState *env, const ARMCPRegInfo *ri,
                         uint64_t value)
{
    ARMCPU *cpu = arm_env_get_cpu(env);
    int i = ri->crm;

    /* Bits [63:49] are hardwired to the value of bit [48]; that is, the
     * register reads and behaves as if values written are sign extended.
     * Bits [1:0] are RES0.
     */
    value = sextract64(value, 0, 49) & ~3ULL;

    raw_write(env, ri, value);
    hw_watchpoint_update(cpu, i);
}

static void dbgwcr_write(CPUARMState *env, const ARMCPRegInfo *ri,
                         uint64_t value)
{
    ARMCPU *cpu = arm_env_get_cpu(env);
    int i = ri->crm;

    raw_write(env, ri, value);
    hw_watchpoint_update(cpu, i);
}

void hw_breakpoint_update(ARMCPU *cpu, int n)
{
    CPUARMState *env = &cpu->env;
    uint64_t bvr = env->cp15.dbgbvr[n];
    uint64_t bcr = env->cp15.dbgbcr[n];
    vaddr addr;
    int bt;
    int flags = BP_CPU;

    if (env->cpu_breakpoint[n]) {
        cpu_breakpoint_remove_by_ref(CPU(cpu), env->cpu_breakpoint[n]);
        env->cpu_breakpoint[n] = NULL;
    }

    if (!extract64(bcr, 0, 1)) {
        /* E bit clear : watchpoint disabled */
        return;
    }

    bt = extract64(bcr, 20, 4);

    switch (bt) {
    case 4: /* unlinked address mismatch (reserved if AArch64) */
    case 5: /* linked address mismatch (reserved if AArch64) */
        qemu_log_mask(LOG_UNIMP,
                      "arm: address mismatch breakpoint types not implemented");
        return;
    case 0: /* unlinked address match */
    case 1: /* linked address match */
    {
        /* Bits [63:49] are hardwired to the value of bit [48]; that is,
         * we behave as if the register was sign extended. Bits [1:0] are
         * RES0. The BAS field is used to allow setting breakpoints on 16
         * bit wide instructions; it is CONSTRAINED UNPREDICTABLE whether
         * a bp will fire if the addresses covered by the bp and the addresses
         * covered by the insn overlap but the insn doesn't start at the
         * start of the bp address range. We choose to require the insn and
         * the bp to have the same address. The constraints on writing to
         * BAS enforced in dbgbcr_write mean we have only four cases:
         *  0b0000  => no breakpoint
         *  0b0011  => breakpoint on addr
         *  0b1100  => breakpoint on addr + 2
         *  0b1111  => breakpoint on addr
         * See also figure D2-3 in the v8 ARM ARM (DDI0487A.c).
         */
        int bas = extract64(bcr, 5, 4);
        addr = sextract64(bvr, 0, 49) & ~3ULL;
        if (bas == 0) {
            return;
        }
        if (bas == 0xc) {
            addr += 2;
        }
        break;
    }
    case 2: /* unlinked context ID match */
    case 8: /* unlinked VMID match (reserved if no EL2) */
    case 10: /* unlinked context ID and VMID match (reserved if no EL2) */
        qemu_log_mask(LOG_UNIMP,
                      "arm: unlinked context breakpoint types not implemented");
        return;
    case 9: /* linked VMID match (reserved if no EL2) */
    case 11: /* linked context ID and VMID match (reserved if no EL2) */
    case 3: /* linked context ID match */
    default:
        /* We must generate no events for Linked context matches (unless
         * they are linked to by some other bp/wp, which is handled in
         * updates for the linking bp/wp). We choose to also generate no events
         * for reserved values.
         */
        return;
    }

    cpu_breakpoint_insert(CPU(cpu), addr, flags, &env->cpu_breakpoint[n]);
}

void hw_breakpoint_update_all(ARMCPU *cpu)
{
    int i;
    CPUARMState *env = &cpu->env;

    /* Completely clear out existing QEMU breakpoints and our array, to
     * avoid possible stale entries following migration load.
     */
    cpu_breakpoint_remove_all(CPU(cpu), BP_CPU);
    memset(env->cpu_breakpoint, 0, sizeof(env->cpu_breakpoint));

    for (i = 0; i < ARRAY_SIZE(cpu->env.cpu_breakpoint); i++) {
        hw_breakpoint_update(cpu, i);
    }
}

static void dbgbvr_write(CPUARMState *env, const ARMCPRegInfo *ri,
                         uint64_t value)
{
    ARMCPU *cpu = arm_env_get_cpu(env);
    int i = ri->crm;

    raw_write(env, ri, value);
    hw_breakpoint_update(cpu, i);
}

static void dbgbcr_write(CPUARMState *env, const ARMCPRegInfo *ri,
                         uint64_t value)
{
    ARMCPU *cpu = arm_env_get_cpu(env);
    int i = ri->crm;

    /* BAS[3] is a read-only copy of BAS[2], and BAS[1] a read-only
     * copy of BAS[0].
     */
    value = deposit64(value, 6, 1, extract64(value, 5, 1));
    value = deposit64(value, 8, 1, extract64(value, 7, 1));

    raw_write(env, ri, value);
    hw_breakpoint_update(cpu, i);
}

static void define_debug_regs(ARMCPU *cpu)
{
    /* Define v7 and v8 architectural debug registers.
     * These are just dummy implementations for now.
     */
    int i;
    int wrps, brps, ctx_cmps;
    ARMCPRegInfo dbgdidr = {
        "DBGDIDR", 14,0,0, 0,0,0, 0,
        ARM_CP_CONST, PL0_R, NULL, cpu->dbgdidr,
    };

    /* Note that all these register fields hold "number of Xs minus 1". */
    brps = extract32(cpu->dbgdidr, 24, 4);
    wrps = extract32(cpu->dbgdidr, 28, 4);
    ctx_cmps = extract32(cpu->dbgdidr, 20, 4);

    assert(ctx_cmps <= brps);

    /* The DBGDIDR and ID_AA64DFR0_EL1 define various properties
     * of the debug registers such as number of breakpoints;
     * check that if they both exist then they agree.
     */
    if (arm_feature(&cpu->env, ARM_FEATURE_AARCH64)) {
        assert(extract32(cpu->id_aa64dfr0, 12, 4) == brps);
        assert(extract32(cpu->id_aa64dfr0, 20, 4) == wrps);
        assert(extract32(cpu->id_aa64dfr0, 28, 4) == ctx_cmps);
    }

    define_one_arm_cp_reg(cpu, &dbgdidr);
    define_arm_cp_regs(cpu, debug_cp_reginfo);

    if (arm_feature(&cpu->env, ARM_FEATURE_LPAE)) {
        define_arm_cp_regs(cpu, debug_lpae_cp_reginfo);
    }

    for (i = 0; i < brps + 1; i++) {
        ARMCPRegInfo dbgregs[] = {
            { "DBGBVR", 14,0,i, 2,0,4,ARM_CP_STATE_BOTH,
              0, PL1_RW, NULL, 0, offsetof(CPUARMState, cp15.dbgbvr[i]),
              NULL, NULL,dbgbvr_write, NULL,raw_write
            },
            { "DBGBCR", 14,0,i, 2,0,5, ARM_CP_STATE_BOTH,
              0, PL1_RW, NULL, 0, offsetof(CPUARMState, cp15.dbgbcr[i]),
              NULL, NULL,dbgbcr_write, NULL,raw_write
            },
            REGINFO_SENTINEL
        };
        define_arm_cp_regs(cpu, dbgregs);
    }

    for (i = 0; i < wrps + 1; i++) {
        ARMCPRegInfo dbgregs[] = {
            { "DBGWVR", 14,0,i, 2,0,6, ARM_CP_STATE_BOTH,
              0, PL1_RW, NULL, 0, offsetof(CPUARMState, cp15.dbgwvr[i]),
              NULL, NULL,dbgwvr_write, NULL,raw_write
            },
            { "DBGWCR", 14,0,i, 2,0,7, ARM_CP_STATE_BOTH,
              0, PL1_RW, NULL, 0, offsetof(CPUARMState, cp15.dbgwcr[i]),
              NULL, NULL,dbgwcr_write, NULL,raw_write
            },
            REGINFO_SENTINEL
        };
        define_arm_cp_regs(cpu, dbgregs);
    }
}

void register_cp_regs_for_features(ARMCPU *cpu)
{
    /* Register all the coprocessor registers based on feature bits */
    CPUARMState *env = &cpu->env;
    if (arm_feature(env, ARM_FEATURE_M)) {
        /* M profile has no coprocessor registers */
        return;
    }

    define_arm_cp_regs(cpu, cp_reginfo);
    if (!arm_feature(env, ARM_FEATURE_V8)) {
        /* Must go early as it is full of wildcards that may be
         * overridden by later definitions.
         */
        define_arm_cp_regs(cpu, not_v8_cp_reginfo);
    }

    if (arm_feature(env, ARM_FEATURE_V6)) {
        /* The ID registers all have impdef reset values */
        ARMCPRegInfo v6_idregs[] = {
            { "ID_PFR0", 0,0,1, 3,0,0, ARM_CP_STATE_BOTH,
              ARM_CP_CONST, PL1_R, NULL, cpu->id_pfr0 },
            { "ID_PFR1", 0,0,1, 3,0,1, ARM_CP_STATE_BOTH,
              ARM_CP_CONST, PL1_R, NULL, cpu->id_pfr1 },
            { "ID_DFR0", 0,0,1, 3,0,2, ARM_CP_STATE_BOTH,
              ARM_CP_CONST, PL1_R, NULL, cpu->id_dfr0 },
            { "ID_AFR0", 0,0,1, 3,0,3, ARM_CP_STATE_BOTH,
              ARM_CP_CONST, PL1_R, NULL, cpu->id_afr0 },
            { "ID_MMFR0", 0,0,1, 3,0,4, ARM_CP_STATE_BOTH,
              ARM_CP_CONST, PL1_R, NULL, cpu->id_mmfr0 },
            { "ID_MMFR1", 0,0,1, 3,0,5, ARM_CP_STATE_BOTH,
              ARM_CP_CONST, PL1_R, NULL, cpu->id_mmfr1 },
            { "ID_MMFR2", 0,0,1, 3,0,6, ARM_CP_STATE_BOTH,
              ARM_CP_CONST, PL1_R, NULL, cpu->id_mmfr2 },
            { "ID_MMFR3", 0,0,1, 3,0,7, ARM_CP_STATE_BOTH,
              ARM_CP_CONST, PL1_R, NULL, cpu->id_mmfr3 },
            { "ID_ISAR0", 0,0,2, 3,0,0, ARM_CP_STATE_BOTH,
              ARM_CP_CONST, PL1_R, NULL, cpu->id_isar0 },
            { "ID_ISAR1", 0,0,2, 3,0,1, ARM_CP_STATE_BOTH,
              ARM_CP_CONST, PL1_R, NULL, cpu->id_isar1 },
            { "ID_ISAR2", 0,0,2, 3,0,2, ARM_CP_STATE_BOTH,
              ARM_CP_CONST, PL1_R, NULL, cpu->id_isar2 },
            { "ID_ISAR3", 0,0,2, 3,0,3, ARM_CP_STATE_BOTH,
              ARM_CP_CONST, PL1_R, NULL, cpu->id_isar3 },
            { "ID_ISAR4", 0,0,2, 3,0,4, ARM_CP_STATE_BOTH,
              ARM_CP_CONST, PL1_R, NULL, cpu->id_isar4 },
            { "ID_ISAR5", 0,0,2, 3,0,5, ARM_CP_STATE_BOTH,
              ARM_CP_CONST, PL1_R, NULL, cpu->id_isar5 },
            /* 6..7 are as yet unallocated and must RAZ */
            { "ID_ISAR6", 15,0,2, 0,0,6, 0,
              ARM_CP_CONST, PL1_R, NULL, 0 },
            { "ID_ISAR7", 15,0,2, 0,0,7, 0,
              ARM_CP_CONST, PL1_R, NULL, 0 },
            REGINFO_SENTINEL
        };
        define_arm_cp_regs(cpu, v6_idregs);
        define_arm_cp_regs(cpu, v6_cp_reginfo);
    } else {
        define_arm_cp_regs(cpu, not_v6_cp_reginfo);
    }
    if (arm_feature(env, ARM_FEATURE_V6K)) {
        define_arm_cp_regs(cpu, v6k_cp_reginfo);
    }
    if (arm_feature(env, ARM_FEATURE_V7MP)) {
        define_arm_cp_regs(cpu, v7mp_cp_reginfo);
    }
    if (arm_feature(env, ARM_FEATURE_V7)) {
        ARMCPRegInfo clidr = {
            "CLIDR", 0,0,0, 3,1,1, ARM_CP_STATE_BOTH,
            ARM_CP_CONST, PL1_R, NULL, cpu->clidr
        };
        /* v7 performance monitor control register: same implementor
         * field as main ID register, and we implement only the cycle
         * count register.
         */
#ifndef CONFIG_USER_ONLY
        ARMCPRegInfo pmcr = {
            "PMCR", 15,9,12, 0,0,0, 0,
            ARM_CP_IO | ARM_CP_NO_MIGRATE, PL0_RW, NULL, 0, offsetoflow32(CPUARMState, cp15.c9_pmcr),
            pmreg_access, NULL,pmcr_write, NULL,raw_write,
        };
        ARMCPRegInfo pmcr64 = {
            "PMCR_EL0", 0,9,12, 3,3,0, ARM_CP_STATE_AA64,
            ARM_CP_IO, PL0_RW, NULL, cpu->midr & 0xff000000, offsetof(CPUARMState, cp15.c9_pmcr),
            pmreg_access, NULL,pmcr_write, NULL,raw_write,
        };
        define_one_arm_cp_reg(cpu, &pmcr);
        define_one_arm_cp_reg(cpu, &pmcr64);
#endif
        define_one_arm_cp_reg(cpu, &clidr);
        define_arm_cp_regs(cpu, v7_cp_reginfo);
        define_debug_regs(cpu);
    } else {
        define_arm_cp_regs(cpu, not_v7_cp_reginfo);
    }
    if (arm_feature(env, ARM_FEATURE_V8)) {
        /* AArch64 ID registers, which all have impdef reset values */
        ARMCPRegInfo v8_idregs[] = {
            { "ID_AA64PFR0_EL1", 0,0,4, 3,0,0, ARM_CP_STATE_AA64,
              ARM_CP_CONST, PL1_R, NULL, cpu->id_aa64pfr0 },
            { "ID_AA64PFR1_EL1", 0,0,4, 3,0,1, ARM_CP_STATE_AA64,
              ARM_CP_CONST, PL1_R, NULL, cpu->id_aa64pfr1},
            { "ID_AA64DFR0_EL1", 0,0,5, 3,0,0, ARM_CP_STATE_AA64,
              ARM_CP_CONST, PL1_R, NULL,
              /* We mask out the PMUVer field, because we don't currently
               * implement the PMU. Not advertising it prevents the guest
               * from trying to use it and getting UNDEFs on registers we
               * don't implement.
               */
              cpu->id_aa64dfr0 & ~0xf00 },
            { "ID_AA64DFR1_EL1", 0,0,5, 3,0,1, ARM_CP_STATE_AA64,
              ARM_CP_CONST, PL1_R, NULL, cpu->id_aa64dfr1 },
            { "ID_AA64AFR0_EL1", 0,0,5, 3,0,4, ARM_CP_STATE_AA64,
              ARM_CP_CONST, PL1_R, NULL, cpu->id_aa64afr0 },
            { "ID_AA64AFR1_EL1", 0,0,5, 3,0,5, ARM_CP_STATE_AA64,
              ARM_CP_CONST, PL1_R, NULL, cpu->id_aa64afr1 },
            { "ID_AA64ISAR0_EL1", 0,0,6, 3,0,0, ARM_CP_STATE_AA64,
              ARM_CP_CONST, PL1_R, NULL, cpu->id_aa64isar0 },
            { "ID_AA64ISAR1_EL1", 0,0,6, 3,0,1, ARM_CP_STATE_AA64,
              ARM_CP_CONST, PL1_R, NULL, cpu->id_aa64isar1 },
            { "ID_AA64MMFR0_EL1", 0,0,7, 3,0,0, ARM_CP_STATE_AA64,
              ARM_CP_CONST, PL1_R, NULL, cpu->id_aa64mmfr0 },
            { "ID_AA64MMFR1_EL1", 0,0,7, 3,0,1, ARM_CP_STATE_AA64,
              ARM_CP_CONST, PL1_R, NULL, cpu->id_aa64mmfr1 },
            { "MVFR0_EL1", 0,0,3, 3,0,0, ARM_CP_STATE_AA64,
              ARM_CP_CONST, PL1_R, NULL, cpu->mvfr0 },
            { "MVFR1_EL1", 0,0,3, 3,0,1, ARM_CP_STATE_AA64,
              ARM_CP_CONST, PL1_R, NULL, cpu->mvfr1 },
            { "MVFR2_EL1", 0,0,3, 3,0,2, ARM_CP_STATE_AA64,
              ARM_CP_CONST, PL1_R, NULL, cpu->mvfr2 },
            REGINFO_SENTINEL
        };
        ARMCPRegInfo rvbar = {
            "RVBAR_EL1", 0,12,0, 3,0,2, ARM_CP_STATE_AA64,
            ARM_CP_CONST, PL1_R, NULL, cpu->rvbar
        };
        define_one_arm_cp_reg(cpu, &rvbar);
        define_arm_cp_regs(cpu, v8_idregs);
        define_arm_cp_regs(cpu, v8_cp_reginfo);
    }
    if (arm_feature(env, ARM_FEATURE_EL2)) {
        define_arm_cp_regs(cpu, v8_el2_cp_reginfo);
    } else {
        /* If EL2 is missing but higher ELs are enabled, we need to
         * register the no_el2 reginfos.
         */
        if (arm_feature(env, ARM_FEATURE_EL3)) {
            define_arm_cp_regs(cpu, v8_el3_no_el2_cp_reginfo);
        }
    }
    if (arm_feature(env, ARM_FEATURE_EL3)) {
        define_arm_cp_regs(cpu, v8_el3_cp_reginfo);
    }
    if (arm_feature(env, ARM_FEATURE_MPU)) {
        /* These are the MPU registers prior to PMSAv6. Any new
         * PMSA core later than the ARM946 will require that we
         * implement the PMSAv6 or PMSAv7 registers, which are
         * completely different.
         */
        assert(!arm_feature(env, ARM_FEATURE_V6));
        define_arm_cp_regs(cpu, pmsav5_cp_reginfo);
    } else {
        define_arm_cp_regs(cpu, vmsa_cp_reginfo);
    }
    if (arm_feature(env, ARM_FEATURE_THUMB2EE)) {
        define_arm_cp_regs(cpu, t2ee_cp_reginfo);
    }
    if (arm_feature(env, ARM_FEATURE_GENERIC_TIMER)) {
        define_arm_cp_regs(cpu, generic_timer_cp_reginfo);
    }
    if (arm_feature(env, ARM_FEATURE_VAPA)) {
        define_arm_cp_regs(cpu, vapa_cp_reginfo);
    }
    if (arm_feature(env, ARM_FEATURE_CACHE_TEST_CLEAN)) {
        define_arm_cp_regs(cpu, cache_test_clean_cp_reginfo);
    }
    if (arm_feature(env, ARM_FEATURE_CACHE_DIRTY_REG)) {
        define_arm_cp_regs(cpu, cache_dirty_status_cp_reginfo);
    }
    if (arm_feature(env, ARM_FEATURE_CACHE_BLOCK_OPS)) {
        define_arm_cp_regs(cpu, cache_block_ops_cp_reginfo);
    }
    if (arm_feature(env, ARM_FEATURE_OMAPCP)) {
        define_arm_cp_regs(cpu, omap_cp_reginfo);
    }
    if (arm_feature(env, ARM_FEATURE_STRONGARM)) {
        define_arm_cp_regs(cpu, strongarm_cp_reginfo);
    }
    if (arm_feature(env, ARM_FEATURE_XSCALE)) {
        define_arm_cp_regs(cpu, xscale_cp_reginfo);
    }
    if (arm_feature(env, ARM_FEATURE_DUMMY_C15_REGS)) {
        define_arm_cp_regs(cpu, dummy_c15_cp_reginfo);
    }
    if (arm_feature(env, ARM_FEATURE_LPAE)) {
        define_arm_cp_regs(cpu, lpae_cp_reginfo);
    }
    /* Slightly awkwardly, the OMAP and StrongARM cores need all of
     * cp15 crn=0 to be writes-ignored, whereas for other cores they should
     * be read-only (ie write causes UNDEF exception).
     */
    {
        ARMCPRegInfo id_pre_v8_midr_cp_reginfo[] = {
            /* Pre-v8 MIDR space.
             * Note that the MIDR isn't a simple constant register because
             * of the TI925 behaviour where writes to another register can
             * cause the MIDR value to change.
             *
             * Unimplemented registers in the c15 0 0 0 space default to
             * MIDR. Define MIDR first as this entire space, then CTR, TCMTR
             * and friends override accordingly.
             */
            { "MIDR", 15,0,0, 0,0,CP_ANY, 0,
              ARM_CP_OVERRIDE, PL1_R, NULL, cpu->midr, offsetof(CPUARMState, cp15.c0_cpuid),
              NULL, NULL,arm_cp_write_ignore, NULL,raw_write, },
            /* crn = 0 op1 = 0 crm = 3..7 : currently unassigned; we RAZ. */
            { "DUMMY",
              15,0,3, 0,0,CP_ANY, 0,
              ARM_CP_CONST, PL1_R, NULL, 0 },
            { "DUMMY",
              15,0,4, 0,0,CP_ANY, 0,
              ARM_CP_CONST, PL1_R, NULL, 0 },
            { "DUMMY",
              15,0,5, 0,0,CP_ANY, 0,
              ARM_CP_CONST, PL1_R, NULL, 0 },
            { "DUMMY",
              15,0,6, 0,0,CP_ANY, 0,
              ARM_CP_CONST, PL1_R, NULL, 0 },
            { "DUMMY",
              15,0,7, 0,0,CP_ANY, 0,
              ARM_CP_CONST, PL1_R, NULL, 0 },
            REGINFO_SENTINEL
        };
        ARMCPRegInfo id_v8_midr_cp_reginfo[] = {
            /* v8 MIDR -- the wildcard isn't necessary, and nor is the
             * variable-MIDR TI925 behaviour. Instead we have a single
             * (strictly speaking IMPDEF) alias of the MIDR, REVIDR.
             */
            { "MIDR_EL1", 0,0,0, 3,0,0, ARM_CP_STATE_BOTH,
              ARM_CP_CONST, PL1_R, NULL, cpu->midr },
            { "REVIDR_EL1", 0,0,0, 3,0,6, ARM_CP_STATE_BOTH,
              ARM_CP_CONST, PL1_R, NULL, cpu->midr },
            REGINFO_SENTINEL
        };
        ARMCPRegInfo id_cp_reginfo[] = {
            /* These are common to v8 and pre-v8 */
            { "CTR", 15,0,0, 0,0,1, 0,
              ARM_CP_CONST, PL1_R, NULL, cpu->ctr },
            { "CTR_EL0", 0,0,0, 3,3,1, ARM_CP_STATE_AA64,
             ARM_CP_CONST, PL0_R, NULL, cpu->ctr, 0,
             ctr_el0_access, },
            /* TCMTR and TLBTR exist in v8 but have no 64-bit versions */
            { "TCMTR", 15,0,0, 0,0,2, 0,
              ARM_CP_CONST, PL1_R, NULL, 0 },
            { "TLBTR", 15,0,0, 0,0,3, 0,
              ARM_CP_CONST, PL1_R, NULL, 0 },
            REGINFO_SENTINEL
        };
        ARMCPRegInfo crn0_wi_reginfo = {
            "CRN0_WI", 15,0,CP_ANY, 0,CP_ANY,CP_ANY, 0,
            ARM_CP_NOP | ARM_CP_OVERRIDE, PL1_W,
        };
        if (arm_feature(env, ARM_FEATURE_OMAPCP) ||
            arm_feature(env, ARM_FEATURE_STRONGARM)) {
            ARMCPRegInfo *r;
            /* Register the blanket "writes ignored" value first to cover the
             * whole space. Then update the specific ID registers to allow write
             * access, so that they ignore writes rather than causing them to
             * UNDEF.
             */
            define_one_arm_cp_reg(cpu, &crn0_wi_reginfo);
            for (r = id_pre_v8_midr_cp_reginfo;
                 r->type != ARM_CP_SENTINEL; r++) {
                r->access = PL1_RW;
            }
            for (r = id_cp_reginfo; r->type != ARM_CP_SENTINEL; r++) {
                r->access = PL1_RW;
            }
        }
        if (arm_feature(env, ARM_FEATURE_V8)) {
            define_arm_cp_regs(cpu, id_v8_midr_cp_reginfo);
        } else {
            define_arm_cp_regs(cpu, id_pre_v8_midr_cp_reginfo);
        }
        define_arm_cp_regs(cpu, id_cp_reginfo);
    }

    if (arm_feature(env, ARM_FEATURE_MPIDR)) {
        define_arm_cp_regs(cpu, mpidr_cp_reginfo);
    }

    if (arm_feature(env, ARM_FEATURE_AUXCR)) {
        ARMCPRegInfo auxcr = {
            "ACTLR_EL1", 0,1,0, 3,0,1, ARM_CP_STATE_BOTH,
            ARM_CP_CONST, PL1_RW, NULL, cpu->reset_auxcr
        };
        define_one_arm_cp_reg(cpu, &auxcr);
    }

    if (arm_feature(env, ARM_FEATURE_CBAR)) {
        if (arm_feature(env, ARM_FEATURE_AARCH64)) {
            /* 32 bit view is [31:18] 0...0 [43:32]. */
            uint32_t cbar32 = (extract64(cpu->reset_cbar, 18, 14) << 18)
                | extract64(cpu->reset_cbar, 32, 12);
            ARMCPRegInfo cbar_reginfo[] = {
                { "CBAR", 15,15,0, 0,4,0, 0,
                  ARM_CP_CONST, PL1_R, NULL, cpu->reset_cbar },
                { "CBAR_EL1", 0,15,3, 3,1,0, ARM_CP_STATE_AA64,
                  ARM_CP_CONST, PL1_R, NULL, cbar32 },
                REGINFO_SENTINEL
            };
            /* We don't implement a r/w 64 bit CBAR currently */
            assert(arm_feature(env, ARM_FEATURE_CBAR_RO));
            define_arm_cp_regs(cpu, cbar_reginfo);
        } else {
            ARMCPRegInfo cbar = {
                "CBAR", 15,15,0, 0,4,0, 0,
                0, PL1_R|PL3_W, NULL, cpu->reset_cbar, offsetof(CPUARMState, cp15.c15_config_base_address)
            };
            if (arm_feature(env, ARM_FEATURE_CBAR_RO)) {
                cbar.access = PL1_R;
                cbar.fieldoffset = 0;
                cbar.type = ARM_CP_CONST;
            }
            define_one_arm_cp_reg(cpu, &cbar);
        }
    }

    /* Generic registers whose values depend on the implementation */
    {
        ARMCPRegInfo sctlr = {
            "SCTLR", 0,1,0, 3,0,0, ARM_CP_STATE_BOTH,
            0, PL1_RW, NULL, cpu->reset_sctlr, offsetof(CPUARMState, cp15.c1_sys),
            NULL, NULL,sctlr_write, NULL,raw_write,
        };
        if (arm_feature(env, ARM_FEATURE_XSCALE)) {
            /* Normally we would always end the TB on an SCTLR write, but Linux
             * arch/arm/mach-pxa/sleep.S expects two instructions following
             * an MMU enable to execute from cache.  Imitate this behaviour.
             */
            sctlr.type |= ARM_CP_SUPPRESS_TB_END;
        }
        define_one_arm_cp_reg(cpu, &sctlr);
    }
}

void arm_cpu_register_gdb_regs_for_features(ARMCPU *cpu)
{
}

void arm_cpu_list(FILE *f, fprintf_function cpu_fprintf)
{
}

static void add_cpreg_to_hashtable(ARMCPU *cpu, const ARMCPRegInfo *r,
                                   void *opaque, int state,
                                   int crm, int opc1, int opc2)
{
    /* Private utility function for define_one_arm_cp_reg_with_opaque():
     * add a single reginfo struct to the hash table.
     */
    uint32_t *key = g_new(uint32_t, 1);
    ARMCPRegInfo *r2 = g_memdup(r, sizeof(ARMCPRegInfo));
    int is64 = (r->type & ARM_CP_64BIT) ? 1 : 0;
    if (r->state == ARM_CP_STATE_BOTH && state == ARM_CP_STATE_AA32) {
        /* The AArch32 view of a shared register sees the lower 32 bits
         * of a 64 bit backing field. It is not migratable as the AArch64
         * view handles that. AArch64 also handles reset.
         * We assume it is a cp15 register if the .cp field is left unset.
         */
        if (r2->cp == 0) {
            r2->cp = 15;
        }
        r2->type |= ARM_CP_NO_MIGRATE;
        r2->resetfn = arm_cp_reset_ignore;
#ifdef HOST_WORDS_BIGENDIAN
        if (r2->fieldoffset) {
            r2->fieldoffset += sizeof(uint32_t);
        }
#endif
    }
    if (state == ARM_CP_STATE_AA64) {
        /* To allow abbreviation of ARMCPRegInfo
         * definitions, we treat cp == 0 as equivalent to
         * the value for "standard guest-visible sysreg".
         * STATE_BOTH definitions are also always "standard
         * sysreg" in their AArch64 view (the .cp value may
         * be non-zero for the benefit of the AArch32 view).
         */
        if (r->cp == 0 || r->state == ARM_CP_STATE_BOTH) {
            r2->cp = CP_REG_ARM64_SYSREG_CP;
        }
        *key = ENCODE_AA64_CP_REG(r2->cp, r2->crn, crm,
                                  r2->opc0, opc1, opc2);
    } else {
        *key = ENCODE_CP_REG(r2->cp, is64, r2->crn, crm, opc1, opc2);
    }
    if (opaque) {
        r2->opaque = opaque;
    }
    /* reginfo passed to helpers is correct for the actual access,
     * and is never ARM_CP_STATE_BOTH:
     */
    r2->state = state;
    /* Make sure reginfo passed to helpers for wildcarded regs
     * has the correct crm/opc1/opc2 for this reg, not CP_ANY:
     */
    r2->crm = crm;
    r2->opc1 = opc1;
    r2->opc2 = opc2;
    /* By convention, for wildcarded registers only the first
     * entry is used for migration; the others are marked as
     * NO_MIGRATE so we don't try to transfer the register
     * multiple times. Special registers (ie NOP/WFI) are
     * never migratable.
     */
    if ((r->type & ARM_CP_SPECIAL) ||
        ((r->crm == CP_ANY) && crm != 0) ||
        ((r->opc1 == CP_ANY) && opc1 != 0) ||
        ((r->opc2 == CP_ANY) && opc2 != 0)) {
        r2->type |= ARM_CP_NO_MIGRATE;
    }

    /* Overriding of an existing definition must be explicitly
     * requested.
     */
    if (!(r->type & ARM_CP_OVERRIDE)) {
        ARMCPRegInfo *oldreg;
        oldreg = g_hash_table_lookup(cpu->cp_regs, key);
        if (oldreg && !(oldreg->type & ARM_CP_OVERRIDE)) {
            fprintf(stderr, "Register redefined: cp=%d %d bit "
                    "crn=%d crm=%d opc1=%d opc2=%d, "
                    "was %s, now %s\n", r2->cp, 32 + 32 * is64,
                    r2->crn, r2->crm, r2->opc1, r2->opc2,
                    oldreg->name, r2->name);
            g_assert_not_reached();
        }
    }
    g_hash_table_insert(cpu->cp_regs, key, r2);
}


void define_one_arm_cp_reg_with_opaque(ARMCPU *cpu,
                                       const ARMCPRegInfo *r, void *opaque)
{
    /* Define implementations of coprocessor registers.
     * We store these in a hashtable because typically
     * there are less than 150 registers in a space which
     * is 16*16*16*8*8 = 262144 in size.
     * Wildcarding is supported for the crm, opc1 and opc2 fields.
     * If a register is defined twice then the second definition is
     * used, so this can be used to define some generic registers and
     * then override them with implementation specific variations.
     * At least one of the original and the second definition should
     * include ARM_CP_OVERRIDE in its type bits -- this is just a guard
     * against accidental use.
     *
     * The state field defines whether the register is to be
     * visible in the AArch32 or AArch64 execution state. If the
     * state is set to ARM_CP_STATE_BOTH then we synthesise a
     * reginfo structure for the AArch32 view, which sees the lower
     * 32 bits of the 64 bit register.
     *
     * Only registers visible in AArch64 may set r->opc0; opc0 cannot
     * be wildcarded. AArch64 registers are always considered to be 64
     * bits; the ARM_CP_64BIT* flag applies only to the AArch32 view of
     * the register, if any.
     */
    int crm, opc1, opc2, state;
    int crmmin = (r->crm == CP_ANY) ? 0 : r->crm;
    int crmmax = (r->crm == CP_ANY) ? 15 : r->crm;
    int opc1min = (r->opc1 == CP_ANY) ? 0 : r->opc1;
    int opc1max = (r->opc1 == CP_ANY) ? 7 : r->opc1;
    int opc2min = (r->opc2 == CP_ANY) ? 0 : r->opc2;
    int opc2max = (r->opc2 == CP_ANY) ? 7 : r->opc2;
    /* 64 bit registers have only CRm and Opc1 fields */
    assert(!((r->type & ARM_CP_64BIT) && (r->opc2 || r->crn)));
    /* op0 only exists in the AArch64 encodings */
    assert((r->state != ARM_CP_STATE_AA32) || (r->opc0 == 0));
    /* AArch64 regs are all 64 bit so ARM_CP_64BIT is meaningless */
    assert((r->state != ARM_CP_STATE_AA64) || !(r->type & ARM_CP_64BIT));
    /* The AArch64 pseudocode CheckSystemAccess() specifies that op1
     * encodes a minimum access level for the register. We roll this
     * runtime check into our general permission check code, so check
     * here that the reginfo's specified permissions are strict enough
     * to encompass the generic architectural permission check.
     */
    if (r->state != ARM_CP_STATE_AA32) {
        int mask = 0;
        switch (r->opc1) {
        case 0: case 1: case 2:
            /* min_EL EL1 */
            mask = PL1_RW;
            break;
        case 3:
            /* min_EL EL0 */
            mask = PL0_RW;
            break;
        case 4:
            /* min_EL EL2 */
            mask = PL2_RW;
            break;
        case 5:
            /* unallocated encoding, so not possible */
            assert(false);
            break;
        case 6:
            /* min_EL EL3 */
            mask = PL3_RW;
            break;
        case 7:
            /* min_EL EL1, secure mode only (we don't check the latter) */
            mask = PL1_RW;
            break;
        default:
            /* broken reginfo with out-of-range opc1 */
            assert(false);
            break;
        }
        /* assert our permissions are not too lax (stricter is fine) */
        assert((r->access & ~mask) == 0);
    }

    /* Check that the register definition has enough info to handle
     * reads and writes if they are permitted.
     */
    if (!(r->type & (ARM_CP_SPECIAL|ARM_CP_CONST))) {
        if (r->access & PL3_R) {
            assert(r->fieldoffset || r->readfn);
        }
        if (r->access & PL3_W) {
            assert(r->fieldoffset || r->writefn);
        }
    }
    /* Bad type field probably means missing sentinel at end of reg list */
    assert(cptype_valid(r->type));
    for (crm = crmmin; crm <= crmmax; crm++) {
        for (opc1 = opc1min; opc1 <= opc1max; opc1++) {
            for (opc2 = opc2min; opc2 <= opc2max; opc2++) {
                for (state = ARM_CP_STATE_AA32;
                     state <= ARM_CP_STATE_AA64; state++) {
                    if (r->state != state && r->state != ARM_CP_STATE_BOTH) {
                        continue;
                    }
                    add_cpreg_to_hashtable(cpu, r, opaque, state,
                                           crm, opc1, opc2);
                }
            }
        }
    }
}

void define_arm_cp_regs_with_opaque(ARMCPU *cpu,
                                    const ARMCPRegInfo *regs, void *opaque)
{
    /* Define a whole list of registers */
    const ARMCPRegInfo *r;
    for (r = regs; r->type != ARM_CP_SENTINEL; r++) {
        define_one_arm_cp_reg_with_opaque(cpu, r, opaque);
    }
}

const ARMCPRegInfo *get_arm_cp_reginfo(GHashTable *cpregs, uint32_t encoded_cp)
{
    return g_hash_table_lookup(cpregs, &encoded_cp);
}

void arm_cp_write_ignore(CPUARMState *env, const ARMCPRegInfo *ri,
                         uint64_t value)
{
    /* Helper coprocessor write function for write-ignore registers */
}

uint64_t arm_cp_read_zero(CPUARMState *env, const ARMCPRegInfo *ri)
{
    /* Helper coprocessor write function for read-as-zero registers */
    return 0;
}

void arm_cp_reset_ignore(CPUARMState *env, const ARMCPRegInfo *opaque)
{
    /* Helper coprocessor reset function for do-nothing-on-reset registers */
}

static int bad_mode_switch(CPUARMState *env, int mode)
{
    /* Return true if it is not valid for us to switch to
     * this CPU mode (ie all the UNPREDICTABLE cases in
     * the ARM ARM CPSRWriteByInstr pseudocode).
     */
    switch (mode) {
    case ARM_CPU_MODE_USR:
    case ARM_CPU_MODE_SYS:
    case ARM_CPU_MODE_SVC:
    case ARM_CPU_MODE_ABT:
    case ARM_CPU_MODE_UND:
    case ARM_CPU_MODE_IRQ:
    case ARM_CPU_MODE_FIQ:
        return 0;
    case ARM_CPU_MODE_MON:
        return !arm_is_secure(env);
    default:
        return 1;
    }
}

uint32_t cpsr_read(CPUARMState *env)
{
    int ZF;
    ZF = (env->ZF == 0);
    return env->uncached_cpsr | (env->NF & 0x80000000) | (ZF << 30) |
        (env->CF << 29) | ((env->VF & 0x80000000) >> 3) | (env->QF << 27)
        | (env->thumb << 5) | ((env->condexec_bits & 3) << 25)
        | ((env->condexec_bits & 0xfc) << 8)
        | (env->GE << 16) | (env->daif & CPSR_AIF);
}

void cpsr_write(CPUARMState *env, uint32_t val, uint32_t mask)
{
    if (mask & CPSR_NZCV) {
        env->ZF = (~val) & CPSR_Z;
        env->NF = val;
        env->CF = (val >> 29) & 1;
        env->VF = (val << 3) & 0x80000000;
    }
    if (mask & CPSR_Q)
        env->QF = ((val & CPSR_Q) != 0);
    if (mask & CPSR_T)
        env->thumb = ((val & CPSR_T) != 0);
    if (mask & CPSR_IT_0_1) {
        env->condexec_bits &= ~3;
        env->condexec_bits |= (val >> 25) & 3;
    }
    if (mask & CPSR_IT_2_7) {
        env->condexec_bits &= 3;
        env->condexec_bits |= (val >> 8) & 0xfc;
    }
    if (mask & CPSR_GE) {
        env->GE = (val >> 16) & 0xf;
    }

    env->daif &= ~(CPSR_AIF & mask);
    env->daif |= val & CPSR_AIF & mask;

    if ((env->uncached_cpsr ^ val) & mask & CPSR_M) {
        if (bad_mode_switch(env, val & CPSR_M)) {
            /* Attempt to switch to an invalid mode: this is UNPREDICTABLE.
             * We choose to ignore the attempt and leave the CPSR M field
             * untouched.
             */
            mask &= ~CPSR_M;
        } else {
            switch_mode(env, val & CPSR_M);
        }
    }
    mask &= ~CACHED_CPSR_BITS;
    env->uncached_cpsr = (env->uncached_cpsr & ~mask) | (val & mask);
}

/* Sign/zero extend */
uint32_t HELPER(sxtb16)(uint32_t x)
{
    uint32_t res;
    res = (uint16_t)(int8_t)x;
    res |= (uint32_t)(int8_t)(x >> 16) << 16;
    return res;
}

uint32_t HELPER(uxtb16)(uint32_t x)
{
    uint32_t res;
    res = (uint16_t)(uint8_t)x;
    res |= (uint32_t)(uint8_t)(x >> 16) << 16;
    return res;
}

uint32_t HELPER(clz_arm)(uint32_t x)
{
    return clz32(x);
}

int32_t HELPER(sdiv)(int32_t num, int32_t den)
{
    if (den == 0)
      return 0;
    if (num == INT_MIN && den == -1)
      return INT_MIN;
    return num / den;
}

uint32_t HELPER(udiv)(uint32_t num, uint32_t den)
{
    if (den == 0)
      return 0;
    return num / den;
}

uint32_t HELPER(rbit)(uint32_t x)
{
    x =  ((x & 0xff000000) >> 24)
       | ((x & 0x00ff0000) >> 8)
       | ((x & 0x0000ff00) << 8)
       | ((x & 0x000000ff) << 24);
    x =  ((x & 0xf0f0f0f0) >> 4)
       | ((x & 0x0f0f0f0f) << 4);
    x =  ((x & 0x88888888) >> 3)
       | ((x & 0x44444444) >> 1)
       | ((x & 0x22222222) << 1)
       | ((x & 0x11111111) << 3);
    return x;
}

#if defined(CONFIG_USER_ONLY)

int arm_cpu_handle_mmu_fault(CPUState *cs, vaddr address, int rw,
                             int mmu_idx)
{
    ARMCPU *cpu = ARM_CPU(NULL, cs);
    CPUARMState *env = &cpu->env;

    env->exception.vaddress = address;
    if (rw == 2) {
        cs->exception_index = EXCP_PREFETCH_ABORT;
    } else {
        cs->exception_index = EXCP_DATA_ABORT;
    }
    return 1;
}

/* These should probably raise undefined insn exceptions.  */
void HELPER(v7m_msr)(CPUARMState *env, uint32_t reg, uint32_t val)
{
    ARMCPU *cpu = arm_env_get_cpu(env);

    cpu_abort(CPU(cpu), "v7m_msr %d\n", reg);
}

uint32_t HELPER(v7m_mrs)(CPUARMState *env, uint32_t reg)
{
    ARMCPU *cpu = arm_env_get_cpu(env);

    cpu_abort(CPU(cpu), "v7m_mrs %d\n", reg);
    return 0;
}

void switch_mode(CPUARMState *env, int mode)
{
    ARMCPU *cpu = arm_env_get_cpu(env);

    if (mode != ARM_CPU_MODE_USR) {
        cpu_abort(CPU(cpu), "Tried to switch out of user mode\n");
    }
}

void HELPER(set_r13_banked)(CPUARMState *env, uint32_t mode, uint32_t val)
{
    ARMCPU *cpu = arm_env_get_cpu(env);

    cpu_abort(CPU(cpu), "banked r13 write\n");
}

uint32_t HELPER(get_r13_banked)(CPUARMState *env, uint32_t mode)
{
    ARMCPU *cpu = arm_env_get_cpu(env);

    cpu_abort(CPU(cpu), "banked r13 read\n");
    return 0;
}

unsigned int arm_excp_target_el(CPUState *cs, unsigned int excp_idx)
{
    return 1;
}

#else

/* Map CPU modes onto saved register banks.  */
int bank_number(int mode)
{
    switch (mode) {
    default:
    case ARM_CPU_MODE_USR:
    case ARM_CPU_MODE_SYS:
        return 0;
    case ARM_CPU_MODE_SVC:
        return 1;
    case ARM_CPU_MODE_ABT:
        return 2;
    case ARM_CPU_MODE_UND:
        return 3;
    case ARM_CPU_MODE_IRQ:
        return 4;
    case ARM_CPU_MODE_FIQ:
        return 5;
    case ARM_CPU_MODE_HYP:
        return 6;
    case ARM_CPU_MODE_MON:
        return 7;
    }
    //hw_error("bank number requested for bad CPSR mode value 0x%x\n", mode);
}

void switch_mode(CPUARMState *env, int mode)
{
    int old_mode;
    int i;

    old_mode = env->uncached_cpsr & CPSR_M;
    if (mode == old_mode)
        return;

    if (old_mode == ARM_CPU_MODE_FIQ) {
        memcpy (env->fiq_regs, env->regs + 8, 5 * sizeof(uint32_t));
        memcpy (env->regs + 8, env->usr_regs, 5 * sizeof(uint32_t));
    } else if (mode == ARM_CPU_MODE_FIQ) {
        memcpy (env->usr_regs, env->regs + 8, 5 * sizeof(uint32_t));
        memcpy (env->regs + 8, env->fiq_regs, 5 * sizeof(uint32_t));
    }

    i = bank_number(old_mode);
    env->banked_r13[i] = env->regs[13];
    env->banked_r14[i] = env->regs[14];
    env->banked_spsr[i] = env->spsr;

    i = bank_number(mode);
    env->regs[13] = env->banked_r13[i];
    env->regs[14] = env->banked_r14[i];
    env->spsr = env->banked_spsr[i];
}

/*
 * Determine the target EL for a given exception type.
 */
unsigned int arm_excp_target_el(CPUState *cs, unsigned int excp_idx)
{
    CPUARMState *env = cs->env_ptr;
    unsigned int cur_el = arm_current_el(env);
    unsigned int target_el;
    /* FIXME: Use actual secure state.  */
    bool secure = false;

    if (!env->aarch64) {
        /* TODO: Add EL2 and 3 exception handling for AArch32.  */
        return 1;
    }

    switch (excp_idx) {
    case EXCP_HVC:
    case EXCP_HYP_TRAP:
        target_el = 2;
        break;
    case EXCP_SMC:
        target_el = 3;
        break;
    case EXCP_FIQ:
    case EXCP_IRQ:
    {
        const uint64_t hcr_mask = excp_idx == EXCP_FIQ ? HCR_FMO : HCR_IMO;
        const uint32_t scr_mask = excp_idx == EXCP_FIQ ? SCR_FIQ : SCR_IRQ;

        target_el = 1;
        if (!secure && (env->cp15.hcr_el2 & hcr_mask)) {
            target_el = 2;
        }
        if (env->cp15.scr_el3 & scr_mask) {
            target_el = 3;
        }
        break;
    }
    case EXCP_VIRQ:
    case EXCP_VFIQ:
        target_el = 1;
        break;
    default:
        target_el = MAX(cur_el, 1);
        break;
    }
    return target_el;
}

static void v7m_push(CPUARMState *env, uint32_t val)
{
    CPUState *cs = CPU(arm_env_get_cpu(env));

    env->regs[13] -= 4;
    stl_phys(cs->as, env->regs[13], val);
}

static uint32_t v7m_pop(CPUARMState *env)
{
    CPUState *cs = CPU(arm_env_get_cpu(env));
    uint32_t val;

    val = ldl_phys(cs->as, env->regs[13]);
    env->regs[13] += 4;
    return val;
}

/* Switch to V7M main or process stack pointer.  */
static void switch_v7m_sp(CPUARMState *env, int process)
{
    uint32_t tmp;
    if (env->v7m.current_sp != process) {
        tmp = env->v7m.other_sp;
        env->v7m.other_sp = env->regs[13];
        env->regs[13] = tmp;
        env->v7m.current_sp = process;
    }
}

static void do_v7m_exception_exit(CPUARMState *env)
{
    uint32_t type;
    uint32_t xpsr;

    type = env->regs[15];
    //if (env->v7m.exception != 0)
    //    armv7m_nvic_complete_irq(env->nvic, env->v7m.exception);

    /* Switch to the target stack.  */
    switch_v7m_sp(env, (type & 4) != 0);
    /* Pop registers.  */
    env->regs[0] = v7m_pop(env);
    env->regs[1] = v7m_pop(env);
    env->regs[2] = v7m_pop(env);
    env->regs[3] = v7m_pop(env);
    env->regs[12] = v7m_pop(env);
    env->regs[14] = v7m_pop(env);
    env->regs[15] = v7m_pop(env);
    xpsr = v7m_pop(env);
    xpsr_write(env, xpsr, 0xfffffdff);
    /* Undo stack alignment.  */
    if (xpsr & 0x200)
        env->regs[13] |= 4;
    /* ??? The exception return type specifies Thread/Handler mode.  However
       this is also implied by the xPSR value. Not sure what to do
       if there is a mismatch.  */
    /* ??? Likewise for mismatches between the CONTROL register and the stack
       pointer.  */
}

void arm_v7m_cpu_do_interrupt(CPUState *cs)
{
    CPUARMState *env = cs->env_ptr;
    uint32_t xpsr = xpsr_read(env);
    uint32_t lr;
    uint32_t addr;

    arm_log_exception(cs->exception_index);

    lr = 0xfffffff1;
    if (env->v7m.current_sp)
        lr |= 4;
    if (env->v7m.exception == 0)
        lr |= 8;

    /* For exceptions we just mark as pending on the NVIC, and let that
       handle it.  */
    /* TODO: Need to escalate if the current priority is higher than the
       one we're raising.  */
    switch (cs->exception_index) {
    case EXCP_UDEF:
        //armv7m_nvic_set_pending(env->nvic, ARMV7M_EXCP_USAGE);
        return;
    case EXCP_SWI:
        /* The PC already points to the next instruction.  */
        //armv7m_nvic_set_pending(env->nvic, ARMV7M_EXCP_SVC);
        return;
    case EXCP_PREFETCH_ABORT:
    case EXCP_DATA_ABORT:
        /* TODO: if we implemented the MPU registers, this is where we
         * should set the MMFAR, etc from exception.fsr and exception.vaddress.
         */
        //armv7m_nvic_set_pending(env->nvic, ARMV7M_EXCP_MEM);
        return;
    case EXCP_BKPT:
#if 0
        if (semihosting_enabled) {
            int nr;
            nr = arm_lduw_code(env, env->regs[15], env->bswap_code) & 0xff;
            if (nr == 0xab) {
                env->regs[15] += 2;
                env->regs[0] = do_arm_semihosting(env);
                qemu_log_mask(CPU_LOG_INT, "...handled as semihosting call\n");
                return;
            }
        }
#endif
        //armv7m_nvic_set_pending(env->nvic, ARMV7M_EXCP_DEBUG);
        return;
    case EXCP_IRQ:
        //env->v7m.exception = armv7m_nvic_acknowledge_irq(env->nvic);
        break;
    case EXCP_EXCEPTION_EXIT:
        do_v7m_exception_exit(env);
        return;
    default:
        cpu_abort(cs, "Unhandled exception 0x%x\n", cs->exception_index);
        return; /* Never happens.  Keep compiler happy.  */
    }

    /* Align stack pointer.  */
    /* ??? Should only do this if Configuration Control Register
       STACKALIGN bit is set.  */
    if (env->regs[13] & 4) {
        env->regs[13] -= 4;
        xpsr |= 0x200;
    }
    /* Switch to the handler mode.  */
    v7m_push(env, xpsr);
    v7m_push(env, env->regs[15]);
    v7m_push(env, env->regs[14]);
    v7m_push(env, env->regs[12]);
    v7m_push(env, env->regs[3]);
    v7m_push(env, env->regs[2]);
    v7m_push(env, env->regs[1]);
    v7m_push(env, env->regs[0]);
    switch_v7m_sp(env, 0);
    /* Clear IT bits */
    env->condexec_bits = 0;
    env->regs[14] = lr;
    addr = ldl_phys(cs->as, env->v7m.vecbase + env->v7m.exception * 4);
    env->regs[15] = addr & 0xfffffffe;
    env->thumb = addr & 1;
}

/* Handle a CPU exception.  */
void arm_cpu_do_interrupt(CPUState *cs)
{
    CPUARMState *env = cs->env_ptr;
    ARMCPU *cpu = ARM_CPU(env->uc, cs);
    uint32_t addr;
    uint32_t mask;
    int new_mode;
    uint32_t offset;
    uint32_t moe;

    assert(!IS_M(env));

    arm_log_exception(cs->exception_index);

    if (arm_is_psci_call(cpu, cs->exception_index)) {
        arm_handle_psci_call(cpu);
        qemu_log_mask(CPU_LOG_INT, "...handled as PSCI call\n");
        return;
    }

    /* If this is a debug exception we must update the DBGDSCR.MOE bits */
    switch (env->exception.syndrome >> ARM_EL_EC_SHIFT) {
    case EC_BREAKPOINT:
    case EC_BREAKPOINT_SAME_EL:
        moe = 1;
        break;
    case EC_WATCHPOINT:
    case EC_WATCHPOINT_SAME_EL:
        moe = 10;
        break;
    case EC_AA32_BKPT:
        moe = 3;
        break;
    case EC_VECTORCATCH:
        moe = 5;
        break;
    default:
        moe = 0;
        break;
    }

    if (moe) {
        env->cp15.mdscr_el1 = deposit64(env->cp15.mdscr_el1, 2, 4, moe);
    }

    /* TODO: Vectored interrupt controller.  */
    switch (cs->exception_index) {
    case EXCP_UDEF:
        new_mode = ARM_CPU_MODE_UND;
        addr = 0x04;
        mask = CPSR_I;
        if (env->thumb)
            offset = 2;
        else
            offset = 4;
        break;
    case EXCP_SWI:
#if 0
        if (semihosting_enabled) {
            /* Check for semihosting interrupt.  */
            if (env->thumb) {
                mask = arm_lduw_code(env, env->regs[15] - 2, env->bswap_code)
                    & 0xff;
            } else {
                mask = arm_ldl_code(env, env->regs[15] - 4, env->bswap_code)
                    & 0xffffff;
            }
            /* Only intercept calls from privileged modes, to provide some
               semblance of security.  */
            if (((mask == 0x123456 && !env->thumb)
                    || (mask == 0xab && env->thumb))
                  && (env->uncached_cpsr & CPSR_M) != ARM_CPU_MODE_USR) {
                env->regs[0] = do_arm_semihosting(env);
                qemu_log_mask(CPU_LOG_INT, "...handled as semihosting call\n");
                return;
            }
        }
#endif
        new_mode = ARM_CPU_MODE_SVC;
        addr = 0x08;
        mask = CPSR_I;
        /* The PC already points to the next instruction.  */
        offset = 0;
        break;
    case EXCP_BKPT:
#if 0
        /* See if this is a semihosting syscall.  */
        if (env->thumb && semihosting_enabled) {
            mask = arm_lduw_code(env, env->regs[15], env->bswap_code) & 0xff;
            if (mask == 0xab
                  && (env->uncached_cpsr & CPSR_M) != ARM_CPU_MODE_USR) {
                env->regs[15] += 2;
                env->regs[0] = do_arm_semihosting(env);
                qemu_log_mask(CPU_LOG_INT, "...handled as semihosting call\n");
                return;
            }
        }
#endif
        env->exception.fsr = 2;
        /* Fall through to prefetch abort.  */
    case EXCP_PREFETCH_ABORT:
        env->cp15.ifsr_el2 = env->exception.fsr;
        env->cp15.far_el[1] = deposit64(env->cp15.far_el[1], 32, 32,
                                        env->exception.vaddress);
        qemu_log_mask(CPU_LOG_INT, "...with IFSR 0x%x IFAR 0x%x\n",
                      env->cp15.ifsr_el2, (uint32_t)env->exception.vaddress);
        new_mode = ARM_CPU_MODE_ABT;
        addr = 0x0c;
        mask = CPSR_A | CPSR_I;
        offset = 4;
        break;
    case EXCP_DATA_ABORT:
        env->cp15.esr_el[1] = env->exception.fsr;
        env->cp15.far_el[1] = deposit64(env->cp15.far_el[1], 0, 32,
                                        env->exception.vaddress);
        qemu_log_mask(CPU_LOG_INT, "...with DFSR 0x%x DFAR 0x%x\n",
                      (uint32_t)env->cp15.esr_el[1],
                      (uint32_t)env->exception.vaddress);
        new_mode = ARM_CPU_MODE_ABT;
        addr = 0x10;
        mask = CPSR_A | CPSR_I;
        offset = 8;
        break;
    case EXCP_IRQ:
        new_mode = ARM_CPU_MODE_IRQ;
        addr = 0x18;
        /* Disable IRQ and imprecise data aborts.  */
        mask = CPSR_A | CPSR_I;
        offset = 4;
        break;
    case EXCP_FIQ:
        new_mode = ARM_CPU_MODE_FIQ;
        addr = 0x1c;
        /* Disable FIQ, IRQ and imprecise data aborts.  */
        mask = CPSR_A | CPSR_I | CPSR_F;
        offset = 4;
        break;
    case EXCP_SMC:
        new_mode = ARM_CPU_MODE_MON;
        addr = 0x08;
        mask = CPSR_A | CPSR_I | CPSR_F;
        offset = 0;
        break;
    default:
        cpu_abort(cs, "Unhandled exception 0x%x\n", cs->exception_index);
        return; /* Never happens.  Keep compiler happy.  */
    }
    /* High vectors.  */
    if (env->cp15.c1_sys & SCTLR_V) {
        /* when enabled, base address cannot be remapped.  */
        addr += 0xffff0000;
    } else {
        /* ARM v7 architectures provide a vector base address register to remap
         * the interrupt vector table.
         * This register is only followed in non-monitor mode, and has a secure
         * and un-secure copy. Since the cpu is always in a un-secure operation
         * and is never in monitor mode this feature is always active.
         * Note: only bits 31:5 are valid.
         */
        addr += env->cp15.vbar_el[1];
    }

    if ((env->uncached_cpsr & CPSR_M) == ARM_CPU_MODE_MON) {
        env->cp15.scr_el3 &= ~SCR_NS;
    }

    switch_mode (env, new_mode);
    /* For exceptions taken to AArch32 we must clear the SS bit in both
     * PSTATE and in the old-state value we save to SPSR_<mode>, so zero it now.
     */
    env->uncached_cpsr &= ~PSTATE_SS;
    env->spsr = cpsr_read(env);
    /* Clear IT bits.  */
    env->condexec_bits = 0;
    /* Switch to the new mode, and to the correct instruction set.  */
    env->uncached_cpsr = (env->uncached_cpsr & ~CPSR_M) | new_mode;
    env->daif |= mask;
    /* this is a lie, as the was no c1_sys on V4T/V5, but who cares
     * and we should just guard the thumb mode on V4 */
    if (arm_feature(env, ARM_FEATURE_V4T)) {
        env->thumb = (env->cp15.c1_sys & SCTLR_TE) != 0;
    }
    env->regs[14] = env->regs[15] + offset;
    env->regs[15] = addr;
    cs->interrupt_request |= CPU_INTERRUPT_EXITTB;
}

/* Check section/page access permissions.
   Returns the page protection flags, or zero if the access is not
   permitted.  */
static inline int check_ap(CPUARMState *env, int ap, int domain_prot,
                           int access_type, int is_user)
{
  int prot_ro;

  if (domain_prot == 3) {
    return PAGE_READ | PAGE_WRITE;
  }

  if (access_type == 1)
      prot_ro = 0;
  else
      prot_ro = PAGE_READ;

  switch (ap) {
  case 0:
      if (arm_feature(env, ARM_FEATURE_V7)) {
          return 0;
      }
      if (access_type == 1)
          return 0;
      switch (env->cp15.c1_sys & (SCTLR_S | SCTLR_R)) {
      case SCTLR_S:
          return is_user ? 0 : PAGE_READ;
      case SCTLR_R:
          return PAGE_READ;
      default:
          return 0;
      }
  case 1:
      return is_user ? 0 : PAGE_READ | PAGE_WRITE;
  case 2:
      if (is_user)
          return prot_ro;
      else
          return PAGE_READ | PAGE_WRITE;
  case 3:
      return PAGE_READ | PAGE_WRITE;
  case 4: /* Reserved.  */
      return 0;
  case 5:
      return is_user ? 0 : prot_ro;
  case 6:
      return prot_ro;
  case 7:
      if (!arm_feature (env, ARM_FEATURE_V6K))
          return 0;
      return prot_ro;
  default:
      abort();
  }
}

static bool get_level1_table_address(CPUARMState *env, uint32_t *table,
                                         uint32_t address)
{
    if (address & env->cp15.c2_mask) {
        if ((env->cp15.c2_control & TTBCR_PD1)) {
            /* Translation table walk disabled for TTBR1 */
            return false;
        }
        *table = env->cp15.ttbr1_el1 & 0xffffc000;
    } else {
        if ((env->cp15.c2_control & TTBCR_PD0)) {
            /* Translation table walk disabled for TTBR0 */
            return false;
        }
        *table = env->cp15.ttbr0_el1 & env->cp15.c2_base_mask;
    }
    *table |= (address >> 18) & 0x3ffc;
    return true;
}

static int get_phys_addr_v5(CPUARMState *env, uint32_t address, int access_type,
                            int is_user, hwaddr *phys_ptr,
                            int *prot, target_ulong *page_size)
{
    CPUState *cs = CPU(arm_env_get_cpu(env));
    int code;
    uint32_t table;
    uint32_t desc;
    int type;
    int ap;
    int domain = 0;
    int domain_prot;
    hwaddr phys_addr;

    /* Pagetable walk.  */
    /* Lookup l1 descriptor.  */
    if (!get_level1_table_address(env, &table, address)) {
        /* Section translation fault if page walk is disabled by PD0 or PD1 */
        code = 5;
        goto do_fault;
    }
    desc = ldl_phys(cs->as, table);
    type = (desc & 3);
    domain = (desc >> 5) & 0x0f;
    domain_prot = (env->cp15.c3 >> (domain * 2)) & 3;
    if (type == 0) {
        /* Section translation fault.  */
        code = 5;
        goto do_fault;
    }
    if (domain_prot == 0 || domain_prot == 2) {
        if (type == 2)
            code = 9; /* Section domain fault.  */
        else
            code = 11; /* Page domain fault.  */
        goto do_fault;
    }
    if (type == 2) {
        /* 1Mb section.  */
        phys_addr = (desc & 0xfff00000) | (address & 0x000fffff);
        ap = (desc >> 10) & 3;
        code = 13;
        *page_size = 1024 * 1024;
    } else {
        /* Lookup l2 entry.  */
    if (type == 1) {
        /* Coarse pagetable.  */
        table = (desc & 0xfffffc00) | ((address >> 10) & 0x3fc);
    } else {
        /* Fine pagetable.  */
        table = (desc & 0xfffff000) | ((address >> 8) & 0xffc);
    }
        desc = ldl_phys(cs->as, table);
        switch (desc & 3) {
        case 0: /* Page translation fault.  */
            code = 7;
            goto do_fault;
        case 1: /* 64k page.  */
            phys_addr = (desc & 0xffff0000) | (address & 0xffff);
            ap = (desc >> (4 + ((address >> 13) & 6))) & 3;
            *page_size = 0x10000;
            break;
        case 2: /* 4k page.  */
            phys_addr = (desc & 0xfffff000) | (address & 0xfff);
            ap = (desc >> (4 + ((address >> 9) & 6))) & 3;
            *page_size = 0x1000;
            break;
        case 3: /* 1k page.  */
        if (type == 1) {
        if (arm_feature(env, ARM_FEATURE_XSCALE)) {
            phys_addr = (desc & 0xfffff000) | (address & 0xfff);
        } else {
            /* Page translation fault.  */
            code = 7;
            goto do_fault;
        }
        } else {
        phys_addr = (desc & 0xfffffc00) | (address & 0x3ff);
        }
            ap = (desc >> 4) & 3;
            *page_size = 0x400;
            break;
        default:
            /* Never happens, but compiler isn't smart enough to tell.  */
            abort();
        }
        code = 15;
    }
    *prot = check_ap(env, ap, domain_prot, access_type, is_user);
    if (!*prot) {
        /* Access permission fault.  */
        goto do_fault;
    }
    *prot |= PAGE_EXEC;
    *phys_ptr = phys_addr;
    return 0;
do_fault:
    return code | (domain << 4);
}

static int get_phys_addr_v6(CPUARMState *env, uint32_t address, int access_type,
                            int is_user, hwaddr *phys_ptr,
                            int *prot, target_ulong *page_size)
{
    CPUState *cs = CPU(arm_env_get_cpu(env));
    int code;
    uint32_t table;
    uint32_t desc;
    uint32_t xn;
    uint32_t pxn = 0;
    int type;
    int ap;
    int domain = 0;
    int domain_prot;
    hwaddr phys_addr;

    /* Pagetable walk.  */
    /* Lookup l1 descriptor.  */
    if (!get_level1_table_address(env, &table, address)) {
        /* Section translation fault if page walk is disabled by PD0 or PD1 */
        code = 5;
        goto do_fault;
    }
    desc = ldl_phys(cs->as, table);
    type = (desc & 3);
    if (type == 0 || (type == 3 && !arm_feature(env, ARM_FEATURE_PXN))) {
        /* Section translation fault, or attempt to use the encoding
         * which is Reserved on implementations without PXN.
         */
        code = 5;
        goto do_fault;
    }
    if ((type == 1) || !(desc & (1 << 18))) {
        /* Page or Section.  */
        domain = (desc >> 5) & 0x0f;
    }
    domain_prot = (env->cp15.c3 >> (domain * 2)) & 3;
    if (domain_prot == 0 || domain_prot == 2) {
        if (type != 1) {
            code = 9; /* Section domain fault.  */
        } else {
            code = 11; /* Page domain fault.  */
        }
        goto do_fault;
    }
    if (type != 1) {
        if (desc & (1 << 18)) {
            /* Supersection.  */
            phys_addr = (desc & 0xff000000) | (address & 0x00ffffff);
            *page_size = 0x1000000;
        } else {
            /* Section.  */
            phys_addr = (desc & 0xfff00000) | (address & 0x000fffff);
            *page_size = 0x100000;
        }
        ap = ((desc >> 10) & 3) | ((desc >> 13) & 4);
        xn = desc & (1 << 4);
        pxn = desc & 1;
        code = 13;
    } else {
        if (arm_feature(env, ARM_FEATURE_PXN)) {
            pxn = (desc >> 2) & 1;
        }
        /* Lookup l2 entry.  */
        table = (desc & 0xfffffc00) | ((address >> 10) & 0x3fc);
        desc = ldl_phys(cs->as, table);
        ap = ((desc >> 4) & 3) | ((desc >> 7) & 4);
        switch (desc & 3) {
        case 0: /* Page translation fault.  */
            code = 7;
            goto do_fault;
        case 1: /* 64k page.  */
            phys_addr = (desc & 0xffff0000) | (address & 0xffff);
            xn = desc & (1 << 15);
            *page_size = 0x10000;
            break;
        case 2: case 3: /* 4k page.  */
            phys_addr = (desc & 0xfffff000) | (address & 0xfff);
            xn = desc & 1;
            *page_size = 0x1000;
            break;
        default:
            /* Never happens, but compiler isn't smart enough to tell.  */
            abort();
        }
        code = 15;
    }
    if (domain_prot == 3) {
        *prot = PAGE_READ | PAGE_WRITE | PAGE_EXEC;
    } else {
        if (pxn && !is_user) {
            xn = 1;
        }
        if (xn && access_type == 2)
            goto do_fault;

        /* The simplified model uses AP[0] as an access control bit.  */
        if ((env->cp15.c1_sys & SCTLR_AFE) && (ap & 1) == 0) {
            /* Access flag fault.  */
            code = (code == 15) ? 6 : 3;
            goto do_fault;
        }
        *prot = check_ap(env, ap, domain_prot, access_type, is_user);
        if (!*prot) {
            /* Access permission fault.  */
            goto do_fault;
        }
        if (!xn) {
            *prot |= PAGE_EXEC;
        }
    }
    *phys_ptr = phys_addr;
    return 0;
do_fault:
    return code | (domain << 4);
}

/* Fault type for long-descriptor MMU fault reporting; this corresponds
 * to bits [5..2] in the STATUS field in long-format DFSR/IFSR.
 */
typedef enum {
    translation_fault = 1,
    access_fault = 2,
    permission_fault = 3,
} MMUFaultType;

static int get_phys_addr_lpae(CPUARMState *env, target_ulong address,
                              int access_type, int is_user,
                              hwaddr *phys_ptr, int *prot,
                              target_ulong *page_size_ptr)
{
    CPUState *cs = CPU(arm_env_get_cpu(env));
    /* Read an LPAE long-descriptor translation table. */
    MMUFaultType fault_type = translation_fault;
    uint32_t level = 1;
    uint32_t epd;
    int32_t tsz;
    uint32_t tg;
    uint64_t ttbr;
    int ttbr_select;
    hwaddr descaddr, descmask;
    uint32_t tableattrs;
    target_ulong page_size;
    uint32_t attrs;
    int32_t granule_sz = 9;
    int32_t va_size = 32;
    int32_t tbi = 0;
    uint32_t t0sz;
    uint32_t t1sz;

    if (arm_el_is_aa64(env, 1)) {
        va_size = 64;
        if (extract64(address, 55, 1))
            tbi = extract64(env->cp15.c2_control, 38, 1);
        else
            tbi = extract64(env->cp15.c2_control, 37, 1);
        tbi *= 8;
    }

    /* Determine whether this address is in the region controlled by
     * TTBR0 or TTBR1 (or if it is in neither region and should fault).
     * This is a Non-secure PL0/1 stage 1 translation, so controlled by
     * TTBCR/TTBR0/TTBR1 in accordance with ARM ARM DDI0406C table B-32:
     */
    t0sz = extract32(env->cp15.c2_control, 0, 6);
    if (arm_el_is_aa64(env, 1)) {
        t0sz = MIN(t0sz, 39);
        t0sz = MAX(t0sz, 16);
    }
    t1sz = extract32(env->cp15.c2_control, 16, 6);
    if (arm_el_is_aa64(env, 1)) {
        t1sz = MIN(t1sz, 39);
        t1sz = MAX(t1sz, 16);
    }
    if (t0sz && !extract64(address, va_size - t0sz, t0sz - tbi)) {
        /* there is a ttbr0 region and we are in it (high bits all zero) */
        ttbr_select = 0;
    } else if (t1sz && !extract64(~address, va_size - t1sz, t1sz - tbi)) {
        /* there is a ttbr1 region and we are in it (high bits all one) */
        ttbr_select = 1;
    } else if (!t0sz) {
        /* ttbr0 region is "everything not in the ttbr1 region" */
        ttbr_select = 0;
    } else if (!t1sz) {
        /* ttbr1 region is "everything not in the ttbr0 region" */
        ttbr_select = 1;
    } else {
        /* in the gap between the two regions, this is a Translation fault */
        fault_type = translation_fault;
        goto do_fault;
    }

    /* Note that QEMU ignores shareability and cacheability attributes,
     * so we don't need to do anything with the SH, ORGN, IRGN fields
     * in the TTBCR.  Similarly, TTBCR:A1 selects whether we get the
     * ASID from TTBR0 or TTBR1, but QEMU's TLB doesn't currently
     * implement any ASID-like capability so we can ignore it (instead
     * we will always flush the TLB any time the ASID is changed).
     */
    if (ttbr_select == 0) {
        ttbr = env->cp15.ttbr0_el1;
        epd = extract32(env->cp15.c2_control, 7, 1);
        tsz = t0sz;

        tg = extract32(env->cp15.c2_control, 14, 2);
        if (tg == 1) { /* 64KB pages */
            granule_sz = 13;
        }
        if (tg == 2) { /* 16KB pages */
            granule_sz = 11;
        }
    } else {
        ttbr = env->cp15.ttbr1_el1;
        epd = extract32(env->cp15.c2_control, 23, 1);
        tsz = t1sz;

        tg = extract32(env->cp15.c2_control, 30, 2);
        if (tg == 3)  { /* 64KB pages */
            granule_sz = 13;
        }
        if (tg == 1) { /* 16KB pages */
            granule_sz = 11;
        }
    }

    if (epd) {
        /* Translation table walk disabled => Translation fault on TLB miss */
        goto do_fault;
    }

    /* The starting level depends on the virtual address size (which can be
     * up to 48 bits) and the translation granule size. It indicates the number
     * of strides (granule_sz bits at a time) needed to consume the bits
     * of the input address. In the pseudocode this is:
     *  level = 4 - RoundUp((inputsize - grainsize) / stride)
     * where their 'inputsize' is our 'va_size - tsz', 'grainsize' is
     * our 'granule_sz + 3' and 'stride' is our 'granule_sz'.
     * Applying the usual "rounded up m/n is (m+n-1)/n" and simplifying:
     *     = 4 - (va_size - tsz - granule_sz - 3 + granule_sz - 1) / granule_sz
     *     = 4 - (va_size - tsz - 4) / granule_sz;
     */
    level = 4 - (va_size - tsz - 4) / granule_sz;

    /* Clear the vaddr bits which aren't part of the within-region address,
     * so that we don't have to special case things when calculating the
     * first descriptor address.
     */
    if (tsz) {
        address &= (1ULL << (va_size - tsz)) - 1;
    }

    descmask = (1ULL << (granule_sz + 3)) - 1;

    /* Now we can extract the actual base address from the TTBR */
    descaddr = extract64(ttbr, 0, 48);
    descaddr &= ~((1ULL << (va_size - tsz - (granule_sz * (4 - level)))) - 1);

    tableattrs = 0;
    for (;;) {
        uint64_t descriptor;

        descaddr |= (address >> (granule_sz * (4 - level))) & descmask;
        descaddr &= ~7ULL;
        descriptor = ldq_phys(cs->as, descaddr);
        if (!(descriptor & 1) ||
            (!(descriptor & 2) && (level == 3))) {
            /* Invalid, or the Reserved level 3 encoding */
            goto do_fault;
        }
        descaddr = descriptor & 0xfffffff000ULL;

        if ((descriptor & 2) && (level < 3)) {
            /* Table entry. The top five bits are attributes which  may
             * propagate down through lower levels of the table (and
             * which are all arranged so that 0 means "no effect", so
             * we can gather them up by ORing in the bits at each level).
             */
            tableattrs |= extract64(descriptor, 59, 5);
            level++;
            continue;
        }
        /* Block entry at level 1 or 2, or page entry at level 3.
         * These are basically the same thing, although the number
         * of bits we pull in from the vaddr varies.
         */
        page_size = (1ULL << ((granule_sz * (4 - level)) + 3));
        descaddr |= (address & (page_size - 1));
        /* Extract attributes from the descriptor and merge with table attrs */
        attrs = extract64(descriptor, 2, 10)
            | (extract64(descriptor, 52, 12) << 10);
        attrs |= extract32(tableattrs, 0, 2) << 11; /* XN, PXN */
        attrs |= extract32(tableattrs, 3, 1) << 5; /* APTable[1] => AP[2] */
        /* The sense of AP[1] vs APTable[0] is reversed, as APTable[0] == 1
         * means "force PL1 access only", which means forcing AP[1] to 0.
         */
        if (extract32(tableattrs, 2, 1)) {
            attrs &= ~(1 << 4);
        }
        /* Since we're always in the Non-secure state, NSTable is ignored. */
        break;
    }
    /* Here descaddr is the final physical address, and attributes
     * are all in attrs.
     */
    fault_type = access_fault;
    if ((attrs & (1 << 8)) == 0) {
        /* Access flag */
        goto do_fault;
    }
    fault_type = permission_fault;
    if (is_user && !(attrs & (1 << 4))) {
        /* Unprivileged access not enabled */
        goto do_fault;
    }
    *prot = PAGE_READ | PAGE_WRITE | PAGE_EXEC;
    if ((arm_feature(env, ARM_FEATURE_V8) && is_user && (attrs & (1 << 12))) ||
        (!arm_feature(env, ARM_FEATURE_V8) && (attrs & (1 << 12))) ||
        (!is_user && (attrs & (1 << 11)))) {
        /* XN/UXN or PXN. Since we only implement EL0/EL1 we unconditionally
         * treat XN/UXN as UXN for v8.
         */
        if (access_type == 2) {
            goto do_fault;
        }
        *prot &= ~PAGE_EXEC;
    }
    if (attrs & (1 << 5)) {
        /* Write access forbidden */
        if (access_type == 1) {
            goto do_fault;
        }
        *prot &= ~PAGE_WRITE;
    }

    *phys_ptr = descaddr;
    *page_size_ptr = page_size;
    return 0;

do_fault:
    /* Long-descriptor format IFSR/DFSR value */
    return (1 << 9) | (fault_type << 2) | level;
}

static int get_phys_addr_mpu(CPUARMState *env, uint32_t address,
                             int access_type, int is_user,
                             hwaddr *phys_ptr, int *prot)
{
    int n;
    uint32_t mask;
    uint32_t base;

    *phys_ptr = address;
    for (n = 7; n >= 0; n--) {
    base = env->cp15.c6_region[n];
    if ((base & 1) == 0)
        continue;
    mask = 1 << ((base >> 1) & 0x1f);
    /* Keep this shift separate from the above to avoid an
       (undefined) << 32.  */
    mask = (mask << 1) - 1;
    if (((base ^ address) & ~mask) == 0)
        break;
    }
    if (n < 0)
    return 2;

    if (access_type == 2) {
        mask = env->cp15.pmsav5_insn_ap;
    } else {
        mask = env->cp15.pmsav5_data_ap;
    }
    mask = (mask >> (n * 4)) & 0xf;
    switch (mask) {
    case 0:
    return 1;
    case 1:
    if (is_user)
      return 1;
    *prot = PAGE_READ | PAGE_WRITE;
    break;
    case 2:
    *prot = PAGE_READ;
    if (!is_user)
        *prot |= PAGE_WRITE;
    break;
    case 3:
    *prot = PAGE_READ | PAGE_WRITE;
    break;
    case 5:
    if (is_user)
        return 1;
    *prot = PAGE_READ;
    break;
    case 6:
    *prot = PAGE_READ;
    break;
    default:
    /* Bad permission.  */
    return 1;
    }
    *prot |= PAGE_EXEC;
    return 0;
}

/* get_phys_addr - get the physical address for this virtual address
 *
 * Find the physical address corresponding to the given virtual address,
 * by doing a translation table walk on MMU based systems or using the
 * MPU state on MPU based systems.
 *
 * Returns 0 if the translation was successful. Otherwise, phys_ptr,
 * prot and page_size are not filled in, and the return value provides
 * information on why the translation aborted, in the format of a
 * DFSR/IFSR fault register, with the following caveats:
 *  * we honour the short vs long DFSR format differences.
 *  * the WnR bit is never set (the caller must do this).
 *  * for MPU based systems we don't bother to return a full FSR format
 *    value.
 *
 * @env: CPUARMState
 * @address: virtual address to get physical address for
 * @access_type: 0 for read, 1 for write, 2 for execute
 * @is_user: 0 for privileged access, 1 for user
 * @phys_ptr: set to the physical address corresponding to the virtual address
 * @prot: set to the permissions for the page containing phys_ptr
 * @page_size: set to the size of the page containing phys_ptr
 */
static inline int get_phys_addr(CPUARMState *env, target_ulong address,
                                int access_type, int is_user,
                                hwaddr *phys_ptr, int *prot,
                                target_ulong *page_size)
{
    /* Fast Context Switch Extension.  */
    if (address < 0x02000000)
        address += env->cp15.c13_fcse;

    if ((env->cp15.c1_sys & SCTLR_M) == 0) {
        /* MMU/MPU disabled.  */
        *phys_ptr = address;
        *prot = PAGE_READ | PAGE_WRITE | PAGE_EXEC;
        *page_size = TARGET_PAGE_SIZE;
        return 0;
    } else if (arm_feature(env, ARM_FEATURE_MPU)) {
        *page_size = TARGET_PAGE_SIZE;
    return get_phys_addr_mpu(env, address, access_type, is_user, phys_ptr,
                 prot);
    } else if (extended_addresses_enabled(env)) {
        return get_phys_addr_lpae(env, address, access_type, is_user, phys_ptr,
                                  prot, page_size);
    } else if (env->cp15.c1_sys & SCTLR_XP) {
        return get_phys_addr_v6(env, address, access_type, is_user, phys_ptr,
                                prot, page_size);
    } else {
        return get_phys_addr_v5(env, address, access_type, is_user, phys_ptr,
                                prot, page_size);
    }
}

int arm_cpu_handle_mmu_fault(CPUState *cs, vaddr address,
                             int access_type, int mmu_idx)
{
    CPUARMState *env = cs->env_ptr;
    hwaddr phys_addr;
    target_ulong page_size;
    int prot;
    int ret, is_user;
    uint32_t syn;
    bool same_el = (arm_current_el(env) != 0);

    is_user = mmu_idx == MMU_USER_IDX;
    ret = get_phys_addr(env, address, access_type, is_user, &phys_addr, &prot,
                        &page_size);
    if (ret == 0) {
        /* Map a single [sub]page.  */
        phys_addr &= TARGET_PAGE_MASK;
        address &= TARGET_PAGE_MASK;
        tlb_set_page(cs, address, phys_addr, prot, mmu_idx, page_size);
        return 0;
    }

    /* AArch64 syndrome does not have an LPAE bit */
    syn = ret & ~(1 << 9);

    /* For insn and data aborts we assume there is no instruction syndrome
     * information; this is always true for exceptions reported to EL1.
     */
    if (access_type == 2) {
        syn = syn_insn_abort(same_el, 0, 0, syn);
        cs->exception_index = EXCP_PREFETCH_ABORT;
    } else {
        syn = syn_data_abort(same_el, 0, 0, 0, access_type == 1, syn);
        if (access_type == 1 && arm_feature(env, ARM_FEATURE_V6)) {
            ret |= (1 << 11);
        }
        cs->exception_index = EXCP_DATA_ABORT;
    }

    env->exception.syndrome = syn;
    env->exception.vaddress = address;
    env->exception.fsr = ret;
    return 1;
}

hwaddr arm_cpu_get_phys_page_debug(CPUState *cs, vaddr addr)
{
    ARMCPU *cpu = ARM_CPU(NULL, cs);
    hwaddr phys_addr;
    target_ulong page_size;
    int prot;
    int ret;

    ret = get_phys_addr(&cpu->env, addr, 0, 0, &phys_addr, &prot, &page_size);

    if (ret != 0) {
        return -1;
    }

    return phys_addr;
}

void HELPER(set_r13_banked)(CPUARMState *env, uint32_t mode, uint32_t val)
{
    if ((env->uncached_cpsr & CPSR_M) == mode) {
        env->regs[13] = val;
    } else {
        env->banked_r13[bank_number(mode)] = val;
    }
}

uint32_t HELPER(get_r13_banked)(CPUARMState *env, uint32_t mode)
{
    if ((env->uncached_cpsr & CPSR_M) == mode) {
        return env->regs[13];
    } else {
        return env->banked_r13[bank_number(mode)];
    }
}

uint32_t HELPER(v7m_mrs)(CPUARMState *env, uint32_t reg)
{
    ARMCPU *cpu = arm_env_get_cpu(env);

    switch (reg) {
    case 0: /* APSR */
        return xpsr_read(env) & 0xf8000000;
    case 1: /* IAPSR */
        return xpsr_read(env) & 0xf80001ff;
    case 2: /* EAPSR */
        return xpsr_read(env) & 0xff00fc00;
    case 3: /* xPSR */
        return xpsr_read(env) & 0xff00fdff;
    case 5: /* IPSR */
        return xpsr_read(env) & 0x000001ff;
    case 6: /* EPSR */
        return xpsr_read(env) & 0x0700fc00;
    case 7: /* IEPSR */
        return xpsr_read(env) & 0x0700edff;
    case 8: /* MSP */
        return env->v7m.current_sp ? env->v7m.other_sp : env->regs[13];
    case 9: /* PSP */
        return env->v7m.current_sp ? env->regs[13] : env->v7m.other_sp;
    case 16: /* PRIMASK */
        return (env->daif & PSTATE_I) != 0;
    case 17: /* BASEPRI */
    case 18: /* BASEPRI_MAX */
        return env->v7m.basepri;
    case 19: /* FAULTMASK */
        return (env->daif & PSTATE_F) != 0;
    case 20: /* CONTROL */
        return env->v7m.control;
    default:
        /* ??? For debugging only.  */
        cpu_abort(CPU(cpu), "Unimplemented system register read (%d)\n", reg);
        return 0;
    }
}

void HELPER(v7m_msr)(CPUARMState *env, uint32_t reg, uint32_t val)
{
    ARMCPU *cpu = arm_env_get_cpu(env);

    switch (reg) {
    case 0: /* APSR */
        xpsr_write(env, val, 0xf8000000);
        break;
    case 1: /* IAPSR */
        xpsr_write(env, val, 0xf8000000);
        break;
    case 2: /* EAPSR */
        xpsr_write(env, val, 0xfe00fc00);
        break;
    case 3: /* xPSR */
        xpsr_write(env, val, 0xfe00fc00);
        break;
    case 5: /* IPSR */
        /* IPSR bits are readonly.  */
        break;
    case 6: /* EPSR */
        xpsr_write(env, val, 0x0600fc00);
        break;
    case 7: /* IEPSR */
        xpsr_write(env, val, 0x0600fc00);
        break;
    case 8: /* MSP */
        if (env->v7m.current_sp)
            env->v7m.other_sp = val;
        else
            env->regs[13] = val;
        break;
    case 9: /* PSP */
        if (env->v7m.current_sp)
            env->regs[13] = val;
        else
            env->v7m.other_sp = val;
        break;
    case 16: /* PRIMASK */
        if (val & 1) {
            env->daif |= PSTATE_I;
        } else {
            env->daif &= ~PSTATE_I;
        }
        break;
    case 17: /* BASEPRI */
        env->v7m.basepri = val & 0xff;
        break;
    case 18: /* BASEPRI_MAX */
        val &= 0xff;
        if (val != 0 && (val < env->v7m.basepri || env->v7m.basepri == 0))
            env->v7m.basepri = val;
        break;
    case 19: /* FAULTMASK */
        if (val & 1) {
            env->daif |= PSTATE_F;
        } else {
            env->daif &= ~PSTATE_F;
        }
        break;
    case 20: /* CONTROL */
        env->v7m.control = val & 3;
        switch_v7m_sp(env, (val & 2) != 0);
        break;
    default:
        /* ??? For debugging only.  */
        cpu_abort(CPU(cpu), "Unimplemented system register write (%d)\n", reg);
        return;
    }
}

#endif

void HELPER(dc_zva)(CPUARMState *env, uint64_t vaddr_in)
{
    /* Implement DC ZVA, which zeroes a fixed-length block of memory.
     * Note that we do not implement the (architecturally mandated)
     * alignment fault for attempts to use this on Device memory
     * (which matches the usual QEMU behaviour of not implementing either
     * alignment faults or any memory attribute handling).
     */

    ARMCPU *cpu = arm_env_get_cpu(env);
    uint64_t blocklen = 4 << cpu->dcz_blocksize;
    uint64_t vaddr = vaddr_in & ~(blocklen - 1);

#ifndef CONFIG_USER_ONLY
    {
        /* Slightly awkwardly, QEMU's TARGET_PAGE_SIZE may be less than
         * the block size so we might have to do more than one TLB lookup.
         * We know that in fact for any v8 CPU the page size is at least 4K
         * and the block size must be 2K or less, but TARGET_PAGE_SIZE is only
         * 1K as an artefact of legacy v5 subpage support being present in the
         * same QEMU executable.
         */
        
        int maxidx = DIV_ROUND_UP(blocklen, TARGET_PAGE_SIZE);
        // msvc doesnt allow non-constant array sizes, so we work out the size it would be
        // TARGET_PAGE_SIZE is 1024
        // blocklen is 64
        // maxidx = (blocklen+TARGET_PAGE_SIZE-1) / TARGET_PAGE_SIZE
        //        = (64+1024-1) / 1024
        //        = 1
#ifdef _MSC_VER
        void *hostaddr[1];
#else
        void *hostaddr[maxidx];
#endif
        int try, i;

        for (try = 0; try < 2; try++) {

            for (i = 0; i < maxidx; i++) {
                hostaddr[i] = tlb_vaddr_to_host(env,
                                                vaddr + TARGET_PAGE_SIZE * i,
                                                1, cpu_mmu_index(env));
                if (!hostaddr[i]) {
                    break;
                }
            }
            if (i == maxidx) {
                /* If it's all in the TLB it's fair game for just writing to;
                 * we know we don't need to update dirty status, etc.
                 */
                for (i = 0; i < maxidx - 1; i++) {
                    memset(hostaddr[i], 0, TARGET_PAGE_SIZE);
                }
                memset(hostaddr[i], 0, blocklen - (i * TARGET_PAGE_SIZE));
                return;
            }
            /* OK, try a store and see if we can populate the tlb. This
             * might cause an exception if the memory isn't writable,
             * in which case we will longjmp out of here. We must for
             * this purpose use the actual register value passed to us
             * so that we get the fault address right.
             */
            helper_ret_stb_mmu(env, vaddr_in, 0, cpu_mmu_index(env), GETRA());
            /* Now we can populate the other TLB entries, if any */
            for (i = 0; i < maxidx; i++) {
                uint64_t va = vaddr + TARGET_PAGE_SIZE * i;
                if (va != (vaddr_in & TARGET_PAGE_MASK)) {
                    helper_ret_stb_mmu(env, va, 0, cpu_mmu_index(env), GETRA());
                }
            }
        }

        /* Slow path (probably attempt to do this to an I/O device or
         * similar, or clearing of a block of code we have translations
         * cached for). Just do a series of byte writes as the architecture
         * demands. It's not worth trying to use a cpu_physical_memory_map(),
         * memset(), unmap() sequence here because:
         *  + we'd need to account for the blocksize being larger than a page
         *  + the direct-RAM access case is almost always going to be dealt
         *    with in the fastpath code above, so there's no speed benefit
         *  + we would have to deal with the map returning NULL because the
         *    bounce buffer was in use
         */
        for (i = 0; i < blocklen; i++) {
            helper_ret_stb_mmu(env, vaddr + i, 0, cpu_mmu_index(env), GETRA());
        }
    }
#else
    memset(g2h(vaddr), 0, blocklen);
#endif
}

/* Note that signed overflow is undefined in C.  The following routines are
   careful to use unsigned types where modulo arithmetic is required.
   Failure to do so _will_ break on newer gcc.  */

/* Signed saturating arithmetic.  */

/* Perform 16-bit signed saturating addition.  */
static inline uint16_t add16_sat(uint16_t a, uint16_t b)
{
    uint16_t res;

    res = a + b;
    if (((res ^ a) & 0x8000) && !((a ^ b) & 0x8000)) {
        if (a & 0x8000)
            res = 0x8000;
        else
            res = 0x7fff;
    }
    return res;
}

/* Perform 8-bit signed saturating addition.  */
static inline uint8_t add8_sat(uint8_t a, uint8_t b)
{
    uint8_t res;

    res = a + b;
    if (((res ^ a) & 0x80) && !((a ^ b) & 0x80)) {
        if (a & 0x80)
            res = 0x80;
        else
            res = 0x7f;
    }
    return res;
}

/* Perform 16-bit signed saturating subtraction.  */
static inline uint16_t sub16_sat(uint16_t a, uint16_t b)
{
    uint16_t res;

    res = a - b;
    if (((res ^ a) & 0x8000) && ((a ^ b) & 0x8000)) {
        if (a & 0x8000)
            res = 0x8000;
        else
            res = 0x7fff;
    }
    return res;
}

/* Perform 8-bit signed saturating subtraction.  */
static inline uint8_t sub8_sat(uint8_t a, uint8_t b)
{
    uint8_t res;

    res = a - b;
    if (((res ^ a) & 0x80) && ((a ^ b) & 0x80)) {
        if (a & 0x80)
            res = 0x80;
        else
            res = 0x7f;
    }
    return res;
}

#define ADD16(a, b, n) RESULT(add16_sat(a, b), n, 16);
#define SUB16(a, b, n) RESULT(sub16_sat(a, b), n, 16);
#define ADD8(a, b, n)  RESULT(add8_sat(a, b), n, 8);
#define SUB8(a, b, n)  RESULT(sub8_sat(a, b), n, 8);
#define PFX q

#include "op_addsub.h"

/* Unsigned saturating arithmetic.  */
static inline uint16_t add16_usat(uint16_t a, uint16_t b)
{
    uint16_t res;
    res = a + b;
    if (res < a)
        res = 0xffff;
    return res;
}

static inline uint16_t sub16_usat(uint16_t a, uint16_t b)
{
    if (a > b)
        return a - b;
    else
        return 0;
}

static inline uint8_t add8_usat(uint8_t a, uint8_t b)
{
    uint8_t res;
    res = a + b;
    if (res < a)
        res = 0xff;
    return res;
}

static inline uint8_t sub8_usat(uint8_t a, uint8_t b)
{
    if (a > b)
        return a - b;
    else
        return 0;
}

#define ADD16(a, b, n) RESULT(add16_usat(a, b), n, 16);
#define SUB16(a, b, n) RESULT(sub16_usat(a, b), n, 16);
#define ADD8(a, b, n)  RESULT(add8_usat(a, b), n, 8);
#define SUB8(a, b, n)  RESULT(sub8_usat(a, b), n, 8);
#define PFX uq

#include "op_addsub.h"

/* Signed modulo arithmetic.  */
#define SARITH16(a, b, n, op) do { \
    int32_t sum; \
    sum = (int32_t)(int16_t)(a) op (int32_t)(int16_t)(b); \
    RESULT(sum, n, 16); \
    if (sum >= 0) \
        ge |= 3 << (n * 2); \
    } while(0)

#define SARITH8(a, b, n, op) do { \
    int32_t sum; \
    sum = (int32_t)(int8_t)(a) op (int32_t)(int8_t)(b); \
    RESULT(sum, n, 8); \
    if (sum >= 0) \
        ge |= 1 << n; \
    } while(0)


#define ADD16(a, b, n) SARITH16(a, b, n, +)
#define SUB16(a, b, n) SARITH16(a, b, n, -)
#define ADD8(a, b, n)  SARITH8(a, b, n, +)
#define SUB8(a, b, n)  SARITH8(a, b, n, -)
#define PFX s
#define ARITH_GE

#include "op_addsub.h"

/* Unsigned modulo arithmetic.  */
#define ADD16(a, b, n) do { \
    uint32_t sum; \
    sum = (uint32_t)(uint16_t)(a) + (uint32_t)(uint16_t)(b); \
    RESULT(sum, n, 16); \
    if ((sum >> 16) == 1) \
        ge |= 3 << (n * 2); \
    } while(0)

#define ADD8(a, b, n) do { \
    uint32_t sum; \
    sum = (uint32_t)(uint8_t)(a) + (uint32_t)(uint8_t)(b); \
    RESULT(sum, n, 8); \
    if ((sum >> 8) == 1) \
        ge |= 1 << n; \
    } while(0)

#define SUB16(a, b, n) do { \
    uint32_t sum; \
    sum = (uint32_t)(uint16_t)(a) - (uint32_t)(uint16_t)(b); \
    RESULT(sum, n, 16); \
    if ((sum >> 16) == 0) \
        ge |= 3 << (n * 2); \
    } while(0)

#define SUB8(a, b, n) do { \
    uint32_t sum; \
    sum = (uint32_t)(uint8_t)(a) - (uint32_t)(uint8_t)(b); \
    RESULT(sum, n, 8); \
    if ((sum >> 8) == 0) \
        ge |= 1 << n; \
    } while(0)

#define PFX u
#define ARITH_GE

#include "op_addsub.h"

/* Halved signed arithmetic.  */
#define ADD16(a, b, n) \
  RESULT(((int32_t)(int16_t)(a) + (int32_t)(int16_t)(b)) >> 1, n, 16)
#define SUB16(a, b, n) \
  RESULT(((int32_t)(int16_t)(a) - (int32_t)(int16_t)(b)) >> 1, n, 16)
#define ADD8(a, b, n) \
  RESULT(((int32_t)(int8_t)(a) + (int32_t)(int8_t)(b)) >> 1, n, 8)
#define SUB8(a, b, n) \
  RESULT(((int32_t)(int8_t)(a) - (int32_t)(int8_t)(b)) >> 1, n, 8)
#define PFX sh

#include "op_addsub.h"

/* Halved unsigned arithmetic.  */
#define ADD16(a, b, n) \
  RESULT(((uint32_t)(uint16_t)(a) + (uint32_t)(uint16_t)(b)) >> 1, n, 16)
#define SUB16(a, b, n) \
  RESULT(((uint32_t)(uint16_t)(a) - (uint32_t)(uint16_t)(b)) >> 1, n, 16)
#define ADD8(a, b, n) \
  RESULT(((uint32_t)(uint8_t)(a) + (uint32_t)(uint8_t)(b)) >> 1, n, 8)
#define SUB8(a, b, n) \
  RESULT(((uint32_t)(uint8_t)(a) - (uint32_t)(uint8_t)(b)) >> 1, n, 8)
#define PFX uh

#include "op_addsub.h"

static inline uint8_t do_usad(uint8_t a, uint8_t b)
{
    if (a > b)
        return a - b;
    else
        return b - a;
}

/* Unsigned sum of absolute byte differences.  */
uint32_t HELPER(usad8)(uint32_t a, uint32_t b)
{
    uint32_t sum;
    sum = do_usad(a, b);
    sum += do_usad(a >> 8, b >> 8);
    sum += do_usad(a >> 16, b >>16);
    sum += do_usad(a >> 24, b >> 24);
    return sum;
}

/* For ARMv6 SEL instruction.  */
uint32_t HELPER(sel_flags)(uint32_t flags, uint32_t a, uint32_t b)
{
    uint32_t mask;

    mask = 0;
    if (flags & 1)
        mask |= 0xff;
    if (flags & 2)
        mask |= 0xff00;
    if (flags & 4)
        mask |= 0xff0000;
    if (flags & 8)
        mask |= 0xff000000;
    return (a & mask) | (b & ~mask);
}

/* VFP support.  We follow the convention used for VFP instructions:
   Single precision routines have a "s" suffix, double precision a
   "d" suffix.  */

/* Convert host exception flags to vfp form.  */
static inline int vfp_exceptbits_from_host(int host_bits)
{
    int target_bits = 0;

    if (host_bits & float_flag_invalid)
        target_bits |= 1;
    if (host_bits & float_flag_divbyzero)
        target_bits |= 2;
    if (host_bits & float_flag_overflow)
        target_bits |= 4;
    if (host_bits & (float_flag_underflow | float_flag_output_denormal))
        target_bits |= 8;
    if (host_bits & float_flag_inexact)
        target_bits |= 0x10;
    if (host_bits & float_flag_input_denormal)
        target_bits |= 0x80;
    return target_bits;
}

uint32_t HELPER(vfp_get_fpscr)(CPUARMState *env)
{
    int i;
    uint32_t fpscr;

    fpscr = (env->vfp.xregs[ARM_VFP_FPSCR] & 0xffc8ffff)
            | (env->vfp.vec_len << 16)
            | (env->vfp.vec_stride << 20);
    i = get_float_exception_flags(&env->vfp.fp_status);
    i |= get_float_exception_flags(&env->vfp.standard_fp_status);
    fpscr |= vfp_exceptbits_from_host(i);
    return fpscr;
}

uint32_t vfp_get_fpscr(CPUARMState *env)
{
    return HELPER(vfp_get_fpscr)(env);
}

/* Convert vfp exception flags to target form.  */
static inline int vfp_exceptbits_to_host(int target_bits)
{
    int host_bits = 0;

    if (target_bits & 1)
        host_bits |= float_flag_invalid;
    if (target_bits & 2)
        host_bits |= float_flag_divbyzero;
    if (target_bits & 4)
        host_bits |= float_flag_overflow;
    if (target_bits & 8)
        host_bits |= float_flag_underflow;
    if (target_bits & 0x10)
        host_bits |= float_flag_inexact;
    if (target_bits & 0x80)
        host_bits |= float_flag_input_denormal;
    return host_bits;
}

void HELPER(vfp_set_fpscr)(CPUARMState *env, uint32_t val)
{
    int i;
    uint32_t changed;

    changed = env->vfp.xregs[ARM_VFP_FPSCR];
    env->vfp.xregs[ARM_VFP_FPSCR] = (val & 0xffc8ffff);
    env->vfp.vec_len = (val >> 16) & 7;
    env->vfp.vec_stride = (val >> 20) & 3;

    changed ^= val;
    if (changed & (3 << 22)) {
        i = (val >> 22) & 3;
        switch (i) {
        case FPROUNDING_TIEEVEN:
            i = float_round_nearest_even;
            break;
        case FPROUNDING_POSINF:
            i = float_round_up;
            break;
        case FPROUNDING_NEGINF:
            i = float_round_down;
            break;
        case FPROUNDING_ZERO:
            i = float_round_to_zero;
            break;
        }
        set_float_rounding_mode(i, &env->vfp.fp_status);
    }
    if (changed & (1 << 24)) {
        set_flush_to_zero((val & (1 << 24)) != 0, &env->vfp.fp_status);
        set_flush_inputs_to_zero((val & (1 << 24)) != 0, &env->vfp.fp_status);
    }
    if (changed & (1 << 25))
        set_default_nan_mode((val & (1 << 25)) != 0, &env->vfp.fp_status);

    i = vfp_exceptbits_to_host(val);
    set_float_exception_flags(i, &env->vfp.fp_status);
    set_float_exception_flags(0, &env->vfp.standard_fp_status);
}

void vfp_set_fpscr(CPUARMState *env, uint32_t val)
{
    HELPER(vfp_set_fpscr)(env, val);
}

#define VFP_HELPER(name, p) HELPER(glue(glue(vfp_,name),p))

#define VFP_BINOP(name) \
float32 VFP_HELPER(name, s)(float32 a, float32 b, void *fpstp) \
{ \
    float_status *fpst = fpstp; \
    return float32_ ## name(a, b, fpst); \
} \
float64 VFP_HELPER(name, d)(float64 a, float64 b, void *fpstp) \
{ \
    float_status *fpst = fpstp; \
    return float64_ ## name(a, b, fpst); \
}
VFP_BINOP(add)
VFP_BINOP(sub)
VFP_BINOP(mul)
VFP_BINOP(div)
VFP_BINOP(min)
VFP_BINOP(max)
VFP_BINOP(minnum)
VFP_BINOP(maxnum)
#undef VFP_BINOP

float32 VFP_HELPER(neg, s)(float32 a)
{
    return float32_chs(a);
}

float64 VFP_HELPER(neg, d)(float64 a)
{
    return float64_chs(a);
}

float32 VFP_HELPER(abs, s)(float32 a)
{
    return float32_abs(a);
}

float64 VFP_HELPER(abs, d)(float64 a)
{
    return float64_abs(a);
}

float32 VFP_HELPER(sqrt, s)(float32 a, CPUARMState *env)
{
    return float32_sqrt(a, &env->vfp.fp_status);
}

float64 VFP_HELPER(sqrt, d)(float64 a, CPUARMState *env)
{
    return float64_sqrt(a, &env->vfp.fp_status);
}

/* XXX: check quiet/signaling case */
#define DO_VFP_cmp(p, type) \
void VFP_HELPER(cmp, p)(type a, type b, CPUARMState *env)  \
{ \
    uint32_t flags; \
    switch(type ## _compare_quiet(a, b, &env->vfp.fp_status)) { \
    case 0: flags = 0x6; break; \
    case -1: flags = 0x8; break; \
    case 1: flags = 0x2; break; \
    default: case 2: flags = 0x3; break; \
    } \
    env->vfp.xregs[ARM_VFP_FPSCR] = (flags << 28) \
        | (env->vfp.xregs[ARM_VFP_FPSCR] & 0x0fffffff); \
} \
void VFP_HELPER(cmpe, p)(type a, type b, CPUARMState *env) \
{ \
    uint32_t flags; \
    switch(type ## _compare(a, b, &env->vfp.fp_status)) { \
    case 0: flags = 0x6; break; \
    case -1: flags = 0x8; break; \
    case 1: flags = 0x2; break; \
    default: case 2: flags = 0x3; break; \
    } \
    env->vfp.xregs[ARM_VFP_FPSCR] = (flags << 28) \
        | (env->vfp.xregs[ARM_VFP_FPSCR] & 0x0fffffff); \
}
DO_VFP_cmp(s, float32)
DO_VFP_cmp(d, float64)
#undef DO_VFP_cmp

/* Integer to float and float to integer conversions */

#define CONV_ITOF(name, fsz, sign) \
    float##fsz HELPER(name)(uint32_t x, void *fpstp) \
{ \
    float_status *fpst = fpstp; \
    return sign##int32_to_##float##fsz((sign##int32_t)x, fpst); \
}

#define CONV_FTOI(name, fsz, sign, round) \
uint32_t HELPER(name)(float##fsz x, void *fpstp) \
{ \
    float_status *fpst = fpstp; \
    if (float##fsz##_is_any_nan(x)) { \
        float_raise(float_flag_invalid, fpst); \
        return 0; \
    } \
    return float##fsz##_to_##sign##int32##round(x, fpst); \
}

#define FLOAT_CONVS(name, p, fsz, sign) \
CONV_ITOF(vfp_##name##to##p, fsz, sign) \
CONV_FTOI(vfp_to##name##p, fsz, sign, ) \
CONV_FTOI(vfp_to##name##z##p, fsz, sign, _round_to_zero)

FLOAT_CONVS(si, s, 32, )
FLOAT_CONVS(si, d, 64, )
FLOAT_CONVS(ui, s, 32, u)
FLOAT_CONVS(ui, d, 64, u)

#undef CONV_ITOF
#undef CONV_FTOI
#undef FLOAT_CONVS

/* floating point conversion */
float64 VFP_HELPER(fcvtd, s)(float32 x, CPUARMState *env)
{
    float64 r = float32_to_float64(x, &env->vfp.fp_status);
    /* ARM requires that S<->D conversion of any kind of NaN generates
     * a quiet NaN by forcing the most significant frac bit to 1.
     */
    return float64_maybe_silence_nan(r);
}

float32 VFP_HELPER(fcvts, d)(float64 x, CPUARMState *env)
{
    float32 r =  float64_to_float32(x, &env->vfp.fp_status);
    /* ARM requires that S<->D conversion of any kind of NaN generates
     * a quiet NaN by forcing the most significant frac bit to 1.
     */
    return float32_maybe_silence_nan(r);
}

/* VFP3 fixed point conversion.  */
#define VFP_CONV_FIX_FLOAT(name, p, fsz, isz, itype) \
float##fsz HELPER(vfp_##name##to##p)(uint##isz##_t  x, uint32_t shift, \
                                     void *fpstp) \
{ \
    float_status *fpst = fpstp; \
    float##fsz tmp; \
    tmp = itype##_to_##float##fsz(x, fpst); \
    return float##fsz##_scalbn(tmp, -(int)shift, fpst); \
}

/* Notice that we want only input-denormal exception flags from the
 * scalbn operation: the other possible flags (overflow+inexact if
 * we overflow to infinity, output-denormal) aren't correct for the
 * complete scale-and-convert operation.
 */
#define VFP_CONV_FLOAT_FIX_ROUND(name, p, fsz, isz, itype, round) \
uint##isz##_t HELPER(vfp_to##name##p##round)(float##fsz x, \
                                             uint32_t shift, \
                                             void *fpstp) \
{ \
    float_status *fpst = fpstp; \
    int old_exc_flags = get_float_exception_flags(fpst); \
    float##fsz tmp; \
    if (float##fsz##_is_any_nan(x)) { \
        float_raise(float_flag_invalid, fpst); \
        return 0; \
    } \
    tmp = float##fsz##_scalbn(x, shift, fpst); \
    old_exc_flags |= get_float_exception_flags(fpst) \
        & float_flag_input_denormal; \
    set_float_exception_flags(old_exc_flags, fpst); \
    return float##fsz##_to_##itype##round(tmp, fpst); \
}

#define VFP_CONV_FIX(name, p, fsz, isz, itype)                   \
VFP_CONV_FIX_FLOAT(name, p, fsz, isz, itype)                     \
VFP_CONV_FLOAT_FIX_ROUND(name, p, fsz, isz, itype, _round_to_zero) \
VFP_CONV_FLOAT_FIX_ROUND(name, p, fsz, isz, itype, )

#define VFP_CONV_FIX_A64(name, p, fsz, isz, itype)               \
VFP_CONV_FIX_FLOAT(name, p, fsz, isz, itype)                     \
VFP_CONV_FLOAT_FIX_ROUND(name, p, fsz, isz, itype, )

VFP_CONV_FIX(sh, d, 64, 64, int16)
VFP_CONV_FIX(sl, d, 64, 64, int32)
VFP_CONV_FIX_A64(sq, d, 64, 64, int64)
VFP_CONV_FIX(uh, d, 64, 64, uint16)
VFP_CONV_FIX(ul, d, 64, 64, uint32)
VFP_CONV_FIX_A64(uq, d, 64, 64, uint64)
VFP_CONV_FIX(sh, s, 32, 32, int16)
VFP_CONV_FIX(sl, s, 32, 32, int32)
VFP_CONV_FIX_A64(sq, s, 32, 64, int64)
VFP_CONV_FIX(uh, s, 32, 32, uint16)
VFP_CONV_FIX(ul, s, 32, 32, uint32)
VFP_CONV_FIX_A64(uq, s, 32, 64, uint64)
#undef VFP_CONV_FIX
#undef VFP_CONV_FIX_FLOAT
#undef VFP_CONV_FLOAT_FIX_ROUND

/* Set the current fp rounding mode and return the old one.
 * The argument is a softfloat float_round_ value.
 */
uint32_t HELPER(set_rmode)(uint32_t rmode, CPUARMState *env)
{
    float_status *fp_status = &env->vfp.fp_status;

    uint32_t prev_rmode = get_float_rounding_mode(fp_status);
    set_float_rounding_mode(rmode, fp_status);

    return prev_rmode;
}

/* Set the current fp rounding mode in the standard fp status and return
 * the old one. This is for NEON instructions that need to change the
 * rounding mode but wish to use the standard FPSCR values for everything
 * else. Always set the rounding mode back to the correct value after
 * modifying it.
 * The argument is a softfloat float_round_ value.
 */
uint32_t HELPER(set_neon_rmode)(uint32_t rmode, CPUARMState *env)
{
    float_status *fp_status = &env->vfp.standard_fp_status;

    uint32_t prev_rmode = get_float_rounding_mode(fp_status);
    set_float_rounding_mode(rmode, fp_status);

    return prev_rmode;
}

/* Half precision conversions.  */
static float32 do_fcvt_f16_to_f32(uint32_t a, CPUARMState *env, float_status *s)
{
    int ieee = (env->vfp.xregs[ARM_VFP_FPSCR] & (1 << 26)) == 0;
    float32 r = float16_to_float32(make_float16(a), ieee, s);
    if (ieee) {
        return float32_maybe_silence_nan(r);
    }
    return r;
}

static uint32_t do_fcvt_f32_to_f16(float32 a, CPUARMState *env, float_status *s)
{
    int ieee = (env->vfp.xregs[ARM_VFP_FPSCR] & (1 << 26)) == 0;
    float16 r = float32_to_float16(a, ieee, s);
    if (ieee) {
        r = float16_maybe_silence_nan(r);
    }
    return float16_val(r);
}

float32 HELPER(neon_fcvt_f16_to_f32)(uint32_t a, CPUARMState *env)
{
    return do_fcvt_f16_to_f32(a, env, &env->vfp.standard_fp_status);
}

uint32_t HELPER(neon_fcvt_f32_to_f16)(float32 a, CPUARMState *env)
{
    return do_fcvt_f32_to_f16(a, env, &env->vfp.standard_fp_status);
}

float32 HELPER(vfp_fcvt_f16_to_f32)(uint32_t a, CPUARMState *env)
{
    return do_fcvt_f16_to_f32(a, env, &env->vfp.fp_status);
}

uint32_t HELPER(vfp_fcvt_f32_to_f16)(float32 a, CPUARMState *env)
{
    return do_fcvt_f32_to_f16(a, env, &env->vfp.fp_status);
}

float64 HELPER(vfp_fcvt_f16_to_f64)(uint32_t a, CPUARMState *env)
{
    int ieee = (env->vfp.xregs[ARM_VFP_FPSCR] & (1 << 26)) == 0;
    float64 r = float16_to_float64(make_float16(a), ieee, &env->vfp.fp_status);
    if (ieee) {
        return float64_maybe_silence_nan(r);
    }
    return r;
}

uint32_t HELPER(vfp_fcvt_f64_to_f16)(float64 a, CPUARMState *env)
{
    int ieee = (env->vfp.xregs[ARM_VFP_FPSCR] & (1 << 26)) == 0;
    float16 r = float64_to_float16(a, ieee, &env->vfp.fp_status);
    if (ieee) {
        r = float16_maybe_silence_nan(r);
    }
    return float16_val(r);
}

#define float32_two make_float32(0x40000000)
#define float32_three make_float32(0x40400000)
#define float32_one_point_five make_float32(0x3fc00000)

float32 HELPER(recps_f32)(float32 a, float32 b, CPUARMState *env)
{
    float_status *s = &env->vfp.standard_fp_status;
    if ((float32_is_infinity(a) && float32_is_zero_or_denormal(b)) ||
        (float32_is_infinity(b) && float32_is_zero_or_denormal(a))) {
        if (!(float32_is_zero(a) || float32_is_zero(b))) {
            float_raise(float_flag_input_denormal, s);
        }
        return float32_two;
    }
    return float32_sub(float32_two, float32_mul(a, b, s), s);
}

float32 HELPER(rsqrts_f32)(float32 a, float32 b, CPUARMState *env)
{
    float_status *s = &env->vfp.standard_fp_status;
    float32 product;
    if ((float32_is_infinity(a) && float32_is_zero_or_denormal(b)) ||
        (float32_is_infinity(b) && float32_is_zero_or_denormal(a))) {
        if (!(float32_is_zero(a) || float32_is_zero(b))) {
            float_raise(float_flag_input_denormal, s);
        }
        return float32_one_point_five;
    }
    product = float32_mul(a, b, s);
    return float32_div(float32_sub(float32_three, product, s), float32_two, s);
}

/* NEON helpers.  */

/* Constants 256 and 512 are used in some helpers; we avoid relying on
 * int->float conversions at run-time.  */
#define float64_256 make_float64(0x4070000000000000LL)
#define float64_512 make_float64(0x4080000000000000LL)
#define float32_maxnorm make_float32(0x7f7fffff)
#define float64_maxnorm make_float64(0x7fefffffffffffffLL)

/* Reciprocal functions
 *
 * The algorithm that must be used to calculate the estimate
 * is specified by the ARM ARM, see FPRecipEstimate()
 */

static float64 recip_estimate(float64 a, float_status *real_fp_status)
{
    /* These calculations mustn't set any fp exception flags,
     * so we use a local copy of the fp_status.
     */
    float_status dummy_status = *real_fp_status;
    float_status *s = &dummy_status;
    /* q = (int)(a * 512.0) */
    float64 q = float64_mul(float64_512, a, s);
    int64_t q_int = float64_to_int64_round_to_zero(q, s);

    /* r = 1.0 / (((double)q + 0.5) / 512.0) */
    q = int64_to_float64(q_int, s);
    q = float64_add(q, float64_half, s);
    q = float64_div(q, float64_512, s);
    q = float64_div(float64_one, q, s);

    /* s = (int)(256.0 * r + 0.5) */
    q = float64_mul(q, float64_256, s);
    q = float64_add(q, float64_half, s);
    q_int = float64_to_int64_round_to_zero(q, s);

    /* return (double)s / 256.0 */
    return float64_div(int64_to_float64(q_int, s), float64_256, s);
}

/* Common wrapper to call recip_estimate */
static float64 call_recip_estimate(float64 num, int off, float_status *fpst)
{
    uint64_t val64 = float64_val(num);
    uint64_t frac = extract64(val64, 0, 52);
    int64_t exp = extract64(val64, 52, 11);
    uint64_t sbit;
    float64 scaled, estimate;

    /* Generate the scaled number for the estimate function */
    if (exp == 0) {
        if (extract64(frac, 51, 1) == 0) {
            exp = -1;
            frac = extract64(frac, 0, 50) << 2;
        } else {
            frac = extract64(frac, 0, 51) << 1;
        }
    }

    /* scaled = '0' : '01111111110' : fraction<51:44> : Zeros(44); */
    scaled = make_float64((0x3feULL << 52)
                          | extract64(frac, 44, 8) << 44);

    estimate = recip_estimate(scaled, fpst);

    /* Build new result */
    val64 = float64_val(estimate);
    sbit = 0x8000000000000000ULL & val64;
    exp = off - exp;
    frac = extract64(val64, 0, 52);

    if (exp == 0) {
        frac = 1ULL << 51 | extract64(frac, 1, 51);
    } else if (exp == -1) {
        frac = 1ULL << 50 | extract64(frac, 2, 50);
        exp = 0;
    }

    return make_float64(sbit | (exp << 52) | frac);
}

static bool round_to_inf(float_status *fpst, bool sign_bit)
{
    switch (fpst->float_rounding_mode) {
    case float_round_nearest_even: /* Round to Nearest */
        return true;
    case float_round_up: /* Round to +Inf */
        return !sign_bit;
    case float_round_down: /* Round to -Inf */
        return sign_bit;
    case float_round_to_zero: /* Round to Zero */
        return false;
    default:
        break;
    }

    g_assert_not_reached();
    return false;
}

float32 HELPER(recpe_f32)(float32 input, void *fpstp)
{
    float_status *fpst = fpstp;
    float32 f32 = float32_squash_input_denormal(input, fpst);
    uint32_t f32_val = float32_val(f32);
    uint32_t f32_sbit = 0x80000000ULL & f32_val;
    int32_t f32_exp = extract32(f32_val, 23, 8);
    uint32_t f32_frac = extract32(f32_val, 0, 23);
    float64 f64, r64;
    uint64_t r64_val;
    int64_t r64_exp;
    uint64_t r64_frac;

    if (float32_is_any_nan(f32)) {
        float32 nan = f32;
        if (float32_is_signaling_nan(f32)) {
            float_raise(float_flag_invalid, fpst);
            nan = float32_maybe_silence_nan(f32);
        }
        if (fpst->default_nan_mode) {
            nan =  float32_default_nan;
        }
        return nan;
    } else if (float32_is_infinity(f32)) {
        return float32_set_sign(float32_zero, float32_is_neg(f32));
    } else if (float32_is_zero(f32)) {
        float_raise(float_flag_divbyzero, fpst);
        return float32_set_sign(float32_infinity, float32_is_neg(f32));
    } else if ((f32_val & ~(1ULL << 31)) < (1ULL << 21)) {
        /* Abs(value) < 2.0^-128 */
        float_raise(float_flag_overflow | float_flag_inexact, fpst);
        if (round_to_inf(fpst, f32_sbit)) {
            return float32_set_sign(float32_infinity, float32_is_neg(f32));
        } else {
            return float32_set_sign(float32_maxnorm, float32_is_neg(f32));
        }
    } else if (f32_exp >= 253 && fpst->flush_to_zero) {
        float_raise(float_flag_underflow, fpst);
        return float32_set_sign(float32_zero, float32_is_neg(f32));
    }


    f64 = make_float64(((int64_t)(f32_exp) << 52) | (int64_t)(f32_frac) << 29);
    r64 = call_recip_estimate(f64, 253, fpst);
    r64_val = float64_val(r64);
    r64_exp = extract64(r64_val, 52, 11);
    r64_frac = extract64(r64_val, 0, 52);

    /* result = sign : result_exp<7:0> : fraction<51:29>; */
    return make_float32(f32_sbit |
                        (r64_exp & 0xff) << 23 |
                        extract64(r64_frac, 29, 24));
}

float64 HELPER(recpe_f64)(float64 input, void *fpstp)
{
    float_status *fpst = fpstp;
    float64 f64 = float64_squash_input_denormal(input, fpst);
    uint64_t f64_val = float64_val(f64);
    uint64_t f64_sbit = 0x8000000000000000ULL & f64_val;
    int64_t f64_exp = extract64(f64_val, 52, 11);
    float64 r64;
    uint64_t r64_val;
    int64_t r64_exp;
    uint64_t r64_frac;

    /* Deal with any special cases */
    if (float64_is_any_nan(f64)) {
        float64 nan = f64;
        if (float64_is_signaling_nan(f64)) {
            float_raise(float_flag_invalid, fpst);
            nan = float64_maybe_silence_nan(f64);
        }
        if (fpst->default_nan_mode) {
            nan =  float64_default_nan;
        }
        return nan;
    } else if (float64_is_infinity(f64)) {
        return float64_set_sign(float64_zero, float64_is_neg(f64));
    } else if (float64_is_zero(f64)) {
        float_raise(float_flag_divbyzero, fpst);
        return float64_set_sign(float64_infinity, float64_is_neg(f64));
    } else if ((f64_val & ~(1ULL << 63)) < (1ULL << 50)) {
        /* Abs(value) < 2.0^-1024 */
        float_raise(float_flag_overflow | float_flag_inexact, fpst);
        if (round_to_inf(fpst, f64_sbit)) {
            return float64_set_sign(float64_infinity, float64_is_neg(f64));
        } else {
            return float64_set_sign(float64_maxnorm, float64_is_neg(f64));
        }
    } else if (f64_exp >= 1023 && fpst->flush_to_zero) {
        float_raise(float_flag_underflow, fpst);
        return float64_set_sign(float64_zero, float64_is_neg(f64));
    }

    r64 = call_recip_estimate(f64, 2045, fpst);
    r64_val = float64_val(r64);
    r64_exp = extract64(r64_val, 52, 11);
    r64_frac = extract64(r64_val, 0, 52);

    /* result = sign : result_exp<10:0> : fraction<51:0> */
    return make_float64(f64_sbit |
                        ((r64_exp & 0x7ff) << 52) |
                        r64_frac);
}

/* The algorithm that must be used to calculate the estimate
 * is specified by the ARM ARM.
 */
static float64 recip_sqrt_estimate(float64 a, float_status *real_fp_status)
{
    /* These calculations mustn't set any fp exception flags,
     * so we use a local copy of the fp_status.
     */
    float_status dummy_status = *real_fp_status;
    float_status *s = &dummy_status;
    float64 q;
    int64_t q_int;

    if (float64_lt(a, float64_half, s)) {
        /* range 0.25 <= a < 0.5 */

        /* a in units of 1/512 rounded down */
        /* q0 = (int)(a * 512.0);  */
        q = float64_mul(float64_512, a, s);
        q_int = float64_to_int64_round_to_zero(q, s);

        /* reciprocal root r */
        /* r = 1.0 / sqrt(((double)q0 + 0.5) / 512.0);  */
        q = int64_to_float64(q_int, s);
        q = float64_add(q, float64_half, s);
        q = float64_div(q, float64_512, s);
        q = float64_sqrt(q, s);
        q = float64_div(float64_one, q, s);
    } else {
        /* range 0.5 <= a < 1.0 */

        int64_t q_int;

        /* a in units of 1/256 rounded down */
        /* q1 = (int)(a * 256.0); */
        q = float64_mul(float64_256, a, s);
        q_int = float64_to_int64_round_to_zero(q, s);

        /* reciprocal root r */
        /* r = 1.0 /sqrt(((double)q1 + 0.5) / 256); */
        q = int64_to_float64(q_int, s);
        q = float64_add(q, float64_half, s);
        q = float64_div(q, float64_256, s);
        q = float64_sqrt(q, s);
        q = float64_div(float64_one, q, s);
    }
    /* r in units of 1/256 rounded to nearest */
    /* s = (int)(256.0 * r + 0.5); */

    q = float64_mul(q, float64_256,s );
    q = float64_add(q, float64_half, s);
    q_int = float64_to_int64_round_to_zero(q, s);

    /* return (double)s / 256.0;*/
    return float64_div(int64_to_float64(q_int, s), float64_256, s);
}

float32 HELPER(rsqrte_f32)(float32 input, void *fpstp)
{
    float_status *s = fpstp;
    float32 f32 = float32_squash_input_denormal(input, s);
    uint32_t val = float32_val(f32);
    uint32_t f32_sbit = 0x80000000 & val;
    int32_t f32_exp = extract32(val, 23, 8);
    uint32_t f32_frac = extract32(val, 0, 23);
    uint64_t f64_frac;
    uint64_t val64;
    int result_exp;
    float64 f64;

    if (float32_is_any_nan(f32)) {
        float32 nan = f32;
        if (float32_is_signaling_nan(f32)) {
            float_raise(float_flag_invalid, s);
            nan = float32_maybe_silence_nan(f32);
        }
        if (s->default_nan_mode) {
            nan =  float32_default_nan;
        }
        return nan;
    } else if (float32_is_zero(f32)) {
        float_raise(float_flag_divbyzero, s);
        return float32_set_sign(float32_infinity, float32_is_neg(f32));
    } else if (float32_is_neg(f32)) {
        float_raise(float_flag_invalid, s);
        return float32_default_nan;
    } else if (float32_is_infinity(f32)) {
        return float32_zero;
    }

    /* Scale and normalize to a double-precision value between 0.25 and 1.0,
     * preserving the parity of the exponent.  */

    f64_frac = ((uint64_t) f32_frac) << 29;
    if (f32_exp == 0) {
        while (extract64(f64_frac, 51, 1) == 0) {
            f64_frac = f64_frac << 1;
            f32_exp = f32_exp-1;
        }
        f64_frac = extract64(f64_frac, 0, 51) << 1;
    }

    if (extract64(f32_exp, 0, 1) == 0) {
        f64 = make_float64(((uint64_t) f32_sbit) << 32
                           | (0x3feULL << 52)
                           | f64_frac);
    } else {
        f64 = make_float64(((uint64_t) f32_sbit) << 32
                           | (0x3fdULL << 52)
                           | f64_frac);
    }

    result_exp = (380 - f32_exp) / 2;

    f64 = recip_sqrt_estimate(f64, s);

    val64 = float64_val(f64);

    val = ((result_exp & 0xff) << 23)
        | ((val64 >> 29)  & 0x7fffff);
    return make_float32(val);
}

float64 HELPER(rsqrte_f64)(float64 input, void *fpstp)
{
    float_status *s = fpstp;
    float64 f64 = float64_squash_input_denormal(input, s);
    uint64_t val = float64_val(f64);
    uint64_t f64_sbit = 0x8000000000000000ULL & val;
    int64_t f64_exp = extract64(val, 52, 11);
    uint64_t f64_frac = extract64(val, 0, 52);
    int64_t result_exp;
    uint64_t result_frac;

    if (float64_is_any_nan(f64)) {
        float64 nan = f64;
        if (float64_is_signaling_nan(f64)) {
            float_raise(float_flag_invalid, s);
            nan = float64_maybe_silence_nan(f64);
        }
        if (s->default_nan_mode) {
            nan =  float64_default_nan;
        }
        return nan;
    } else if (float64_is_zero(f64)) {
        float_raise(float_flag_divbyzero, s);
        return float64_set_sign(float64_infinity, float64_is_neg(f64));
    } else if (float64_is_neg(f64)) {
        float_raise(float_flag_invalid, s);
        return float64_default_nan;
    } else if (float64_is_infinity(f64)) {
        return float64_zero;
    }

    /* Scale and normalize to a double-precision value between 0.25 and 1.0,
     * preserving the parity of the exponent.  */

    if (f64_exp == 0) {
        while (extract64(f64_frac, 51, 1) == 0) {
            f64_frac = f64_frac << 1;
            f64_exp = f64_exp - 1;
        }
        f64_frac = extract64(f64_frac, 0, 51) << 1;
    }

    if (extract64(f64_exp, 0, 1) == 0) {
        f64 = make_float64(f64_sbit
                           | (0x3feULL << 52)
                           | f64_frac);
    } else {
        f64 = make_float64(f64_sbit
                           | (0x3fdULL << 52)
                           | f64_frac);
    }

    result_exp = (3068 - f64_exp) / 2;

    f64 = recip_sqrt_estimate(f64, s);

    result_frac = extract64(float64_val(f64), 0, 52);

    return make_float64(f64_sbit |
                        ((result_exp & 0x7ff) << 52) |
                        result_frac);
}

uint32_t HELPER(recpe_u32)(uint32_t a, void *fpstp)
{
    float_status *s = fpstp;
    float64 f64;

    if ((a & 0x80000000) == 0) {
        return 0xffffffff;
    }

    f64 = make_float64((0x3feULL << 52)
                       | ((int64_t)(a & 0x7fffffff) << 21));

    f64 = recip_estimate(f64, s);

    return 0x80000000 | ((float64_val(f64) >> 21) & 0x7fffffff);
}

uint32_t HELPER(rsqrte_u32)(uint32_t a, void *fpstp)
{
    float_status *fpst = fpstp;
    float64 f64;

    if ((a & 0xc0000000) == 0) {
        return 0xffffffff;
    }

    if (a & 0x80000000) {
        f64 = make_float64((0x3feULL << 52)
                           | ((uint64_t)(a & 0x7fffffff) << 21));
    } else { /* bits 31-30 == '01' */
        f64 = make_float64((0x3fdULL << 52)
                           | ((uint64_t)(a & 0x3fffffff) << 22));
    }

    f64 = recip_sqrt_estimate(f64, fpst);

    return 0x80000000 | ((float64_val(f64) >> 21) & 0x7fffffff);
}

/* VFPv4 fused multiply-accumulate */
float32 VFP_HELPER(muladd, s)(float32 a, float32 b, float32 c, void *fpstp)
{
    float_status *fpst = fpstp;
    return float32_muladd(a, b, c, 0, fpst);
}

float64 VFP_HELPER(muladd, d)(float64 a, float64 b, float64 c, void *fpstp)
{
    float_status *fpst = fpstp;
    return float64_muladd(a, b, c, 0, fpst);
}

/* ARMv8 round to integral */
float32 HELPER(rints_exact)(float32 x, void *fp_status)
{
    return float32_round_to_int(x, fp_status);
}

float64 HELPER(rintd_exact)(float64 x, void *fp_status)
{
    return float64_round_to_int(x, fp_status);
}

float32 HELPER(rints)(float32 x, void *fp_status)
{
    int old_flags = get_float_exception_flags(fp_status), new_flags;
    float32 ret;

    ret = float32_round_to_int(x, fp_status);

    /* Suppress any inexact exceptions the conversion produced */
    if (!(old_flags & float_flag_inexact)) {
        new_flags = get_float_exception_flags(fp_status);
        set_float_exception_flags(new_flags & ~float_flag_inexact, fp_status);
    }

    return ret;
}

float64 HELPER(rintd)(float64 x, void *fp_status)
{
    int old_flags = get_float_exception_flags(fp_status), new_flags;
    float64 ret;

    ret = float64_round_to_int(x, fp_status);

    new_flags = get_float_exception_flags(fp_status);

    /* Suppress any inexact exceptions the conversion produced */
    if (!(old_flags & float_flag_inexact)) {
        new_flags = get_float_exception_flags(fp_status);
        set_float_exception_flags(new_flags & ~float_flag_inexact, fp_status);
    }

    return ret;
}

/* Convert ARM rounding mode to softfloat */
int arm_rmode_to_sf(int rmode)
{
    switch (rmode) {
    case FPROUNDING_TIEAWAY:
        rmode = float_round_ties_away;
        break;
    case FPROUNDING_ODD:
        /* FIXME: add support for TIEAWAY and ODD */
        qemu_log_mask(LOG_UNIMP, "arm: unimplemented rounding mode: %d\n",
                      rmode);
    case FPROUNDING_TIEEVEN:
    default:
        rmode = float_round_nearest_even;
        break;
    case FPROUNDING_POSINF:
        rmode = float_round_up;
        break;
    case FPROUNDING_NEGINF:
        rmode = float_round_down;
        break;
    case FPROUNDING_ZERO:
        rmode = float_round_to_zero;
        break;
    }
    return rmode;
}

/* CRC helpers.
 * The upper bytes of val (above the number specified by 'bytes') must have
 * been zeroed out by the caller.
 */
uint32_t HELPER(crc32_arm)(uint32_t acc, uint32_t val, uint32_t bytes)
{
#if 0   // FIXME
    uint8_t buf[4];

    stl_le_p(buf, val);

    /* zlib crc32 converts the accumulator and output to one's complement.  */
    return crc32(acc ^ 0xffffffff, buf, bytes) ^ 0xffffffff;
#endif
    return 0;
}

uint32_t HELPER(crc32c)(uint32_t acc, uint32_t val, uint32_t bytes)
{
    uint8_t buf[4];

    stl_le_p(buf, val);

    /* Linux crc32c converts the output to one's complement.  */
    return crc32c(acc, buf, bytes) ^ 0xffffffff;
}
