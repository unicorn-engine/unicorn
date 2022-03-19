/*
 *  S/390 misc helper routines
 *
 *  Copyright (c) 2009 Ulrich Hecht
 *  Copyright (c) 2009 Alexander Graf
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

#include "qemu/osdep.h"
#include "cpu.h"
#include "internal.h"
#include "exec/memory.h"
#include "qemu/host-utils.h"
#include "exec/helper-proto.h"
#include "qemu/timer.h"
#include "exec/exec-all.h"
#include "exec/cpu_ldst.h"
#include "tcg_s390x.h"
#include "s390-tod.h"

#include "sysemu/cpus.h"
#include "sysemu/sysemu.h"
#include "hw/s390x/ebcdic.h"
//#include "hw/s390x/sclp.h"
//#include "hw/s390x/s390_flic.h"
#include "hw/s390x/ioinst.h"
//#include "hw/s390x/s390-pci-inst.h"
//#include "hw/s390x/tod.h"

/* #define DEBUG_HELPER */
#ifdef DEBUG_HELPER
#define HELPER_LOG(x, ...) qemu_log(x)
#else
#define HELPER_LOG(x, ...)
#endif

/* Raise an exception statically from a TB.  */
void HELPER(exception)(CPUS390XState *env, uint32_t excp)
{
    CPUState *cs = env_cpu(env);

    HELPER_LOG("%s: exception %d\n", __func__, excp);
    cs->exception_index = excp;
    cpu_loop_exit(cs);
}

/* Store CPU Timer (also used for EXTRACT CPU TIME) */
uint64_t HELPER(stpt)(CPUS390XState *env)
{
    return time2tod(env->cputm - qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL));
}

/* Store Clock */
uint64_t HELPER(stck)(CPUS390XState *env)
{
#if 0
    S390TODState *td = s390_get_todstate();
    S390TODClass *tdc = S390_TOD_GET_CLASS(td);
    S390TOD tod;

    tdc->get(td, &tod, &error_abort);
    return tod.low;
#endif
    return 0;
}

/* SCLP service call */
uint32_t HELPER(servc)(CPUS390XState *env, uint64_t r1, uint64_t r2)
{
#if 0
    qemu_mutex_lock_iothread();
    int r = sclp_service_call(env, r1, r2);
    qemu_mutex_unlock_iothread();
    if (r < 0) {
        tcg_s390_program_interrupt(env, -r, GETPC());
    }
    return r;
#endif
    return 0;
}

void HELPER(diag)(CPUS390XState *env, uint32_t r1, uint32_t r3, uint32_t num)
{
#if 0
    uint64_t r;

    switch (num) {
    case 0x500:
        /* KVM hypercall */
        qemu_mutex_lock_iothread();
        r = s390_virtio_hypercall(env);
        qemu_mutex_unlock_iothread();
        break;
    case 0x44:
        /* yield */
        r = 0;
        break;
    case 0x308:
        /* ipl */
        qemu_mutex_lock_iothread();
        handle_diag_308(env, r1, r3, GETPC());
        qemu_mutex_unlock_iothread();
        r = 0;
        break;
    case 0x288:
        /* time bomb (watchdog) */
        r = handle_diag_288(env, r1, r3);
        break;
    default:
        r = -1;
        break;
    }

    if (r) {
        tcg_s390_program_interrupt(env, PGM_SPECIFICATION, GETPC());
    }
#endif
}

/* Set Prefix */
void HELPER(spx)(CPUS390XState *env, uint64_t a1)
{
    CPUState *cs = env_cpu(env);
    uint32_t prefix = a1 & 0x7fffe000;

    env->psa = prefix;
    HELPER_LOG("prefix: %#x\n", prefix);
    tlb_flush_page(cs, 0);
    tlb_flush_page(cs, TARGET_PAGE_SIZE);
}

static void update_ckc_timer(CPUS390XState *env)
{
#if 0
    S390TODState *td = s390_get_todstate();
    uint64_t time;

    /* stop the timer and remove pending CKC IRQs */
    timer_del(env->tod_timer);
    g_assert(qemu_mutex_iothread_locked());
    env->pending_int &= ~INTERRUPT_EXT_CLOCK_COMPARATOR;

    /* the tod has to exceed the ckc, this can never happen if ckc is all 1's */
    if (env->ckc == -1ULL) {
        return;
    }

    /* difference between origins */
    time = env->ckc - td->base.low;

    /* nanoseconds */
    time = tod2time(time);

    timer_mod(env->tod_timer, time);
#endif
}

/* Set Clock Comparator */
void HELPER(sckc)(CPUS390XState *env, uint64_t ckc)
{
#if 0
    env->ckc = ckc;

    qemu_mutex_lock_iothread();
    update_ckc_timer(env);
    qemu_mutex_unlock_iothread();
#endif
}

void tcg_s390_tod_updated(CPUState *cs, run_on_cpu_data opaque)
{
    S390CPU *cpu = S390_CPU(cs);

    update_ckc_timer(&cpu->env);
}

/* Set Clock */
uint32_t HELPER(sck)(CPUS390XState *env, uint64_t tod_low)
{
#if 0
    S390TODState *td = s390_get_todstate();
    S390TODClass *tdc = S390_TOD_GET_CLASS(td);
    S390TOD tod = {
        .high = 0,
        .low = tod_low,
    };

    qemu_mutex_lock_iothread();
    tdc->set(td, &tod, &error_abort);
    qemu_mutex_unlock_iothread();
#endif

    return 0;
}

/* Set Tod Programmable Field */
void HELPER(sckpf)(CPUS390XState *env, uint64_t r0)
{
    uint32_t val = r0;

    if (val & 0xffff0000) {
        tcg_s390_program_interrupt(env, PGM_SPECIFICATION, GETPC());
    }
    env->todpr = val;
}

/* Store Clock Comparator */
uint64_t HELPER(stckc)(CPUS390XState *env)
{
    return env->ckc;
}

/* Set CPU Timer */
void HELPER(spt)(CPUS390XState *env, uint64_t time)
{
    if (time == -1ULL) {
        return;
    }

    /* nanoseconds */
    time = tod2time(time);

    env->cputm = qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL) + time;

    // timer_mod(env->cpu_timer, env->cputm);
}

/* Store System Information */
uint32_t HELPER(stsi)(CPUS390XState *env, uint64_t a0, uint64_t r0, uint64_t r1)
{
#if 0
    const uintptr_t ra = GETPC();
    const uint32_t sel1 = r0 & STSI_R0_SEL1_MASK;
    const uint32_t sel2 = r1 & STSI_R1_SEL2_MASK;
    const MachineState *ms = MACHINE(qdev_get_machine());
    uint16_t total_cpus = 0, conf_cpus = 0, reserved_cpus = 0;
    S390CPU *cpu = env_archcpu(env);
    SysIB sysib = { };
    int i, cc = 0;

    if ((r0 & STSI_R0_FC_MASK) > STSI_R0_FC_LEVEL_3) {
        /* invalid function code: no other checks are performed */
        return 3;
    }

    if ((r0 & STSI_R0_RESERVED_MASK) || (r1 & STSI_R1_RESERVED_MASK)) {
        tcg_s390_program_interrupt(env, PGM_SPECIFICATION, ra);
    }

    if ((r0 & STSI_R0_FC_MASK) == STSI_R0_FC_CURRENT) {
        /* query the current level: no further checks are performed */
        env->regs[0] = STSI_R0_FC_LEVEL_3;
        return 0;
    }

    if (a0 & ~TARGET_PAGE_MASK) {
        tcg_s390_program_interrupt(env, PGM_SPECIFICATION, ra);
    }

    /* count the cpus and split them into configured and reserved ones */
    for (i = 0; i < ms->possible_cpus->len; i++) {
        total_cpus++;
        if (ms->possible_cpus->cpus[i].cpu) {
            conf_cpus++;
        } else {
            reserved_cpus++;
        }
    }

    /*
     * In theory, we could report Level 1 / Level 2 as current. However,
     * the Linux kernel will detect this as running under LPAR and assume
     * that we have a sclp linemode console (which is always present on
     * LPAR, but not the default for QEMU), therefore not displaying boot
     * messages and making booting a Linux kernel under TCG harder.
     *
     * For now we fake the same SMP configuration on all levels.
     *
     * TODO: We could later make the level configurable via the machine
     *       and change defaults (linemode console) based on machine type
     *       and accelerator.
     */
    switch (r0 & STSI_R0_FC_MASK) {
    case STSI_R0_FC_LEVEL_1:
        if ((sel1 == 1) && (sel2 == 1)) {
            /* Basic Machine Configuration */
            char type[5] = {};

            ebcdic_put(sysib.sysib_111.manuf, "QEMU            ", 16);
            /* same as machine type number in STORE CPU ID, but in EBCDIC */
            snprintf(type, ARRAY_SIZE(type), "%X", cpu->model->def->type);
            ebcdic_put(sysib.sysib_111.type, type, 4);
            /* model number (not stored in STORE CPU ID for z/Architecure) */
            ebcdic_put(sysib.sysib_111.model, "QEMU            ", 16);
            ebcdic_put(sysib.sysib_111.sequence, "QEMU            ", 16);
            ebcdic_put(sysib.sysib_111.plant, "QEMU", 4);
        } else if ((sel1 == 2) && (sel2 == 1)) {
            /* Basic Machine CPU */
            ebcdic_put(sysib.sysib_121.sequence, "QEMUQEMUQEMUQEMU", 16);
            ebcdic_put(sysib.sysib_121.plant, "QEMU", 4);
            sysib.sysib_121.cpu_addr = cpu_to_be16(env->core_id);
        } else if ((sel1 == 2) && (sel2 == 2)) {
            /* Basic Machine CPUs */
            sysib.sysib_122.capability = cpu_to_be32(0x443afc29);
            sysib.sysib_122.total_cpus = cpu_to_be16(total_cpus);
            sysib.sysib_122.conf_cpus = cpu_to_be16(conf_cpus);
            sysib.sysib_122.reserved_cpus = cpu_to_be16(reserved_cpus);
        } else {
            cc = 3;
        }
        break;
    case STSI_R0_FC_LEVEL_2:
        if ((sel1 == 2) && (sel2 == 1)) {
            /* LPAR CPU */
            ebcdic_put(sysib.sysib_221.sequence, "QEMUQEMUQEMUQEMU", 16);
            ebcdic_put(sysib.sysib_221.plant, "QEMU", 4);
            sysib.sysib_221.cpu_addr = cpu_to_be16(env->core_id);
        } else if ((sel1 == 2) && (sel2 == 2)) {
            /* LPAR CPUs */
            sysib.sysib_222.lcpuc = 0x80; /* dedicated */
            sysib.sysib_222.total_cpus = cpu_to_be16(total_cpus);
            sysib.sysib_222.conf_cpus = cpu_to_be16(conf_cpus);
            sysib.sysib_222.reserved_cpus = cpu_to_be16(reserved_cpus);
            ebcdic_put(sysib.sysib_222.name, "QEMU    ", 8);
            sysib.sysib_222.caf = cpu_to_be32(1000);
            sysib.sysib_222.dedicated_cpus = cpu_to_be16(conf_cpus);
        } else {
            cc = 3;
        }
        break;
    case STSI_R0_FC_LEVEL_3:
        if ((sel1 == 2) && (sel2 == 2)) {
            /* VM CPUs */
            sysib.sysib_322.count = 1;
            sysib.sysib_322.vm[0].total_cpus = cpu_to_be16(total_cpus);
            sysib.sysib_322.vm[0].conf_cpus = cpu_to_be16(conf_cpus);
            sysib.sysib_322.vm[0].reserved_cpus = cpu_to_be16(reserved_cpus);
            sysib.sysib_322.vm[0].caf = cpu_to_be32(1000);
            /* Linux kernel uses this to distinguish us from z/VM */
            ebcdic_put(sysib.sysib_322.vm[0].cpi, "KVM/Linux       ", 16);
            sysib.sysib_322.vm[0].ext_name_encoding = 2; /* UTF-8 */

            /* If our VM has a name, use the real name */
            if (qemu_name) {
                memset(sysib.sysib_322.vm[0].name, 0x40,
                       sizeof(sysib.sysib_322.vm[0].name));
                ebcdic_put(sysib.sysib_322.vm[0].name, qemu_name,
                           MIN(sizeof(sysib.sysib_322.vm[0].name),
                               strlen(qemu_name)));
                strncpy((char *)sysib.sysib_322.ext_names[0], qemu_name,
                        sizeof(sysib.sysib_322.ext_names[0]));
            } else {
                ebcdic_put(sysib.sysib_322.vm[0].name, "TCGguest", 8);
                strcpy((char *)sysib.sysib_322.ext_names[0], "TCGguest");
            }

            /* add the uuid */
            memcpy(sysib.sysib_322.vm[0].uuid, &qemu_uuid,
                   sizeof(sysib.sysib_322.vm[0].uuid));
        } else {
            cc = 3;
        }
        break;
    }

    if (cc == 0) {
        if (s390_cpu_virt_mem_write(cpu, a0, 0, &sysib, sizeof(sysib))) {
            s390_cpu_virt_mem_handle_exc(cpu, ra);
        }
    }

    return cc;
#endif

    return 0;
}

uint32_t HELPER(sigp)(CPUS390XState *env, uint64_t order_code, uint32_t r1,
                      uint32_t r3)
{
#if 0
    int cc;

    /* TODO: needed to inject interrupts  - push further down */
    qemu_mutex_lock_iothread();
    cc = handle_sigp(env, order_code & SIGP_ORDER_MASK, r1, r3);
    qemu_mutex_unlock_iothread();

    return cc;
#endif
    return 0;
}

void HELPER(xsch)(CPUS390XState *env, uint64_t r1)
{
#if 0
    S390CPU *cpu = env_archcpu(env);
    qemu_mutex_lock_iothread();
    ioinst_handle_xsch(cpu, r1, GETPC());
    qemu_mutex_unlock_iothread();
#endif
}

void HELPER(csch)(CPUS390XState *env, uint64_t r1)
{
#if 0
    S390CPU *cpu = env_archcpu(env);
    qemu_mutex_lock_iothread();
    ioinst_handle_csch(cpu, r1, GETPC());
    qemu_mutex_unlock_iothread();
#endif
}

void HELPER(hsch)(CPUS390XState *env, uint64_t r1)
{
#if 0
    S390CPU *cpu = env_archcpu(env);
    qemu_mutex_lock_iothread();
    ioinst_handle_hsch(cpu, r1, GETPC());
    qemu_mutex_unlock_iothread();
#endif
}

void HELPER(msch)(CPUS390XState *env, uint64_t r1, uint64_t inst)
{
#if 0
    S390CPU *cpu = env_archcpu(env);
    qemu_mutex_lock_iothread();
    ioinst_handle_msch(cpu, r1, inst >> 16, GETPC());
    qemu_mutex_unlock_iothread();
#endif
}

void HELPER(rchp)(CPUS390XState *env, uint64_t r1)
{
#if 0
    S390CPU *cpu = env_archcpu(env);
    qemu_mutex_lock_iothread();
    ioinst_handle_rchp(cpu, r1, GETPC());
    qemu_mutex_unlock_iothread();
#endif
}

void HELPER(rsch)(CPUS390XState *env, uint64_t r1)
{
#if 0
    S390CPU *cpu = env_archcpu(env);
    qemu_mutex_lock_iothread();
    ioinst_handle_rsch(cpu, r1, GETPC());
    qemu_mutex_unlock_iothread();
#endif
}

void HELPER(sal)(CPUS390XState *env, uint64_t r1)
{
#if 0
    S390CPU *cpu = env_archcpu(env);

    qemu_mutex_lock_iothread();
    ioinst_handle_sal(cpu, r1, GETPC());
    qemu_mutex_unlock_iothread();
#endif
}

void HELPER(schm)(CPUS390XState *env, uint64_t r1, uint64_t r2, uint64_t inst)
{
#if 0
    S390CPU *cpu = env_archcpu(env);

    qemu_mutex_lock_iothread();
    ioinst_handle_schm(cpu, r1, r2, inst >> 16, GETPC());
    qemu_mutex_unlock_iothread();
#endif
}

void HELPER(ssch)(CPUS390XState *env, uint64_t r1, uint64_t inst)
{
#if 0
    S390CPU *cpu = env_archcpu(env);
    qemu_mutex_lock_iothread();
    ioinst_handle_ssch(cpu, r1, inst >> 16, GETPC());
    qemu_mutex_unlock_iothread();
#endif
}

void HELPER(stcrw)(CPUS390XState *env, uint64_t inst)
{
#if 0
    S390CPU *cpu = env_archcpu(env);

    qemu_mutex_lock_iothread();
    ioinst_handle_stcrw(cpu, inst >> 16, GETPC());
    qemu_mutex_unlock_iothread();
#endif
}

void HELPER(stsch)(CPUS390XState *env, uint64_t r1, uint64_t inst)
{
#if 0
    S390CPU *cpu = env_archcpu(env);
    qemu_mutex_lock_iothread();
    ioinst_handle_stsch(cpu, r1, inst >> 16, GETPC());
    qemu_mutex_unlock_iothread();
#endif
}

uint32_t HELPER(tpi)(CPUS390XState *env, uint64_t addr)
{
#if 0
    const uintptr_t ra = GETPC();
    S390CPU *cpu = env_archcpu(env);
    QEMUS390FLICState *flic = s390_get_qemu_flic(s390_get_flic());
    QEMUS390FlicIO *io = NULL;
    LowCore *lowcore;

    if (addr & 0x3) {
        tcg_s390_program_interrupt(env, PGM_SPECIFICATION, ra);
    }

    qemu_mutex_lock_iothread();
    io = qemu_s390_flic_dequeue_io(flic, env->cregs[6]);
    if (!io) {
        qemu_mutex_unlock_iothread();
        return 0;
    }

    if (addr) {
        struct {
            uint16_t id;
            uint16_t nr;
            uint32_t parm;
        } intc = {
            .id = cpu_to_be16(io->id),
            .nr = cpu_to_be16(io->nr),
            .parm = cpu_to_be32(io->parm),
        };

        if (s390_cpu_virt_mem_write(cpu, addr, 0, &intc, sizeof(intc))) {
            /* writing failed, reinject and properly clean up */
            s390_io_interrupt(io->id, io->nr, io->parm, io->word);
            qemu_mutex_unlock_iothread();
            g_free(io);
            s390_cpu_virt_mem_handle_exc(cpu, ra);
            return 0;
        }
    } else {
        /* no protection applies */
        lowcore = cpu_map_lowcore(env);
        lowcore->subchannel_id = cpu_to_be16(io->id);
        lowcore->subchannel_nr = cpu_to_be16(io->nr);
        lowcore->io_int_parm = cpu_to_be32(io->parm);
        lowcore->io_int_word = cpu_to_be32(io->word);
        cpu_unmap_lowcore(env, lowcore);
    }

    g_free(io);
    qemu_mutex_unlock_iothread();
#endif
    return 1;
}

void HELPER(tsch)(CPUS390XState *env, uint64_t r1, uint64_t inst)
{
#if 0
    S390CPU *cpu = env_archcpu(env);
    qemu_mutex_lock_iothread();
    ioinst_handle_tsch(cpu, r1, inst >> 16, GETPC());
    qemu_mutex_unlock_iothread();
#endif
}

void HELPER(chsc)(CPUS390XState *env, uint64_t inst)
{
#if 0
    S390CPU *cpu = env_archcpu(env);
    qemu_mutex_lock_iothread();
    ioinst_handle_chsc(cpu, inst >> 16, GETPC());
    qemu_mutex_unlock_iothread();
#endif
}

void HELPER(per_check_exception)(CPUS390XState *env)
{
    if (env->per_perc_atmid) {
        tcg_s390_program_interrupt(env, PGM_PER, GETPC());
    }
}

/* Check if an address is within the PER starting address and the PER
   ending address.  The address range might loop.  */
static inline bool get_per_in_range(CPUS390XState *env, uint64_t addr)
{
    if (env->cregs[10] <= env->cregs[11]) {
        return env->cregs[10] <= addr && addr <= env->cregs[11];
    } else {
        return env->cregs[10] <= addr || addr <= env->cregs[11];
    }
}

void HELPER(per_branch)(CPUS390XState *env, uint64_t from, uint64_t to)
{
    if ((env->cregs[9] & PER_CR9_EVENT_BRANCH)) {
        if (!(env->cregs[9] & PER_CR9_CONTROL_BRANCH_ADDRESS)
            || get_per_in_range(env, to)) {
            env->per_address = from;
            env->per_perc_atmid = PER_CODE_EVENT_BRANCH | get_per_atmid(env);
        }
    }
}

void HELPER(per_ifetch)(CPUS390XState *env, uint64_t addr)
{
    if ((env->cregs[9] & PER_CR9_EVENT_IFETCH) && get_per_in_range(env, addr)) {
        env->per_address = addr;
        env->per_perc_atmid = PER_CODE_EVENT_IFETCH | get_per_atmid(env);

        /* If the instruction has to be nullified, trigger the
           exception immediately. */
        if (env->cregs[9] & PER_CR9_EVENT_NULLIFICATION) {
            CPUState *cs = env_cpu(env);

            env->per_perc_atmid |= PER_CODE_EVENT_NULLIFICATION;
            env->int_pgm_code = PGM_PER;
            env->int_pgm_ilen = get_ilen(cpu_ldub_code(env, addr));

            cs->exception_index = EXCP_PGM;
            cpu_loop_exit(cs);
        }
    }
}

void HELPER(per_store_real)(CPUS390XState *env)
{
    if ((env->cregs[9] & PER_CR9_EVENT_STORE) &&
        (env->cregs[9] & PER_CR9_EVENT_STORE_REAL)) {
        /* PSW is saved just before calling the helper.  */
        env->per_address = env->psw.addr;
        env->per_perc_atmid = PER_CODE_EVENT_STORE_REAL | get_per_atmid(env);
    }
}

static uint8_t stfl_bytes[2048];
static unsigned int used_stfl_bytes;

static void prepare_stfl(void)
{
#if 0
    static bool initialized;
    int i;

    /* racy, but we don't care, the same values are always written */
    if (initialized) {
        return;
    }

    s390_get_feat_block(S390_FEAT_TYPE_STFL, stfl_bytes);
    for (i = 0; i < sizeof(stfl_bytes); i++) {
        if (stfl_bytes[i]) {
            used_stfl_bytes = i + 1;
        }
    }
    initialized = true;
#endif
}

void HELPER(stfl)(CPUS390XState *env)
{
    LowCore *lowcore;

    lowcore = cpu_map_lowcore(env);
    prepare_stfl();
    memcpy(&lowcore->stfl_fac_list, stfl_bytes, sizeof(lowcore->stfl_fac_list));
    cpu_unmap_lowcore(env, lowcore);
}

uint32_t HELPER(stfle)(CPUS390XState *env, uint64_t addr)
{
    const uintptr_t ra = GETPC();
    const int count_bytes = ((env->regs[0] & 0xff) + 1) * 8;
    int max_bytes;
    int i;

    if (addr & 0x7) {
        tcg_s390_program_interrupt(env, PGM_SPECIFICATION, ra);
    }

    prepare_stfl();
    max_bytes = ROUND_UP(used_stfl_bytes, 8);

    /*
     * The PoP says that doublewords beyond the highest-numbered facility
     * bit may or may not be stored.  However, existing hardware appears to
     * not store the words, and existing software depend on that.
     */
    for (i = 0; i < MIN(count_bytes, max_bytes); ++i) {
        cpu_stb_data_ra(env, addr + i, stfl_bytes[i], ra);
    }

    env->regs[0] = deposit64(env->regs[0], 0, 8, (max_bytes / 8) - 1);
    return count_bytes >= max_bytes ? 0 : 3;
}

/*
 * Note: we ignore any return code of the functions called for the pci
 * instructions, as the only time they return !0 is when the stub is
 * called, and in that case we didn't even offer the zpci facility.
 * The only exception is SIC, where program checks need to be handled
 * by the caller.
 */
void HELPER(clp)(CPUS390XState *env, uint32_t r2)
{
#if 0
    S390CPU *cpu = env_archcpu(env);

    qemu_mutex_lock_iothread();
    clp_service_call(cpu, r2, GETPC());
    qemu_mutex_unlock_iothread();
#endif
}

void HELPER(pcilg)(CPUS390XState *env, uint32_t r1, uint32_t r2)
{
#if 0
    S390CPU *cpu = env_archcpu(env);

    qemu_mutex_lock_iothread();
    pcilg_service_call(cpu, r1, r2, GETPC());
    qemu_mutex_unlock_iothread();
#endif
}

void HELPER(pcistg)(CPUS390XState *env, uint32_t r1, uint32_t r2)
{
#if 0
    S390CPU *cpu = env_archcpu(env);

    qemu_mutex_lock_iothread();
    pcistg_service_call(cpu, r1, r2, GETPC());
    qemu_mutex_unlock_iothread();
#endif
}

void HELPER(stpcifc)(CPUS390XState *env, uint32_t r1, uint64_t fiba,
                     uint32_t ar)
{
#if 0
    S390CPU *cpu = env_archcpu(env);

    qemu_mutex_lock_iothread();
    stpcifc_service_call(cpu, r1, fiba, ar, GETPC());
    qemu_mutex_unlock_iothread();
#endif
}

void HELPER(sic)(CPUS390XState *env, uint64_t r1, uint64_t r3)
{
#if 0
    int r;

    qemu_mutex_lock_iothread();
    r = css_do_sic(env, (r3 >> 27) & 0x7, r1 & 0xffff);
    qemu_mutex_unlock_iothread();
    /* css_do_sic() may actually return a PGM_xxx value to inject */
    if (r) {
        tcg_s390_program_interrupt(env, -r, GETPC());
    }
#endif
}

void HELPER(rpcit)(CPUS390XState *env, uint32_t r1, uint32_t r2)
{
#if 0
    S390CPU *cpu = env_archcpu(env);

    qemu_mutex_lock_iothread();
    rpcit_service_call(cpu, r1, r2, GETPC());
    qemu_mutex_unlock_iothread();
#endif
}

void HELPER(pcistb)(CPUS390XState *env, uint32_t r1, uint32_t r3,
                    uint64_t gaddr, uint32_t ar)
{
#if 0
    S390CPU *cpu = env_archcpu(env);

    qemu_mutex_lock_iothread();
    pcistb_service_call(cpu, r1, r3, gaddr, ar, GETPC());
    qemu_mutex_unlock_iothread();
#endif
}

void HELPER(mpcifc)(CPUS390XState *env, uint32_t r1, uint64_t fiba,
                    uint32_t ar)
{
#if 0
    S390CPU *cpu = env_archcpu(env);

    qemu_mutex_lock_iothread();
    mpcifc_service_call(cpu, r1, fiba, ar, GETPC());
    qemu_mutex_unlock_iothread();
#endif
}
