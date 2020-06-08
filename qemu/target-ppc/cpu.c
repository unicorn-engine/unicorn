#include "translate.h"
#include "cpu.h"
#include "hw/ppc/ppc.h"
#include "family.h"

#if defined(TARGET_PPC)
#include "mach/mpc8572e.h"
#include "mach/cpu_405.h"
#include "mach/cpu_401.h"
#include "mach/cpu_604.h"
#endif

#if defined(TARGET_PPC64)
#include "mach/cpu_970.h"
#endif

static void ppc_cpu_initfn(struct uc_struct* uc ,Object *obj,void* opaque)
{
    CPUState *cs = CPU(obj);
    PowerPCCPU *cpu = POWERPC_CPU(uc,obj);
    PowerPCCPUClass *pcc = POWERPC_CPU_GET_CLASS(uc,cpu);
    CPUPPCState *env = &cpu->env;

    cs->env_ptr = env;
    cpu_exec_init(env,opaque);
    cpu->cpu_dt_id = cs->cpu_index;

    env->msr_mask = pcc->msr_mask;
    env->mmu_model = pcc->mmu_model;
    env->excp_model = pcc->excp_model;
    env->bus_model = pcc->bus_model;
    env->insns_flags = pcc->insns_flags;
    env->insns_flags2 = pcc->insns_flags2;
    env->flags = pcc->flags;
    // env->bfd_mach = pcc->bfd_mach;
    env->check_pow = pcc->check_pow;

#if defined(TARGET_PPC64)
    if (pcc->sps) {
        env->sps = *pcc->sps;
    } else if (env->mmu_model & POWERPC_MMU_64) {
        /* Use default sets of page sizes */
        static const struct ppc_segment_page_sizes defsps = {
            .sps = {
                { .page_shift = 12, /* 4K */
                  .slb_enc = 0,
                  .enc = { { .page_shift = 12, .pte_enc = 0 } }
                },
                { .page_shift = 24, /* 16M */
                  .slb_enc = 0x100,
                  .enc = { { .page_shift = 24, .pte_enc = 0 } }
                },
            },
        };
        env->sps = defsps;
    }
#endif /* defined(TARGET_PPC64) */
    cpu_reset(cs);

    if (tcg_enabled(uc)) {
        ppc_translate_init(uc);
    }
}

static ObjectClass *ppc_cpu_class_by_name(struct uc_struct* uc,const char *cpu_model)
{
    ObjectClass *oc;
    char *typename;

    if (!cpu_model) {
        return NULL;
    }

    typename = g_strdup_printf("%s-" TYPE_POWERPC_CPU, cpu_model);
    oc = object_class_by_name(uc, typename);
    g_free(typename);
    if (!oc || !object_class_dynamic_cast(uc, oc, TYPE_POWERPC_CPU) ||
        object_class_is_abstract(oc)) {
        return NULL;
    }
    return oc;
}

void ppc_cpu_set_pc(CPUState *cs, vaddr value)
{
    CPUPPCState *env = cs->env_ptr;
    PowerPCCPU *cpu = POWERPC_CPU(env->uc,cs);

    cpu->env.nip = value;
}


static void ppc_cpu_exec_enter(CPUState *cs)
{
    CPUPPCState *env = cs->env_ptr;
    //PowerPCCPU *cpu = POWERPC_CPU(env->uc,cs);

    env->reserve_addr = -1;
}

static bool ppc_cpu_has_work(CPUState *cs)
{   
    CPUPPCState *env = cs->env_ptr;
    return ((env->msr >> MSR_EE)   & 1) && (cs->interrupt_request & CPU_INTERRUPT_HARD);
}


static void create_ppc_opcodes(PowerPCCPU *cpu, Error **errp)
{
    CPUPPCState *env = &cpu->env;
    PowerPCCPUClass *pcc = POWERPC_CPU_GET_CLASS(env->uc,cpu);
    opcode_t *opc;

    fill_new_table(env->opcodes, PPC_CPU_OPCODES_LEN);
    for (opc = opcodes; opc < &opcodes[ARRAY_SIZE(opcodes)]; opc++) {
        if (((opc->handler.type & pcc->insns_flags) != 0) ||
            ((opc->handler.type2 & pcc->insns_flags2) != 0)) {
            if (register_insn(env->opcodes, opc) < 0) {
                fprintf(stderr,"ERROR initializing PowerPC instruction "
                           "0x%02x 0x%02x 0x%02x", opc->opc1, opc->opc2,
                           opc->opc3);
                /*error_setg(errp, "ERROR initializing PowerPC instruction "
                           "0x%02x 0x%02x 0x%02x", opc->opc1, opc->opc2,
                           opc->opc3);*/
                return;
            }
        }
    }
    fix_opcode_tables(env->opcodes);
    fflush(stdout);
    fflush(stderr);
}

static void init_ppc_proc(PowerPCCPU *cpu)
{
    CPUPPCState *env = &cpu->env;
    PowerPCCPUClass *pcc = POWERPC_CPU_GET_CLASS(env->uc,cpu);

#if !defined(CONFIG_USER_ONLY)
    int i;

    // env->irq_inputs = NULL;
    /* Set all exception vectors to an invalid address */
    for (i = 0; i < POWERPC_EXCP_NB; i++)
        env->excp_vectors[i] = (target_ulong)(-1ULL);
    env->ivor_mask = 0x00000000;
    env->ivpr_mask = 0x00000000;
    /* Default MMU definitions */
    env->nb_BATs = 0;
    env->nb_tlb = 0;
    env->nb_ways = 0;
    env->tlb_type = TLB_NONE;

#endif
    /* Register SPR common to all PowerPC implementations */

    gen_spr_generic(env);

    /* PowerPC implementation specific initialisations (SPRs, timers, ...) */
    (*pcc->init_proc)(env);

    /* MSR bits & flags consistency checks */
    if (env->msr_mask & (1 << 25)) {
        switch (env->flags & (POWERPC_FLAG_SPE | POWERPC_FLAG_VRE)) {
        case POWERPC_FLAG_SPE:
        case POWERPC_FLAG_VRE:
            break;
        default:
            fprintf(stderr, "PowerPC MSR definition inconsistency\n"
                    "Should define POWERPC_FLAG_SPE or POWERPC_FLAG_VRE\n");
            exit(1);
        }
    } else if (env->flags & (POWERPC_FLAG_SPE | POWERPC_FLAG_VRE)) {
        fprintf(stderr, "PowerPC MSR definition inconsistency\n"
                "Should not define POWERPC_FLAG_SPE nor POWERPC_FLAG_VRE\n");
        exit(1);
    }
    if (env->msr_mask & (1 << 17)) {
        switch (env->flags & (POWERPC_FLAG_TGPR | POWERPC_FLAG_CE)) {
        case POWERPC_FLAG_TGPR:
        case POWERPC_FLAG_CE:
            break;
        default:
            fprintf(stderr, "PowerPC MSR definition inconsistency\n"
                    "Should define POWERPC_FLAG_TGPR or POWERPC_FLAG_CE\n");
            exit(1);
        }
    } else if (env->flags & (POWERPC_FLAG_TGPR | POWERPC_FLAG_CE)) {
        fprintf(stderr, "PowerPC MSR definition inconsistency\n"
                "Should not define POWERPC_FLAG_TGPR nor POWERPC_FLAG_CE\n");
        exit(1);
    }
    if (env->msr_mask & (1 << 10)) {
        switch (env->flags & (POWERPC_FLAG_SE | POWERPC_FLAG_DWE |
                              POWERPC_FLAG_UBLE)) {
        case POWERPC_FLAG_SE:
        case POWERPC_FLAG_DWE:
        case POWERPC_FLAG_UBLE:
            break;
        default:
            fprintf(stderr, "PowerPC MSR definition inconsistency\n"
                    "Should define POWERPC_FLAG_SE or POWERPC_FLAG_DWE or "
                    "POWERPC_FLAG_UBLE\n");
            exit(1);
        }
    } else if (env->flags & (POWERPC_FLAG_SE | POWERPC_FLAG_DWE |
                             POWERPC_FLAG_UBLE)) {
        fprintf(stderr, "PowerPC MSR definition inconsistency\n"
                "Should not define POWERPC_FLAG_SE nor POWERPC_FLAG_DWE nor "
                "POWERPC_FLAG_UBLE\n");
            exit(1);
    }
    if (env->msr_mask & (1 << 9)) {
        switch (env->flags & (POWERPC_FLAG_BE | POWERPC_FLAG_DE)) {
        case POWERPC_FLAG_BE:
        case POWERPC_FLAG_DE:
            break;
        default:
            fprintf(stderr, "PowerPC MSR definition inconsistency\n"
                    "Should define POWERPC_FLAG_BE or POWERPC_FLAG_DE\n");
            exit(1);
        }
    } else if (env->flags & (POWERPC_FLAG_BE | POWERPC_FLAG_DE)) {
        fprintf(stderr, "PowerPC MSR definition inconsistency\n"
                "Should not define POWERPC_FLAG_BE nor POWERPC_FLAG_DE\n");
        exit(1);
    }
    if (env->msr_mask & (1 << 2)) {
        switch (env->flags & (POWERPC_FLAG_PX | POWERPC_FLAG_PMM)) {
        case POWERPC_FLAG_PX:
        case POWERPC_FLAG_PMM:
            break;
        default:
            fprintf(stderr, "PowerPC MSR definition inconsistency\n"
                    "Should define POWERPC_FLAG_PX or POWERPC_FLAG_PMM\n");
            exit(1);
        }
    } else if (env->flags & (POWERPC_FLAG_PX | POWERPC_FLAG_PMM)) {
        fprintf(stderr, "PowerPC MSR definition inconsistency\n"
                "Should not define POWERPC_FLAG_PX nor POWERPC_FLAG_PMM\n");
        exit(1);
    }
    if ((env->flags & (POWERPC_FLAG_RTC_CLK | POWERPC_FLAG_BUS_CLK)) == 0) {
        fprintf(stderr, "PowerPC flags inconsistency\n"
                "Should define the time-base and decrementer clock source\n");
        exit(1);
    }
    /* Allocate TLBs buffer when needed */
#if !defined(CONFIG_USER_ONLY)
    if (env->nb_tlb != 0) {
        int nb_tlb = env->nb_tlb;
        if (env->id_tlbs != 0)
            nb_tlb *= 2;
        switch (env->tlb_type) {
        case TLB_6XX:
            env->tlb.tlb6 = g_malloc0(nb_tlb * sizeof(ppc6xx_tlb_t));
            break;
        case TLB_EMB:
            env->tlb.tlbe = g_malloc0(nb_tlb * sizeof(ppcemb_tlb_t));
            break;
        case TLB_MAS:
            env->tlb.tlbm = g_malloc0(nb_tlb * sizeof(ppcmas_tlb_t));
            break;
        }
        
        /* Pre-compute some useful values */
        env->tlb_per_way = env->nb_tlb / env->nb_ways;
        mmubooke_create_initial_mapping(env);
    }
    /*if (env->irq_inputs == NULL) {
        fprintf(stderr, "WARNING: no internal IRQ controller registered.\n"
                " Attempt QEMU to crash very soon !\n");
    }*/
#endif
    if (env->check_pow == NULL) {
        fprintf(stderr, "WARNING: no power management check handler "
                "registered.\n"
                " Attempt QEMU to crash very soon !\n");
    }
}

static int ppc_cpu_realizefn(struct uc_struct *uc,DeviceState *dev, Error **errp)
{
    CPUState *cs = CPU(dev);
    PowerPCCPU *cpu = POWERPC_CPU(uc,dev);
    PowerPCCPUClass *pcc = POWERPC_CPU_GET_CLASS(uc,cpu);
    Error *local_err = NULL;
#if !defined(CONFIG_USER_ONLY)
    int max_smt = 1;
#endif

#if !defined(CONFIG_USER_ONLY)
    if (smp_threads > max_smt) {
        error_setg(errp, "Cannot support more than %d threads on PPC with %s",
                   max_smt, "TCG");
        return 1;
    }
    /*
    if (!is_power_of_2(smp_threads)) {
        error_setg(errp, "Cannot support %d threads on PPC with %s, "
                   "threads count must be a power of 2.",
                   smp_threads, "TCG");
        return;
    }
    */

    cpu->cpu_dt_id = (cs->cpu_index / smp_threads) * max_smt
        + (cs->cpu_index % smp_threads);
#endif

    if (tcg_enabled(uc)) {
        /*
        if (ppc_fixup_cpu(cpu) != 0) {
            error_setg(errp, "Unable to emulate selected CPU with TCG");
            return;
        }
        */
    }

    create_ppc_opcodes(cpu, &local_err);
    if (local_err != NULL) {
        error_propagate(errp, local_err);
        return 1;
    }
    init_ppc_proc(cpu);

    qemu_init_vcpu(cs);

    pcc->parent_realize(uc,dev, errp);
    return 0;
}

/* Opcode types */
enum {
    PPC_DIRECT   = 0, /* Opcode routine        */
    PPC_INDIRECT = 1, /* Indirect opcode table */
};

static opc_handler_t invalid_handler = {
    .inval1  = 0xFFFFFFFF,
    .inval2  = 0xFFFFFFFF,
    .type    = PPC_NONE,
    .type2   = PPC_NONE,
    .handler = gen_invalid,
};

static void ppc_cpu_unrealizefn(struct uc_struct* uc,DeviceState *dev, Error **errp)
{
    PowerPCCPU *cpu = POWERPC_CPU(uc,dev);
    CPUPPCState *env = &cpu->env;
    opc_handler_t **table;
    int i, j;

    for (i = 0; i < PPC_CPU_OPCODES_LEN; i++) {
        if (env->opcodes[i] == &invalid_handler) {
            continue;
        }
        if (is_indirect_opcode(env->opcodes[i])) {
            table = ind_table(env->opcodes[i]);
            for (j = 0; j < PPC_CPU_INDIRECT_OPCODES_LEN; j++) {
                if (table[j] != &invalid_handler &&
                        is_indirect_opcode(table[j])) {
                    g_free((opc_handler_t *)((uintptr_t)table[j] &
                        ~PPC_INDIRECT));
                }
            }
            g_free((opc_handler_t *)((uintptr_t)env->opcodes[i] &
                ~PPC_INDIRECT));
        }
    }
}

static void ppc_cpu_class_init(struct uc_struct* uc,ObjectClass* oc, void *data)
{
    PowerPCCPUClass *pcc = POWERPC_CPU_CLASS(uc,oc);
    CPUClass *cc = CPU_CLASS(uc,oc);
    DeviceClass *dc = DEVICE_CLASS(uc,oc);

    pcc->parent_realize = dc->realize;
    //pcc->pvr_match = ppc_pvr_match_default;
    //pcc->interrupts_big_endian = ppc_cpu_interrupts_big_endian_always;
    dc->realize = ppc_cpu_realizefn;
    dc->unrealize = ppc_cpu_unrealizefn;

    pcc->parent_reset = cc->reset;
    cc->reset = ppc_cpu_reset;

    cc->class_by_name = ppc_cpu_class_by_name;

    cc->has_work = ppc_cpu_has_work;
    cc->do_interrupt = ppc_cpu_do_interrupt;
    cc->cpu_exec_interrupt = ppc_cpu_exec_interrupt;
    //cc->dump_state = ppc_cpu_dump_state;
    //cc->dump_statistics = ppc_cpu_dump_statistics;
    cc->set_pc = ppc_cpu_set_pc;
    //cc->gdb_read_register = ppc_cpu_gdb_read_register;
    //cc->gdb_write_register = ppc_cpu_gdb_write_register;
#ifdef CONFIG_USER_ONLY
    cc->handle_mmu_fault = ppc_cpu_handle_mmu_fault;
#else
    //cc->get_phys_page_debug = ppc_cpu_get_phys_page_debug;
    //cc->vmsd = &vmstate_ppc_cpu;
#if defined(TARGET_PPC64)
    //cc->write_elf64_note = ppc64_cpu_write_elf64_note;
    //cc->write_elf64_qemunote = ppc64_cpu_write_elf64_qemunote;
#endif
#endif
    cc->cpu_exec_enter = ppc_cpu_exec_enter;

    //cc->gdb_num_core_regs = 71;

#ifdef USE_APPLE_GDB
    //cc->gdb_read_register = ppc_cpu_gdb_read_register_apple;
    //cc->gdb_write_register = ppc_cpu_gdb_write_register_apple;
    //cc->gdb_num_core_regs = 71 + 32;
#endif

#if defined(TARGET_PPC64)
    //cc->gdb_core_xml_file = "power64-core.xml";
#else
    //cc->gdb_core_xml_file = "power-core.xml";
#endif
#ifndef CONFIG_USER_ONLY
    //cc->virtio_is_big_endian = ppc_cpu_is_big_endian;
#endif

    dc->fw_name = "PowerPC,UNKNOWN";
}

/*
 * Define abstract type PowerPCCPU and its different implementations
 */
void ppc_cpu_register_types(struct uc_struct* uc)
{
    const TypeInfo ppc_cpu_type_info = {
        TYPE_POWERPC_CPU,
        TYPE_CPU,
        sizeof(PowerPCCPUClass),
        sizeof(PowerPCCPU),
        uc,
        ppc_cpu_initfn,
        NULL,
        NULL,
        NULL,
        ppc_cpu_class_init,
        NULL,
        NULL,
        true
    };

#if !defined(TARGET_PPC64)
    ppc_e500v2_cpu_family_register_types(uc);
    ppc_mpc8572e_register_types(uc);

    ppc_405_cpu_family_register_types(uc);
    ppc_405_cpu_register_types(uc);
    
    ppc_401_cpu_family_register_types(uc);
    ppc_401_cpu_register_types(uc);

    ppc_604_cpu_family_register_types(uc);
    ppc_604_cpu_register_types(uc);
#else
    ppc64_970_cpu_family_register_types(uc);
    ppc64_970_cpu_register_types(uc);
#endif
    
    type_register_static(uc,&ppc_cpu_type_info);
}

//type_init(ppc_cpu_register_types)

/*
 *  PowerPC MMU stub handling for user mode emulation
 *
 *  Copyright (c) 2003-2007 Jocelyn Mayer
 *  Copyright (c) 2013 David Gibson, IBM Corporation.
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, see <http://www.gnu.org/licenses/>.
 */


#if defined(CONFIG_USER_ONLY)

int ppc_cpu_handle_mmu_fault(CPUState *cs, vaddr address, int rw,
                             int mmu_idx)
{    
    CPUPPCState *env = cs->env_ptr;
    PowerPCCPU *cpu = POWERPC_CPU(env->uc,cs);
    int exception, error_code;

    if (rw == 2) {
        exception = POWERPC_EXCP_ISI;
        error_code = 0x40000000;
    } else {
        exception = POWERPC_EXCP_DSI;
        error_code = 0x40000000;
        if (rw) {
            error_code |= 0x02000000;
        }
        env->spr[SPR_DAR] = address;
        env->spr[SPR_DSISR] = error_code;
    }
    cs->exception_index = exception;
    env->error_code = error_code;

    return 1;
}
#endif