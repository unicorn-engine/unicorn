/*
 * QEMU S/390 CPU
 *
 * Copyright (c) 2009 Ulrich Hecht
 * Copyright (c) 2011 Alexander Graf
 * Copyright (c) 2012 SUSE LINUX Products GmbH
 * Copyright (c) 2012 IBM Corp.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, see <http://www.gnu.org/licenses/>.
 */

#include "qemu/osdep.h"
#include "cpu.h"
#include "internal.h"
#include "qemu/timer.h"
#include "sysemu/sysemu.h"
#include "sysemu/tcg.h"
#include "fpu/softfloat-helpers.h"
#include "exec/exec-all.h"

#define CR0_RESET       0xE0UL
#define CR14_RESET      0xC2000000UL;

static void s390_cpu_set_pc(CPUState *cs, vaddr value)
{
    S390CPU *cpu = S390_CPU(cs);

    cpu->env.psw.addr = value;
}

static bool s390_cpu_has_work(CPUState *cs)
{
    S390CPU *cpu = S390_CPU(cs);

#if 0
    /* STOPPED cpus can never wake up */
    if (s390_cpu_get_state(cpu) != S390_CPU_STATE_LOAD &&
        s390_cpu_get_state(cpu) != S390_CPU_STATE_OPERATING) {
        return false;
    }
#endif

    if (!(cs->interrupt_request & CPU_INTERRUPT_HARD)) {
        return false;
    }

    return s390_cpu_has_int(cpu);
}

/* S390CPUClass::reset() */
static void s390_cpu_reset(CPUState *dev, cpu_reset_type type)
{
    CPUState *s = CPU(dev);
    S390CPU *cpu = S390_CPU(s);
    S390CPUClass *scc = S390_CPU_GET_CLASS(cpu);
    CPUS390XState *env = &cpu->env;

    scc->parent_reset(dev);
    cpu->env.sigp_order = 0;
    s390_cpu_set_state(S390_CPU_STATE_STOPPED, cpu);

    switch (type) {
    case S390_CPU_RESET_CLEAR:
        memset(env, 0, offsetof(CPUS390XState, start_initial_reset_fields));
        /* fall through */
    case S390_CPU_RESET_INITIAL:
        /* initial reset does not clear everything! */
        memset(&env->start_initial_reset_fields, 0,
               offsetof(CPUS390XState, start_normal_reset_fields) -
               offsetof(CPUS390XState, start_initial_reset_fields));

        /* architectured initial value for Breaking-Event-Address register */
        env->gbea = 1;

        /* architectured initial values for CR 0 and 14 */
        env->cregs[0] = CR0_RESET;
        env->cregs[14] = CR14_RESET;

        /* tininess for underflow is detected before rounding */
        set_float_detect_tininess(float_tininess_before_rounding,
                                  &env->fpu_status);
       /* fall through */
    case S390_CPU_RESET_NORMAL:
        env->psw.mask &= ~PSW_MASK_RI;
        memset(&env->start_normal_reset_fields, 0,
               offsetof(CPUS390XState, end_reset_fields) -
               offsetof(CPUS390XState, start_normal_reset_fields));

        env->pfault_token = -1UL;
        env->bpbc = false;
        break;
    default:
        g_assert_not_reached();
    }
}

static void s390_cpu_realizefn(struct uc_struct *uc, CPUState *dev)
{
    CPUState *cs = CPU(dev);
    S390CPU *cpu = S390_CPU(dev);

    /* the model has to be realized before qemu_init_vcpu() due to kvm */
    // s390_realize_cpu_model(cs);

    /* sync cs->cpu_index and env->core_id. The latter is needed for TCG. */
    cs->cpu_index = cpu->env.core_id;

    cpu_exec_realizefn(cs);

    qemu_init_vcpu(cs);

    cpu_reset(cs);
}

static void s390_cpu_initfn(struct uc_struct *uc, CPUState *obj)
{
    CPUState *cs = CPU(obj);
    S390CPU *cpu = S390_CPU(obj);

    cpu_set_cpustate_pointers(cpu);
    cs->halted = 1;
    cs->exception_index = EXCP_HLT;
    // s390_cpu_model_register_props(obj);
    // cpu->env.tod_timer =
    //     timer_new_ns(QEMU_CLOCK_VIRTUAL, s390x_tod_timer, cpu);
    // cpu->env.cpu_timer =
    //     timer_new_ns(QEMU_CLOCK_VIRTUAL, s390x_cpu_timer, cpu);
    s390_cpu_set_state(S390_CPU_STATE_STOPPED, cpu);

    cpu->env.uc = uc;
}

static unsigned s390_count_running_cpus(void)
{
    return 1;
}

unsigned int s390_cpu_halt(S390CPU *cpu)
{
    CPUState *cs = CPU(cpu);

    if (!cs->halted) {
        cs->halted = 1;
        cs->exception_index = EXCP_HLT;
    }

    return s390_count_running_cpus();
}

void s390_cpu_unhalt(S390CPU *cpu)
{
    CPUState *cs = CPU(cpu);

    if (cs->halted) {
        cs->halted = 0;
        cs->exception_index = -1;
    }
}

unsigned int s390_cpu_set_state(uint8_t cpu_state, S390CPU *cpu)
 {
    switch (cpu_state) {
    case S390_CPU_STATE_STOPPED:
    case S390_CPU_STATE_CHECK_STOP:
        /* halt the cpu for common infrastructure */
        s390_cpu_halt(cpu);
        break;
    case S390_CPU_STATE_OPERATING:
    case S390_CPU_STATE_LOAD:
        /*
         * Starting a CPU with a PSW WAIT bit set:
         * KVM: handles this internally and triggers another WAIT exit.
         * TCG: will actually try to continue to run. Don't unhalt, will
         *      be done when the CPU actually has work (an interrupt).
         */
        if (!(cpu->env.psw.mask & PSW_MASK_WAIT)) {
            s390_cpu_unhalt(cpu);
        }
        break;
    default:
        //error_report("Requested CPU state is not a valid S390 CPU state: %u",
        //             cpu_state);
        exit(1);
    }
    cpu->env.cpu_state = cpu_state;

    return s390_count_running_cpus();
}

int s390_set_memory_limit(uint64_t new_limit, uint64_t *hw_limit)
{
    return 0;
}

void s390_set_max_pagesize(uint64_t pagesize)
{
}

void s390_cmma_reset(void)
{
}

void s390_crypto_reset(void)
{
}

void s390_enable_css_support(S390CPU *cpu)
{
}

static void s390_cpu_class_init(struct uc_struct *uc, CPUClass *oc)
{
    S390CPUClass *scc = S390_CPU_CLASS(oc);
    CPUClass *cc = CPU_CLASS(scc);

    scc->reset = s390_cpu_reset;
    cc->has_work = s390_cpu_has_work;
    // cc->do_interrupt = s390_cpu_do_interrupt;
    cc->set_pc = s390_cpu_set_pc;
    cc->get_phys_page_debug = s390_cpu_get_phys_page_debug;
    cc->cpu_exec_interrupt = s390_cpu_exec_interrupt;
    cc->debug_excp_handler = s390x_cpu_debug_excp_handler;
    cc->do_unaligned_access = s390x_cpu_do_unaligned_access;
    cc->tcg_initialize = s390x_translate_init;
    cc->tlb_fill_cpu = s390_cpu_tlb_fill;

    // s390_cpu_model_class_register_props(oc);
}

S390CPU *cpu_s390_init(struct uc_struct *uc, const char *cpu_model)
{
    S390CPU *cpu;
    CPUState *cs;
    CPUClass *cc;
    // int i;

    cpu = calloc(1, sizeof(*cpu));
    if (cpu == NULL) {
        return NULL;
    }

    if (uc->cpu_model == INT_MAX) {
        uc->cpu_model = UC_CPU_S390X_QEMU; // qemu-s390x-cpu
    } else if (uc->cpu_model > UC_CPU_S390X_MAX) {
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

    /* init CPUClass */
    s390_cpu_class_init(uc, cc);

    // init skeys
    s390_skeys_init(uc);

    // init s390 models
    s390_init_cpu_model(uc, uc->cpu_model);

    /* init CPUState */
    cpu_common_initfn(uc, cs);

    /* init CPU */
    s390_cpu_initfn(uc, cs);

    /* realize CPU */
    s390_cpu_realizefn(uc, cs);

    // init addresss space
    cpu_address_space_init(cs, 0, cs->memory);

    //qemu_init_vcpu(cs);

    return cpu;
}
