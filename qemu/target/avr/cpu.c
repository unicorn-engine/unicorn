/*
 * QEMU AVR CPU
 *
 * Copyright (c) 2019-2020 Michael Rolnik
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
#include "exec/exec-all.h"
#include "cpu.h"

static void avr_cpu_set_pc(CPUState *cs, vaddr value)
{
    AVRCPU *cpu = AVR_CPU(cs);

    cpu->env.pc_w = value / 2; /* internally PC points to words */
}

static bool avr_cpu_has_work(CPUState *cs)
{
    AVRCPU *cpu = AVR_CPU(cs);
    CPUAVRState *env = &cpu->env;

    return (cs->interrupt_request & (CPU_INTERRUPT_HARD | CPU_INTERRUPT_RESET))
            && cpu_interrupts_enabled(env);
}

static void avr_cpu_synchronize_from_tb(CPUState *cs, TranslationBlock *tb)
{
    AVRCPU *cpu = AVR_CPU(cs);
    CPUAVRState *env = &cpu->env;

    env->pc_w = tb->pc / 2; /* internally PC points to words */
}

static void avr_cpu_reset(CPUState *cs)
{
    AVRCPU *cpu = AVR_CPU(cs);
    AVRCPUClass *mcc = AVR_CPU_GET_CLASS(cpu);
    CPUAVRState *env = &cpu->env;

    mcc->parent_reset(cs);

    env->pc_w = 0;
    env->sregI = 1;
    env->sregC = 0;
    env->sregZ = 0;
    env->sregN = 0;
    env->sregV = 0;
    env->sregS = 0;
    env->sregH = 0;
    env->sregT = 0;

    env->rampD = 0;
    env->rampX = 0;
    env->rampY = 0;
    env->rampZ = 0;
    env->eind = 0;
    env->sp = 0;

    env->skip = 0;

    memset(env->r, 0, sizeof(env->r));
}

static void avr_cpu_realizefn(CPUState *cs)
{
    cpu_exec_realizefn(cs);
    qemu_init_vcpu(cs);
    cpu_reset(cs);
}

static void avr_cpu_initfn(struct uc_struct *uc, CPUState *obj)
{
    AVRCPU *cpu = AVR_CPU(obj);
    CPUAVRState *env = &cpu->env;

    env->uc = uc;
    cpu_set_cpustate_pointers(cpu);
}

static void avr_cpu_class_init(CPUClass *oc)
{
    CPUClass *cc = CPU_CLASS(oc);
    AVRCPUClass *mcc = AVR_CPU_CLASS(oc);

    /* parent class is CPUClass, parent_reset() is cpu_common_reset(). */
    mcc->parent_reset = cc->reset;
    /* overwrite the CPUClass->reset to arch reset: avr_cpu_reset(). */
    cc->reset = avr_cpu_reset;

    cc->has_work = avr_cpu_has_work;
    cc->do_interrupt = avr_cpu_do_interrupt;
    cc->cpu_exec_interrupt = avr_cpu_exec_interrupt;
    cc->set_pc = avr_cpu_set_pc;
    cc->get_phys_page_debug = avr_cpu_get_phys_page_debug;
    cc->tlb_fill = avr_cpu_tlb_fill;
    cc->tcg_initialize = avr_cpu_tcg_init;
    cc->synchronize_from_tb = avr_cpu_synchronize_from_tb;
}

/*
 * Setting features of AVR core type avr5
 * --------------------------------------
 *
 * This type of AVR core is present in the following AVR MCUs:
 *
 * ata5702m322, ata5782, ata5790, ata5790n, ata5791, ata5795, ata5831, ata6613c,
 * ata6614q, ata8210, ata8510, atmega16, atmega16a, atmega161, atmega162,
 * atmega163, atmega164a, atmega164p, atmega164pa, atmega165, atmega165a,
 * atmega165p, atmega165pa, atmega168, atmega168a, atmega168p, atmega168pa,
 * atmega168pb, atmega169, atmega169a, atmega169p, atmega169pa, atmega16hvb,
 * atmega16hvbrevb, atmega16m1, atmega16u4, atmega32a, atmega32, atmega323,
 * atmega324a, atmega324p, atmega324pa, atmega325, atmega325a, atmega325p,
 * atmega325pa, atmega3250, atmega3250a, atmega3250p, atmega3250pa, atmega328,
 * atmega328p, atmega328pb, atmega329, atmega329a, atmega329p, atmega329pa,
 * atmega3290, atmega3290a, atmega3290p, atmega3290pa, atmega32c1, atmega32m1,
 * atmega32u4, atmega32u6, atmega406, atmega64, atmega64a, atmega640, atmega644,
 * atmega644a, atmega644p, atmega644pa, atmega645, atmega645a, atmega645p,
 * atmega6450, atmega6450a, atmega6450p, atmega649, atmega649a, atmega649p,
 * atmega6490, atmega16hva, atmega16hva2, atmega32hvb, atmega6490a, atmega6490p,
 * atmega64c1, atmega64m1, atmega64hve, atmega64hve2, atmega64rfr2,
 * atmega644rfr2, atmega32hvbrevb, at90can32, at90can64, at90pwm161, at90pwm216,
 * at90pwm316, at90scr100, at90usb646, at90usb647, at94k, m3000
 */
static void avr_avr5_initfn(CPUState *obj)
{
    AVRCPU *cpu = AVR_CPU(obj);
    CPUAVRState *env = &cpu->env;

    set_avr_feature(env, AVR_FEATURE_LPM);
    set_avr_feature(env, AVR_FEATURE_IJMP_ICALL);
    set_avr_feature(env, AVR_FEATURE_ADIW_SBIW);
    set_avr_feature(env, AVR_FEATURE_SRAM);
    set_avr_feature(env, AVR_FEATURE_BREAK);

    set_avr_feature(env, AVR_FEATURE_2_BYTE_PC);
    set_avr_feature(env, AVR_FEATURE_2_BYTE_SP);
    set_avr_feature(env, AVR_FEATURE_JMP_CALL);
    set_avr_feature(env, AVR_FEATURE_LPMX);
    set_avr_feature(env, AVR_FEATURE_MOVW);
    set_avr_feature(env, AVR_FEATURE_MUL);
}

/*
 * Setting features of AVR core type avr51
 * --------------------------------------
 *
 * This type of AVR core is present in the following AVR MCUs:
 *
 * atmega128, atmega128a, atmega1280, atmega1281, atmega1284, atmega1284p,
 * atmega128rfa1, atmega128rfr2, atmega1284rfr2, at90can128, at90usb1286,
 * at90usb1287
 */
static void avr_avr51_initfn(CPUState *obj)
{
    AVRCPU *cpu = AVR_CPU(obj);
    CPUAVRState *env = &cpu->env;

    set_avr_feature(env, AVR_FEATURE_LPM);
    set_avr_feature(env, AVR_FEATURE_IJMP_ICALL);
    set_avr_feature(env, AVR_FEATURE_ADIW_SBIW);
    set_avr_feature(env, AVR_FEATURE_SRAM);
    set_avr_feature(env, AVR_FEATURE_BREAK);

    set_avr_feature(env, AVR_FEATURE_2_BYTE_PC);
    set_avr_feature(env, AVR_FEATURE_2_BYTE_SP);
    set_avr_feature(env, AVR_FEATURE_RAMPZ);
    set_avr_feature(env, AVR_FEATURE_ELPMX);
    set_avr_feature(env, AVR_FEATURE_ELPM);
    set_avr_feature(env, AVR_FEATURE_JMP_CALL);
    set_avr_feature(env, AVR_FEATURE_LPMX);
    set_avr_feature(env, AVR_FEATURE_MOVW);
    set_avr_feature(env, AVR_FEATURE_MUL);
}

/*
 * Setting features of AVR core type avr6
 * --------------------------------------
 *
 * This type of AVR core is present in the following AVR MCUs:
 *
 * atmega2560, atmega2561, atmega256rfr2, atmega2564rfr2
 */
static void avr_avr6_initfn(CPUState *obj)
{
    AVRCPU *cpu = AVR_CPU(obj);
    CPUAVRState *env = &cpu->env;

    set_avr_feature(env, AVR_FEATURE_LPM);
    set_avr_feature(env, AVR_FEATURE_IJMP_ICALL);
    set_avr_feature(env, AVR_FEATURE_ADIW_SBIW);
    set_avr_feature(env, AVR_FEATURE_SRAM);
    set_avr_feature(env, AVR_FEATURE_BREAK);

    set_avr_feature(env, AVR_FEATURE_3_BYTE_PC);
    set_avr_feature(env, AVR_FEATURE_2_BYTE_SP);
    set_avr_feature(env, AVR_FEATURE_RAMPZ);
    set_avr_feature(env, AVR_FEATURE_EIJMP_EICALL);
    set_avr_feature(env, AVR_FEATURE_ELPMX);
    set_avr_feature(env, AVR_FEATURE_ELPM);
    set_avr_feature(env, AVR_FEATURE_JMP_CALL);
    set_avr_feature(env, AVR_FEATURE_LPMX);
    set_avr_feature(env, AVR_FEATURE_MOVW);
    set_avr_feature(env, AVR_FEATURE_MUL);
}

static const AVRCPUInfo avr_cpu_info[] = {
    {"avr5", avr_avr5_initfn},
    {"avr51", avr_avr51_initfn},
    {"avr6", avr_avr6_initfn},
};

AVRCPU *cpu_avr_init(struct uc_struct *uc)
{
    AVRCPU *cpu;
    CPUState *cs;
    CPUClass *cc;

    cpu = qemu_memalign(8, sizeof(*cpu));
    if (cpu == NULL) {
        return NULL;
    }
    memset((void *)cpu, 0, sizeof(*cpu));

    if (uc->cpu_model == INT_MAX) {
        uc->cpu_model = UC_CPU_AVR_6;
    }

    cs = (CPUState *)cpu;
    cc = (CPUClass *)&cpu->cc;
    cs->cc = cc;
    cs->uc = uc;
    uc->cpu = cs;

    /* init CPUClass */
    cpu_class_init(uc, cc);

    /* init AVRCPUClass */
    avr_cpu_class_init(cc);

    /* init CPUState */
    cpu_common_initfn(uc, cs);

    /* init AVRCPU */
    avr_cpu_initfn(uc, cs);

    /* init AVR types */
    avr_cpu_info[uc->cpu_model].initfn(cs);

    /* realize AVRCPU */
    avr_cpu_realizefn(cs);

    // init address space
    cpu_address_space_init(cs, 0, cs->memory);

    return cpu;
}
