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
#include "disas/dis-asm.h"
#include "unicorn_helper.h"

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

static void avr_cpu_reset(DeviceState *ds)
{
    CPUState *cs = CPU(ds);
    AVRCPU *cpu = AVR_CPU(cs);
    AVRCPUClass *mcc = AVR_CPU_GET_CLASS(cpu);
    CPUAVRState *env = &cpu->env;

    if (mcc->parent_reset)
        mcc->parent_reset(ds);

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

#if 0
static void avr_cpu_disas_set_info(CPUState *cpu, disassemble_info *info)
{
    info->mach = bfd_arch_avr;
    info->print_insn = avr_print_insn;
}
#endif

static void avr_cpu_realizefn(DeviceState *dev)
{
    CPUState *cs = CPU(dev);
    AVRCPUClass *mcc = AVR_CPU_GET_CLASS(dev);

    cpu_exec_realizefn(cs);
    qemu_init_vcpu(cs);
    cpu_reset(cs);

    if (mcc->parent_realize)
        mcc->parent_realize(dev);
}

#if 0
static void avr_cpu_set_int(void *opaque, int irq, int level)
{
    AVRCPU *cpu = opaque;
    CPUAVRState *env = &cpu->env;
    CPUState *cs = CPU(cpu);
    uint64_t mask = (1ull << irq);

    if (level) {
        env->intsrc |= mask;
        cpu_interrupt(cs, CPU_INTERRUPT_HARD);
    } else {
        env->intsrc &= ~mask;
        if (env->intsrc == 0) {
            cpu_reset_interrupt(cs, CPU_INTERRUPT_HARD);
        }
    }
}
#endif

static void avr_cpu_initfn(Object *obj, struct uc_struct *uc)
{
    AVRCPU *cpu = AVR_CPU(obj);
    CPUAVRState *const env = &cpu->env;

    env->uc = uc;
    cpu_set_cpustate_pointers(cpu);

#if 0
    /* Set the number of interrupts supported by the CPU. */
    qdev_init_gpio_in(DEVICE(cpu), avr_cpu_set_int,
                      sizeof(cpu->env.intsrc) * 8);
#endif
}

#if 0
static ObjectClass *avr_cpu_class_by_name(const char *cpu_model)
{
    ObjectClass *oc;

    oc = object_class_by_name(cpu_model);
    if (object_class_dynamic_cast(oc, TYPE_AVR_CPU) == NULL ||
        object_class_is_abstract(oc)) {
        oc = NULL;
    }
    return oc;
}
#endif

#if 0
static void avr_cpu_dump_state(CPUState *cs, FILE *f, int flags)
{
    AVRCPU *cpu = AVR_CPU(cs);
    CPUAVRState *env = &cpu->env;
    int i;

    qemu_fprintf(f, "\n");
    qemu_fprintf(f, "PC:    %06x\n", env->pc_w * 2); /* PC points to words */
    qemu_fprintf(f, "SP:      %04x\n", env->sp);
    qemu_fprintf(f, "rampD:     %02x\n", env->rampD >> 16);
    qemu_fprintf(f, "rampX:     %02x\n", env->rampX >> 16);
    qemu_fprintf(f, "rampY:     %02x\n", env->rampY >> 16);
    qemu_fprintf(f, "rampZ:     %02x\n", env->rampZ >> 16);
    qemu_fprintf(f, "EIND:      %02x\n", env->eind >> 16);
    qemu_fprintf(f, "X:       %02x%02x\n", env->r[27], env->r[26]);
    qemu_fprintf(f, "Y:       %02x%02x\n", env->r[29], env->r[28]);
    qemu_fprintf(f, "Z:       %02x%02x\n", env->r[31], env->r[30]);
    qemu_fprintf(f, "SREG:    [ %c %c %c %c %c %c %c %c ]\n",
                 env->sregI ? 'I' : '-',
                 env->sregT ? 'T' : '-',
                 env->sregH ? 'H' : '-',
                 env->sregS ? 'S' : '-',
                 env->sregV ? 'V' : '-',
                 env->sregN ? '-' : 'N', /* Zf has negative logic */
                 env->sregZ ? 'Z' : '-',
                 env->sregC ? 'I' : '-');
    qemu_fprintf(f, "SKIP:    %02x\n", env->skip);

    qemu_fprintf(f, "\n");
    for (i = 0; i < ARRAY_SIZE(env->r); i++) {
        qemu_fprintf(f, "R[%02d]:  %02x   ", i, env->r[i]);

        if ((i % 8) == 7) {
            qemu_fprintf(f, "\n");
        }
    }
    qemu_fprintf(f, "\n");
}
#endif

static void avr_cpu_class_init(ObjectClass *oc, void *data)
{
    CPUClass *cc = CPU_CLASS(oc);
    AVRCPUClass *mcc = AVR_CPU_CLASS(oc);

    mcc->parent_realize = NULL;
    mcc->parent_reset = NULL;

#if 0
    cc->class_by_name = avr_cpu_class_by_name;
#endif

    cc->reset = avr_cpu_reset;
    cc->has_work = avr_cpu_has_work;
    cc->do_interrupt = avr_cpu_do_interrupt;
    cc->cpu_exec_interrupt = avr_cpu_exec_interrupt;
#if 0
    cc->dump_state = avr_cpu_dump_state;
#endif
    cc->set_pc = avr_cpu_set_pc;
#if 0
    cc->memory_rw_debug = avr_cpu_memory_rw_debug;
#endif
    cc->get_phys_page_debug = avr_cpu_get_phys_page_debug;
    cc->tlb_fill = avr_cpu_tlb_fill;
#if 0
    cc->vmsd = &vms_avr_cpu;
    cc->disas_set_info = avr_cpu_disas_set_info;
#endif
    cc->tcg_initialize = avr_cpu_tcg_init;
    cc->synchronize_from_tb = avr_cpu_synchronize_from_tb;
#if 0
    cc->gdb_read_register = avr_cpu_gdb_read_register;
    cc->gdb_write_register = avr_cpu_gdb_write_register;
    cc->gdb_num_core_regs = 35;
    cc->gdb_core_xml_file = "avr-cpu.xml";
#endif
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
static void avr_avr5_initfn(Object *obj)
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
static void avr_avr51_initfn(Object *obj)
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
static void avr_avr6_initfn(Object *obj)
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

typedef struct AVRCPUInfo {
    int model;
    const char *name;
    void (*initfn)(Object *obj);
} AVRCPUInfo;

static const AVRCPUInfo avr_cpu_info[] ={
    {UC_CPU_AVR_ATMEGA16, "arch:avr5", avr_avr5_initfn},
    {UC_CPU_AVR_ATMEGA16, "atmega16", avr_avr5_initfn},
    {UC_CPU_AVR_ATMEGA32, "atmega32", avr_avr5_initfn},
    {UC_CPU_AVR_ATMEGA64, "atmega64", avr_avr5_initfn},

    {UC_CPU_AVR_ATMEGA128, "arch:avr51", avr_avr51_initfn},
    {UC_CPU_AVR_ATMEGA128, "atmega128", avr_avr51_initfn},
    {UC_CPU_AVR_ATMEGA128RFR2, "atmega128rfr2", avr_avr51_initfn},
    {UC_CPU_AVR_ATMEGA1280, "atmega1280", avr_avr51_initfn},

    {UC_CPU_AVR_ATMEGA256, "arch:avr6", avr_avr6_initfn},
    {UC_CPU_AVR_ATMEGA256RFR2, "atmega256rfr2", avr_avr6_initfn},
    {UC_CPU_AVR_ATMEGA2560, "atmega2560", avr_avr6_initfn},
};

static const AVRCPUInfo *avr_cpu_info_get(int cpu_model)
{
    for (int i = 0; i < ARRAY_SIZE(avr_cpu_info); i++) {
        const AVRCPUInfo *const cip = &avr_cpu_info[i];
        if (cpu_model == cip->model)
            return cip;
    }
    return NULL;
}

#if 0
static void avr_cpu_list_entry(gpointer data, gpointer user_data)
{
    const char *typename = object_class_get_name(OBJECT_CLASS(data));

    qemu_printf("%s\n", typename);
}

void avr_cpu_list(void)
{
    GSList *list;
    list = object_class_get_list_sorted(TYPE_AVR_CPU, false);
    g_slist_foreach(list, avr_cpu_list_entry, NULL);
    g_slist_free(list);
}

#define DEFINE_AVR_CPU_TYPE(model, initfn) \
    { \
        .parent = TYPE_AVR_CPU, \
        .instance_init = initfn, \
        .name = AVR_CPU_TYPE_NAME(model), \
    }

static const TypeInfo avr_cpu_type_info[] = {
    {
        .name = TYPE_AVR_CPU,
        .parent = TYPE_CPU,
        .instance_size = sizeof(AVRCPU),
        .instance_init = avr_cpu_initfn,
        .class_size = sizeof(AVRCPUClass),
        .class_init = avr_cpu_class_init,
        .abstract = true,
    },
    DEFINE_AVR_CPU_TYPE("avr5", avr_avr5_initfn),
    DEFINE_AVR_CPU_TYPE("avr51", avr_avr51_initfn),
    DEFINE_AVR_CPU_TYPE("avr6", avr_avr6_initfn),
};

DEFINE_TYPES(avr_cpu_type_info)
#endif

AVRCPU *cpu_avr_init(struct uc_struct *uc)
{
    AVRCPU *cpu;
    CPUState *cs;
    CPUClass *cc;
    ObjectClass *oc;

    cpu = calloc(1, sizeof(*cpu));
    if (cpu == NULL) {
        return NULL;
    }

    if (uc->cpu_model == INT_MAX)
        uc->cpu_model = UC_CPU_AVR_ATMEGA128;
    const AVRCPUInfo *const cip = avr_cpu_info_get(uc->cpu_model);
    if (!cip) {
        free(cpu);
        return NULL;
    }

    cs = &cpu->parent_obj;
    cc = &AVR_CPU_GET_CLASS(cpu)->parent_class;
    oc = (ObjectClass *)cc;
    cs->cc = cc;
    cs->uc = uc;
    uc->cpu = cs;

    cpu_class_init(uc, cc);
    avr_cpu_class_init(oc, NULL);

    cpu_common_initfn(uc, cs);
    avr_cpu_initfn(cs, uc);
    cip->initfn(cs);

    avr_cpu_realizefn(cs);

    // init address space
    cpu_address_space_init(cs, 0, cs->memory);

    qemu_init_vcpu(cs);

    return cpu;
}
