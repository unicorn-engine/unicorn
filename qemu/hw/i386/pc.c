/*
 * QEMU PC System Emulator
 *
 * Copyright (c) 2003-2004 Fabrice Bellard
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
 * THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */
/* Modified for Unicorn Engine by Nguyen Anh Quynh, 2015 */

#include "hw/hw.h"
#include "hw/i386/pc.h"
#include "sysemu/sysemu.h"
#include "qapi-visit.h"


/* XXX: add IGNNE support */
void cpu_set_ferr(CPUX86State *s)
{
//    qemu_irq_raise(ferr_irq);
}

/* TSC handling */
uint64_t cpu_get_tsc(CPUX86State *env)
{
    return cpu_get_ticks();
}

/* SMM support */

static cpu_set_smm_t smm_set;
static void *smm_arg;

void cpu_smm_register(cpu_set_smm_t callback, void *arg)
{
    assert(smm_set == NULL);
    assert(smm_arg == NULL);
    smm_set = callback;
    smm_arg = arg;
}

void cpu_smm_update(CPUX86State *env)
{
    struct uc_struct *uc = x86_env_get_cpu(env)->parent_obj.uc;

    if (smm_set && smm_arg && CPU(x86_env_get_cpu(env)) == uc->cpu) {
        smm_set(!!(env->hflags & HF_SMM_MASK), smm_arg);
    }
}

/* IRQ handling */
int cpu_get_pic_interrupt(CPUX86State *env)
{
    X86CPU *cpu = x86_env_get_cpu(env);
    int intno;

    intno = apic_get_interrupt(cpu->apic_state);
    if (intno >= 0) {
        return intno;
    }
    /* read the irq from the PIC */
    if (!apic_accept_pic_intr(cpu->apic_state)) {
        return -1;
    }

    return 0;
}

DeviceState *cpu_get_current_apic(struct uc_struct *uc)
{
    if (uc->current_cpu) {
        X86CPU *cpu = X86_CPU(uc, uc->current_cpu);
        return cpu->apic_state;
    } else {
        return NULL;
    }
}

static X86CPU *pc_new_cpu(struct uc_struct *uc, const char *cpu_model, int64_t apic_id,
                          Error **errp)
{
    X86CPU *cpu;
    Error *local_err = NULL;

    cpu = cpu_x86_create(uc, cpu_model, &local_err);
    if (local_err != NULL) {
        error_propagate(errp, local_err);
        return NULL;
    }

    object_property_set_int(uc, OBJECT(cpu), apic_id, "apic-id", &local_err);
    object_property_set_bool(uc, OBJECT(cpu), true, "realized", &local_err);

    if (local_err) {
        error_propagate(errp, local_err);
        object_unref(uc, OBJECT(cpu));
        cpu = NULL;
    }
    return cpu;
}

int pc_cpus_init(struct uc_struct *uc, const char *cpu_model)
{
    int i;
    Error *error = NULL;

    /* init CPUs */
    if (cpu_model == NULL) {
#ifdef TARGET_X86_64
        cpu_model = "qemu64";
#else
        cpu_model = "qemu32";
#endif
    }

    for (i = 0; i < smp_cpus; i++) {
        uc->cpu = (CPUState *)pc_new_cpu(uc, cpu_model, x86_cpu_apic_id_from_index(i), &error);
        if (error) {
            //error_report("%s", error_get_pretty(error));
            error_free(error);
            return -1;
        }
    }

    return 0;
}

static void pc_machine_initfn(struct uc_struct *uc, Object *obj, void *opaque)
{
}

static void pc_machine_class_init(struct uc_struct *uc, ObjectClass *oc, void *data)
{
}

static const TypeInfo pc_machine_info = {
    TYPE_PC_MACHINE,
    TYPE_MACHINE,

    sizeof(PCMachineClass),
    sizeof(PCMachineState),
    NULL,

    pc_machine_initfn,
    NULL,
    NULL,

    NULL,

    pc_machine_class_init,
    NULL,
    NULL,

    true,

    NULL,
    NULL,

    // should this be added somehow?
    //.interfaces = (InterfaceInfo[]) { { } },
};

void pc_machine_register_types(struct uc_struct *uc)
{
    type_register_static(uc, &pc_machine_info);
}
