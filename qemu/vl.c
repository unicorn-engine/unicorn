/*
 * QEMU System Emulator
 *
 * Copyright (c) 2003-2008 Fabrice Bellard
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

/* Unicorn Emulator Engine */
/* By Nguyen Anh Quynh, 2015 */

#include "hw/boards.h"  // MachineClass
#include "sysemu/sysemu.h"
#include "sysemu/cpus.h"
#include "vl.h"
#include "uc_priv.h"

#define DEFAULT_RAM_SIZE 128

int smp_cpus = 1;
int smp_cores = 1;
int smp_threads = 1;

// cpus.c
void cpu_resume(CPUState *cpu)
{
    cpu->stop = false;
    cpu->stopped = false;
}

void cpu_stop_current(struct uc_struct *uc)
{
    if (uc->current_cpu) {
        uc->current_cpu->stop = false;
        uc->current_cpu->stopped = true;
        cpu_exit(uc->current_cpu);
    }
}


/***********************************************************/
/* machine registration */

MachineClass *find_default_machine(struct uc_struct *uc, int arch)
{
    GSList *el, *machines = object_class_get_list(uc, TYPE_MACHINE, false);
    MachineClass *mc = NULL;

    for (el = machines; el; el = el->next) {
        MachineClass *temp = el->data;

        if ((temp->is_default) && (temp->arch == arch)) {
            mc = temp;
            break;
        }
    }

    g_slist_free(machines);
    return mc;
}

DEFAULT_VISIBILITY
int machine_initialize(struct uc_struct *uc)
{
    MachineClass *machine_class;
    MachineState *current_machine;

    module_call_init(uc, MODULE_INIT_QOM);
    register_types_object(uc);
    machine_register_types(uc);
    container_register_types(uc);
    cpu_register_types(uc);
    qdev_register_types(uc);

    // Initialize arch specific.
    uc->init_arch(uc);

    module_call_init(uc, MODULE_INIT_MACHINE);
    // this will auto initialize all register objects above.
    machine_class = find_default_machine(uc, uc->arch);
    if (machine_class == NULL) {
        //fprintf(stderr, "No machine specified, and there is no default.\n"
        //        "Use -machine help to list supported machines!\n");
        return -2;
    }

    current_machine = MACHINE(uc, object_new(uc, object_class_get_name(
                    OBJECT_CLASS(machine_class))));
    uc->machine_state = current_machine;
    current_machine->uc = uc;
    uc->cpu_exec_init_all(uc);

    machine_class->max_cpus = 1;
    configure_accelerator(current_machine);

    current_machine->cpu_model = NULL;

    return machine_class->init(uc, current_machine);
}

void qemu_system_reset_request(struct uc_struct* uc)
{
    cpu_stop_current(uc);
}

void qemu_system_shutdown_request(void)
{
    //shutdown_requested = 1;
}

static void machine_class_init(struct uc_struct *uc, ObjectClass *oc, void *data)
{
    MachineClass *mc = MACHINE_CLASS(uc, oc);
    QEMUMachine *qm = data;

    mc->family = qm->family;
    mc->name = qm->name;
    mc->init = qm->init;
    mc->reset = qm->reset;
    mc->max_cpus = qm->max_cpus;
    mc->is_default = qm->is_default;
    mc->arch = qm->arch;
}

void qemu_register_machine(struct uc_struct *uc, QEMUMachine *m, const char *type_machine,
        void (*init)(struct uc_struct *uc, ObjectClass *oc, void *data))
{
    char *name = g_strconcat(m->name, TYPE_MACHINE_SUFFIX, NULL);
    TypeInfo ti = {0};
    ti.name       = name;
    ti.parent     = type_machine;
    ti.class_init = init;
    ti.class_data = (void *)m;

    if (init == NULL)
        ti.class_init = machine_class_init;

    type_register(uc, &ti);
    g_free(name);
}
