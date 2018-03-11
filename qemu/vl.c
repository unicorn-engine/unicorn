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

#include "qemu/osdep.h"
#include "qapi/error.h"
#include "qemu/cutils.h"
#include "hw/boards.h"  // MachineClass
#include "sysemu/sysemu.h"
#include "sysemu/cpus.h"
#include "qemu/log.h"
#include "vl.h"
#include "uc_priv.h"
#include "exec/semihost.h"

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
/* Semihosting */

bool semihosting_enabled(void)
{
    // UNICORN: Always return false
    return false;
}

SemihostingTarget semihosting_get_target(void)
{
    return SEMIHOSTING_TARGET_AUTO;
}

const char *semihosting_get_arg(int i)
{
    return NULL;
}

int semihosting_get_argc(void)
{
    return 0;
}

const char *semihosting_get_cmdline(void)
{
    return NULL;
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

    // Initialize cache information
    init_cache_info(uc);

    // Initialize arch specific.
    uc->init_arch(uc);

    module_call_init(uc, MODULE_INIT_MACHINE);
    // this will auto initialize all register objects above.
    machine_class = find_default_machine(uc, uc->arch);
    if (machine_class == NULL) {
        // error_report("No machine specified, and there is no default");
        // error_printf("Use -machine help to list supported machines\n");
        return -2;
    }

    current_machine = MACHINE(uc, object_new(uc, object_class_get_name(
                    OBJECT_CLASS(machine_class))));
    uc->machine_state = current_machine;
    current_machine->uc = uc;

    // Unicorn: FIXME: ditto with regards to below
    //qemu_tcg_configure(uc);

    // Unicorn: FIXME: this should be uncommented
    //          However due to the "stellar" way unicorn
    //          handles multiple targets (e.g. the YOLO
    //          Python script named header_gen.py), this
    //          results in a compilation error.
    //if (machine_class->minimum_page_bits) {
    //    if (!set_preferred_target_page_bits(uc, machine_class->minimum_page_bits)) {
    //        /* This would be a board error: specifying a minimum smaller than
    //         * a target's compile-time fixed setting.
    //         */
    //        g_assert_not_reached();
    //    }
    //}
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
