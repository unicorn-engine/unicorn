/*
 * QEMU CPU model
 *
 * Copyright (c) 2012-2014 SUSE LINUX Products GmbH
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, see
 * <http://www.gnu.org/licenses/gpl-2.0.html>
 */

#include "qemu/osdep.h"
#include "qapi/error.h"
#include "qemu-common.h"
#include "hw/boards.h"
#include "qemu/log.h"
#include "uc_priv.h"

CPUState *cpu_by_arch_id(struct uc_struct *uc, int64_t id)
{
    CPUState *cpu = uc->cpu;
    CPUClass *cc = CPU_GET_CLASS(uc, cpu);

    if (cc->get_arch_id(cpu) == id) {
        return cpu;
    }
    return NULL;
}

bool cpu_exists(struct uc_struct *uc, int64_t id)
{
    return !!cpu_by_arch_id(uc, id);
}

CPUState *cpu_generic_init(struct uc_struct *uc, const char *typename, const char *cpu_model)
{
    CPUState *cpu = NULL;
    ObjectClass *oc;
    CPUClass *cc;
    Error *err = NULL;
    gchar **model_pieces;

    model_pieces = g_strsplit(cpu_model, ",", 2);

    oc = cpu_class_by_name(uc, typename, model_pieces[0]);
    if (oc == NULL) {
        g_strfreev(model_pieces);
        return NULL;
    }

    cc = CPU_CLASS(uc, oc);
    /* TODO: all callers of cpu_generic_init() need to be converted to
     * call parse_features() only once, before calling cpu_generic_init().
     */
    cc->parse_features(uc, object_class_get_name(oc), model_pieces[1], &err);
    g_strfreev(model_pieces);
    if (err != NULL) {
        goto out;
    }

    cpu = CPU(object_new(uc, object_class_get_name(oc)));
    object_property_set_bool(uc, OBJECT(cpu), true, "realized", &err);

out:
    if (err != NULL) {
        error_free(err);
        object_unref(uc, OBJECT(cpu));
        return NULL;
    }

    return cpu;
}

bool cpu_paging_enabled(const CPUState *cpu)
{
    CPUClass *cc = CPU_GET_CLASS(cpu->uc, cpu);

    return cc->get_paging_enabled(cpu);
}

static bool cpu_common_get_paging_enabled(const CPUState *cpu)
{
    return false;
}

void cpu_get_memory_mapping(CPUState *cpu, MemoryMappingList *list,
                            Error **errp)
{
    CPUClass *cc = CPU_GET_CLASS(cpu->uc, cpu);

    cc->get_memory_mapping(cpu, list, errp);
}

static void cpu_common_get_memory_mapping(CPUState *cpu,
                                          MemoryMappingList *list,
                                          Error **errp)
{
    error_setg(errp, "Obtaining memory mappings is unsupported on this CPU.");
}

void cpu_reset_interrupt(CPUState *cpu, int mask)
{
    cpu->interrupt_request &= ~mask;
}

void cpu_exit(CPUState *cpu)
{
    atomic_set(&cpu->exit_request, 1);
    /* Ensure cpu_exec will see the exit request after TCG has exited.  */
    smp_wmb();
    atomic_set(&cpu->tcg_exit_req, 1);
}

static void cpu_common_noop(CPUState *cpu)
{
}

static bool cpu_common_exec_interrupt(CPUState *cpu, int int_req)
{
    return false;
}

void cpu_dump_state(CPUState *cpu, FILE *f, fprintf_function cpu_fprintf,
                    int flags)
{
    CPUClass *cc = CPU_GET_CLASS(cpu->uc, cpu);

    if (cc->dump_state) {
        cc->dump_state(cpu, f, cpu_fprintf, flags);
    }
}

void cpu_dump_statistics(CPUState *cpu, FILE *f, fprintf_function cpu_fprintf,
                         int flags)
{
    CPUClass *cc = CPU_GET_CLASS(cpu->uc, cpu);

    if (cc->dump_statistics) {
        cc->dump_statistics(cpu, f, cpu_fprintf, flags);
    }
}

void cpu_reset(CPUState *cpu)
{
    CPUClass *klass = CPU_GET_CLASS(cpu->uc, cpu);

    if (klass->reset != NULL) {
        (*klass->reset)(cpu);
    }
}

static void cpu_common_reset(CPUState *cpu)
{
    CPUClass *cc = CPU_GET_CLASS(cpu->uc, cpu);

    if (qemu_loglevel_mask(CPU_LOG_RESET)) {
        qemu_log("CPU Reset (CPU %d)\n", cpu->cpu_index);
        log_cpu_state(cpu, cc->reset_dump_flags);
    }

    cpu->interrupt_request = 0;
    cpu->halted = 0;
    cpu->mem_io_pc = 0;
    cpu->mem_io_vaddr = 0;
    cpu->icount_extra = 0;
    cpu->icount_decr.u32 = 0;
    cpu->can_do_io = 0;
    cpu->exception_index = -1;
    cpu->crash_occurred = false;

    // TODO: Should be uncommented, but good 'ol
    //       unicorn's crappy symbol deduplication
    //       makes it impossible right now
    //if (tcg_enabled(cpu->uc)) {
        cpu_tb_jmp_cache_clear(cpu);

        // Ditto: should also be uncommented
        //tcg_flush_softmmu_tlb(cpu);
    //}
}

static bool cpu_common_has_work(CPUState *cs)
{
    return false;
}

static bool cpu_common_debug_check_watchpoint(CPUState *cpu, CPUWatchpoint *wp)
{
    /* If no extra check is required, QEMU watchpoint match can be considered
     * as an architectural match.
     */
    return true;
}

ObjectClass *cpu_class_by_name(struct uc_struct *uc, const char *typename, const char *cpu_model)
{
    CPUClass *cc;

    if (!cpu_model) {
        return NULL;
    }
    cc = CPU_CLASS(uc, object_class_by_name(uc, typename));

    return cc->class_by_name(uc, cpu_model);
}

static ObjectClass *cpu_common_class_by_name(struct uc_struct *uc, const char *cpu_model)
{
    return NULL;
}

static void cpu_common_parse_features(struct uc_struct *uc, const char *typename, char *features,
                                      Error **errp)
{
    char *featurestr; /* Single "key=value" string being parsed */
    char *val;

    /* TODO: all callers of ->parse_features() need to be changed to
     * call it only once, so we can remove this check (or change it
     * to assert(!cpu_globals_initialized).
     * Current callers of ->parse_features() are:
     * - cpu_generic_init()
     */
    if (uc->cpu_globals_initialized) {
        return;
    }
    uc->cpu_globals_initialized = true;

    featurestr = features ? strtok(features, ",") : NULL;

    while (featurestr) {
        val = strchr(featurestr, '=');
        if (val) {
            // Unicorn: if'd out
#if 0
            GlobalProperty *prop = g_new0(GlobalProperty, 1);
#endif
            *val = 0;
            val++;

            // Unicorn: If'd out
#if 0
            prop->driver = typename;
            prop->property = g_strdup(featurestr);
            prop->value = g_strdup(val);
            prop->errp = &error_fatal;
            qdev_prop_register_global(prop);
#endif
        } else {
            error_setg(errp, "Expected key=value format, found %s.",
                       featurestr);
            return;
        }
        featurestr = strtok(NULL, ",");
    }
}

static int cpu_common_realizefn(struct uc_struct *uc, DeviceState *dev, Error **errp)
{
    CPUState *cpu = CPU(dev);
    Object *machine = qdev_get_machine(uc);

    /* qdev_get_machine() can return something that's not TYPE_MACHINE
     * if this is one of the user-only emulators; in that case there's
     * no need to check the ignore_memory_transaction_failures board flag.
     */
    if (object_dynamic_cast(uc, machine, TYPE_MACHINE)) {
        ObjectClass *oc = object_get_class(machine);
        MachineClass *mc = MACHINE_CLASS(uc, oc);

        if (mc) {
            cpu->ignore_memory_transaction_failures =
                mc->ignore_memory_transaction_failures;
        }
    }

    if (dev->hotplugged) {
        cpu_resume(cpu);
    }

    return 0;
}

static void cpu_common_initfn(struct uc_struct *uc, Object *obj, void *opaque)
{
    CPUState *cpu = CPU(obj);

    QTAILQ_INIT(&cpu->breakpoints);
    QTAILQ_INIT(&cpu->watchpoints);
}

static int64_t cpu_common_get_arch_id(CPUState *cpu)
{
    return cpu->cpu_index;
}

static vaddr cpu_adjust_watchpoint_address(CPUState *cpu, vaddr addr, int len)
{
    return addr;
}

static void cpu_class_init(struct uc_struct *uc, ObjectClass *klass, void *data)
{
    DeviceClass *dc = DEVICE_CLASS(uc, klass);
    CPUClass *k = CPU_CLASS(uc, klass);

    k->class_by_name = cpu_common_class_by_name;
    k->parse_features = cpu_common_parse_features;
    k->reset = cpu_common_reset;
    k->get_arch_id = cpu_common_get_arch_id;
    k->has_work = cpu_common_has_work;
    k->get_paging_enabled = cpu_common_get_paging_enabled;
    k->get_memory_mapping = cpu_common_get_memory_mapping;
    k->debug_excp_handler = cpu_common_noop;
    k->debug_check_watchpoint = cpu_common_debug_check_watchpoint;
    k->cpu_exec_enter = cpu_common_noop;
    k->cpu_exec_exit = cpu_common_noop;
    k->cpu_exec_interrupt = cpu_common_exec_interrupt;
    k->adjust_watchpoint_address = cpu_adjust_watchpoint_address;
    dc->realize = cpu_common_realizefn;
    /*
     * Reason: CPUs still need special care by board code: wiring up
     * IRQs, adding reset handlers, halting non-first CPUs, ...
     */
    dc->cannot_instantiate_with_device_add_yet = true;
}

static const TypeInfo cpu_type_info = {
    TYPE_CPU,
    TYPE_DEVICE,

    sizeof(CPUClass),
    sizeof(CPUState),
    NULL,

    cpu_common_initfn,
    NULL,
    NULL,

    NULL,

    cpu_class_init,
    NULL,
    NULL,

    true,
};

void cpu_register_types(struct uc_struct *uc)
{
    type_register_static(uc, &cpu_type_info);
}
