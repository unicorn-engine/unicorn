#ifndef HW_PC_H
#define HW_PC_H

#include "qemu/typedefs.h"
#include "hw/boards.h"

/**
 * PCMachineState:
 */
struct PCMachineState {
    /*< private >*/
    MachineState parent_obj;

    uint64_t max_ram_below_4g;
};

#define PC_MACHINE_MAX_RAM_BELOW_4G "max-ram-below-4g"

/**
 * PCMachineClass:
 */
struct PCMachineClass {
    /*< private >*/
    MachineClass parent_class;
};

#define TYPE_PC_MACHINE "generic-pc-machine"
#define PC_MACHINE(uc, obj) \
    OBJECT_CHECK(uc, PCMachineState, (obj), TYPE_PC_MACHINE)
#define PC_MACHINE_GET_CLASS(obj) \
    OBJECT_GET_CLASS(PCMachineClass, (obj), TYPE_PC_MACHINE)
#define PC_MACHINE_CLASS(klass) \
    OBJECT_CLASS_CHECK(PCMachineClass, (klass), TYPE_PC_MACHINE)

int pc_cpus_init(struct uc_struct *uc, const char *cpu_model);

FWCfgState *pc_memory_init(MachineState *machine,
                           MemoryRegion *system_memory,
                           ram_addr_t begin,
                           MemoryRegion **ram_memory);
typedef void (*cpu_set_smm_t)(int smm, void *arg);
void cpu_smm_register(cpu_set_smm_t callback, void *arg);

void pc_machine_register_types(struct uc_struct *uc);
void x86_cpu_register_types(struct uc_struct *uc);

#define PC_DEFAULT_MACHINE_OPTIONS \
    .max_cpus = 255

// Unicorn: Modified to work with Unicorn.
#define DEFINE_PC_MACHINE(suffix, namestr, initfn) \
    static void pc_machine_##suffix##_class_init(struct uc_struct *uc, ObjectClass *oc, void *data) \
    { \
        MachineClass *mc = MACHINE_CLASS(uc, oc); \
        mc->max_cpus = 255; \
        mc->is_default = 1; \
        mc->init = initfn; \
        mc->arch = UC_ARCH_X86; \
    } \
    static const TypeInfo pc_machine_type_##suffix = { \
        namestr TYPE_MACHINE_SUFFIX, \
        TYPE_PC_MACHINE, \
        0, \
        0, \
        NULL, \
        NULL, \
        NULL, \
        NULL, \
        NULL, \
        pc_machine_##suffix##_class_init, \
    }; \
    void pc_machine_init_##suffix(struct uc_struct *uc); \
    void pc_machine_init_##suffix(struct uc_struct *uc) \
    { \
        type_register(uc, &pc_machine_type_##suffix); \
    }

#endif
