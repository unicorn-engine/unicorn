#ifndef HW_PC_H
#define HW_PC_H

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

typedef struct PCMachineState PCMachineState;
typedef struct PCMachineClass PCMachineClass;

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

#endif
