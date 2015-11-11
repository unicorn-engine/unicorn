/* Declarations for use by board files for creating devices.  */

#ifndef HW_BOARDS_H
#define HW_BOARDS_H

#include "qemu/typedefs.h"
#include "sysemu/accel.h"
#include "hw/qdev.h"
#include "qom/object.h"
#include "uc_priv.h"

typedef int QEMUMachineInitFunc(struct uc_struct *uc, MachineState *ms);

typedef void QEMUMachineResetFunc(void);

struct QEMUMachine {
    const char *family; /* NULL iff @name identifies a standalone machtype */
    const char *name;
    QEMUMachineInitFunc *init;
    QEMUMachineResetFunc *reset;
    int max_cpus;
    int is_default;
    int arch;
};

void memory_region_allocate_system_memory(MemoryRegion *mr, Object *owner,
                                          const char *name,
                                          uint64_t ram_size);

void qemu_register_machine(struct uc_struct *uc, QEMUMachine *m, const char *type_machine,
        void (*init)(struct uc_struct *uc, ObjectClass *oc, void *data));

#define TYPE_MACHINE_SUFFIX "-machine"
#define TYPE_MACHINE "machine"
#undef MACHINE  /* BSD defines it and QEMU does not use it */
#define MACHINE(uc, obj) \
    OBJECT_CHECK(uc, MachineState, (obj), TYPE_MACHINE)
#define MACHINE_GET_CLASS(uc, obj) \
    OBJECT_GET_CLASS(uc, MachineClass, (obj), TYPE_MACHINE)
#define MACHINE_CLASS(uc, klass) \
    OBJECT_CLASS_CHECK(uc, MachineClass, (klass), TYPE_MACHINE)

MachineClass *find_default_machine(struct uc_struct *uc, int arch);

/**
 * MachineClass:
 * @qemu_machine: #QEMUMachine
 */
struct MachineClass {
    /*< private >*/
    ObjectClass parent_class;
    /*< public >*/

    const char *family; /* NULL iff @name identifies a standalone machtype */
    const char *name;

    int (*init)(struct uc_struct *uc, MachineState *state);
    void (*reset)(void);

    int max_cpus;
    int is_default;
    int arch;
};

/**
 * MachineState:
 */
struct MachineState {
    /*< private >*/
    Object parent_obj;

    /*< public >*/
    ram_addr_t ram_size;
    ram_addr_t maxram_size;
    const char *cpu_model;
    struct uc_struct *uc;
    AccelState *accelerator;
};

void machine_register_types(struct uc_struct *uc);

#endif
