/* Declarations for use by board files for creating devices.  */

#ifndef HW_BOARDS_H
#define HW_BOARDS_H

#include "qemu/typedefs.h"
#include "sysemu/accel.h"
#include "hw/qdev.h"
#include "qom/object.h"
#include "qom/cpu.h"
#include "uc_priv.h"

typedef int QEMUMachineInitFunc(struct uc_struct *uc, MachineState *ms);

typedef void QEMUMachineResetFunc(void);

struct QEMUMachine {
    const char *name;
    QEMUMachineInitFunc *init;
    int max_cpus;
    int is_default;
    int arch;
    int minimum_page_bits;
};

/**
 * memory_region_allocate_system_memory - Allocate a board's main memory
 * @mr: the #MemoryRegion to be initialized
 * @owner: the object that tracks the region's reference count
 * @name: name of the memory region
 * @ram_size: size of the region in bytes
 *
 * This function allocates the main memory for a board model, and
 * initializes @mr appropriately. It also arranges for the memory
 * to be migrated (by calling vmstate_register_ram_global()).
 *
 * Memory allocated via this function will be backed with the memory
 * backend the user provided using "-mem-path" or "-numa node,memdev=..."
 * if appropriate; this is typically used to cause host huge pages to be
 * used. This function should therefore be called by a board exactly once,
 * for the primary or largest RAM area it implements.
 *
 * For boards where the major RAM is split into two parts in the memory
 * map, you can deal with this by calling memory_region_allocate_system_memory()
 * once to get a MemoryRegion with enough RAM for both parts, and then
 * creating alias MemoryRegions via memory_region_init_alias() which
 * alias into different parts of the RAM MemoryRegion and can be mapped
 * into the memory map in the appropriate places.
 *
 * Smaller pieces of memory (display RAM, static RAMs, etc) don't need
 * to be backed via the -mem-path memory backend and can simply
 * be created via memory_region_init_ram().
 */
void memory_region_allocate_system_memory(MemoryRegion *mr, Object *owner,
                                          const char *name,
                                          uint64_t ram_size);

void qemu_register_machine(struct uc_struct *uc, QEMUMachine *m, const char *type_machine,
        void (*init)(struct uc_struct *uc, ObjectClass *oc, void *data));

#define TYPE_MACHINE_SUFFIX "-machine"

/* Machine class name that needs to be used for class-name-based machine
 * type lookup to work.
 */
#define MACHINE_TYPE_NAME(machinename) (machinename TYPE_MACHINE_SUFFIX)

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
 * @minimum_page_bits:
 *    If non-zero, the board promises never to create a CPU with a page size
 *    smaller than this, so QEMU can use a more efficient larger page
 *    size than the target architecture's minimum. (Attempting to create
 *    such a CPU will fail.) Note that changing this is a migration
 *    compatibility break for the machine.
 * @ignore_memory_transaction_failures:
 *    If this is flag is true then the CPU will ignore memory transaction
 *    failures which should cause the CPU to take an exception due to an
 *    access to an unassigned physical address; the transaction will instead
 *    return zero (for a read) or be ignored (for a write). This should be
 *    set only by legacy board models which rely on the old RAZ/WI behaviour
 *    for handling devices that QEMU does not yet model. New board models
 *    should instead use "unimplemented-device" for all memory ranges where
 *    the guest will attempt to probe for a device that QEMU doesn't
 *    implement and a stub device is required.
 */
struct MachineClass {
    /*< private >*/
    ObjectClass parent_class;
    /*< public >*/

    const char *name;

    int (*init)(struct uc_struct *uc, MachineState *state);
    void (*reset)(void);

    int max_cpus;
    int is_default;
    int arch;
    int minimum_page_bits;
    bool has_hotpluggable_cpus;
    bool ignore_memory_transaction_failures;
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

#define DEFINE_MACHINE(namestr, machine_initfn) \
    static void machine_initfn##_class_init(struct uc_struct *uc, ObjectClass *oc, void *data) \
    { \
        MachineClass *mc = MACHINE_CLASS(uc, oc); \
        machine_initfn(mc); \
    } \
    static const TypeInfo machine_initfn##_typeinfo = { \
        MACHINE_TYPE_NAME(namestr), \
        TYPE_MACHINE, \
        0, \
        0, \
        NULL, \
        NULL, \
        NULL, \
        NULL, \
        NULL, \
        machine_initfn##_class_init, \
    }; \
    void machine_initfn##_register_types(struct uc_struct *uc) \
    { \
        type_register_static(uc, &machine_initfn##_typeinfo); \
    }

void machine_register_types(struct uc_struct *uc);

#endif
