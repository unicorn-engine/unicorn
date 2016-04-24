#ifndef SYSEMU_H
#define SYSEMU_H
/* Misc. things related to the system emulator.  */

#include "qemu/timer.h"
#include "qapi/error.h"

/* vl.c */

struct uc_struct;

int runstate_is_running(void);
typedef struct vm_change_state_entry VMChangeStateEntry;

#define VMRESET_SILENT   false
#define VMRESET_REPORT   true

int vm_start(struct uc_struct*);

void qemu_system_reset_request(struct uc_struct*);
void qemu_system_shutdown_request(void);
void qemu_system_powerdown_request(void);
void qemu_system_reset(bool report);

extern int smp_cpus;

#endif
