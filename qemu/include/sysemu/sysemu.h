#ifndef SYSEMU_H
#define SYSEMU_H
/* Misc. things related to the system emulator.  */
/* Modified for Unicorn Engine by Chen Huitao<chenhuitao@hfmrit.com>, 2020 */

#include "qemu/timer.h"

/* vl.c */

struct uc_struct;

int vm_start(struct uc_struct*);

void qemu_system_reset_request(struct uc_struct*);
void qemu_system_shutdown_request(void);
void qemu_system_powerdown_request(void);
void qemu_system_reset(bool report);

extern int smp_cpus;

#endif
