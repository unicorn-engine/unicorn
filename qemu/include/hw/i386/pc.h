/* Modified for Unicorn Engine by Chen Huitao<chenhuitao@hfmrit.com>, 2020 */
#ifndef HW_PC_H
#define HW_PC_H

#include "qemu/typedefs.h"
#include "uc_priv.h"

typedef void (*cpu_set_smm_t)(int smm, void *arg);
void cpu_smm_register(cpu_set_smm_t callback, void *arg);

#endif
