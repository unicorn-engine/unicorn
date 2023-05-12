/* Unicorn Emulator Engine */
/* By Nguyen Anh Quynh <aquynh@gmail.com>, 2015 */

/*
   Modified for Unicorn Engine by Eric Poole <eric.poole@aptiv.com>, 2022
   Copyright 2022 Aptiv
*/

#ifndef UC_QEMU_TARGET_TRICORE_H
#define UC_QEMU_TARGET_TRICORE_H

// functions to read & write registers
uc_err reg_read_tricore(void *env, int mode, unsigned int regid, void *value,
                        size_t *size);
uc_err reg_write_tricore(void *env, int mode, unsigned int regid,
                         const void *value, size_t *size, int *setpc);

void uc_init_tricore(struct uc_struct *uc);
#endif
