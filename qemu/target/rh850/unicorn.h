/* Unicorn Emulator Engine */
/* By Damien Cauquil <dcauquil@quarkslab.com>, 2023 */

#ifndef UC_QEMU_TARGET_RH850_H
#define UC_QEMU_TARGET_RH850_H

// functions to read & write registers
uc_err reg_read_rh850(void *_env, int mode, unsigned int regid, void *value,
                      size_t *size);
uc_err reg_write_rh850(void *_env, int mode, unsigned int regid,
                       const void *value, size_t *size, int *setpc);

void reg_reset_rh850(struct uc_struct *uc);

void uc_init_rh850(struct uc_struct *uc);
#endif
