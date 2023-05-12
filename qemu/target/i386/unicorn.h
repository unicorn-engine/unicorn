/* Unicorn Emulator Engine */
/* By Nguyen Anh Quynh <aquynh@gmail.com>, 2015 */
/* Modified for Unicorn Engine by Chen Huitao<chenhuitao@hfmrit.com>, 2020 */

#ifndef UC_QEMU_TARGET_I386_H
#define UC_QEMU_TARGET_I386_H

// functions to read & write registers
uc_err reg_read_x86_64(void *env, int mode, unsigned int regid, void *value,
                       size_t *size);
uc_err reg_write_x86_64(void *env, int mode, unsigned int regid,
                        const void *value, size_t *size, int *setpc);

void uc_init_x86_64(struct uc_struct *uc);
#endif
