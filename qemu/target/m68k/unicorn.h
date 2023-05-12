/* Unicorn Emulator Engine */
/* By Nguyen Anh Quynh <aquynh@gmail.com>, 2015 */

#ifndef UC_QEMU_TARGET_M68K_H
#define UC_QEMU_TARGET_M68K_H

// functions to read & write registers
uc_err reg_read_m68k(void *env, int mode, unsigned int regid, void *value,
                     size_t *size);
uc_err reg_write_m68k(void *env, int mode, unsigned int regid,
                      const void *value, size_t *size, int *setpc);

void uc_init_m68k(struct uc_struct *uc);
#endif
