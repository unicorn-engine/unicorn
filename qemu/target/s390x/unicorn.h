/* Unicorn Emulator Engine */
/* By Nguyen Anh Quynh <aquynh@gmail.com>, 2015-2021 */

#ifndef UC_QEMU_TARGET_S390X_H
#define UC_QEMU_TARGET_S390X_H

// functions to read & write registers
uc_err reg_read_s390x(void *env, int mode, unsigned int regid, void *value,
                      size_t *size);
uc_err reg_write_s390x(void *env, int mode, unsigned int regid,
                       const void *value, size_t *size, int *setpc);

void uc_init_s390x(struct uc_struct *uc);
#endif
