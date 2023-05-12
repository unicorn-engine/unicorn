/* Unicorn Emulator Engine */
/* By Nguyen Anh Quynh <aquynh@gmail.com>, 2015 */

#ifndef UC_QEMU_TARGET_ARM_H
#define UC_QEMU_TARGET_ARM_H

// functions to read & write registers
uc_err reg_read_arm(void *env, int mode, unsigned int regid, void *value,
                    size_t *size);
uc_err reg_read_aarch64(void *env, int mode, unsigned int regid, void *value,
                        size_t *size);
uc_err reg_write_arm(void *env, int mode, unsigned int regid, const void *value,
                     size_t *size, int *setpc);
uc_err reg_write_aarch64(void *env, int mode, unsigned int regid,
                         const void *value, size_t *size, int *setpc);

void uc_init_arm(struct uc_struct *uc);
void uc_init_aarch64(struct uc_struct *uc);
#endif
