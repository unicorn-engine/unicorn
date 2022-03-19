/* Unicorn Emulator Engine */
/* By Nguyen Anh Quynh <aquynh@gmail.com>, 2015-2021 */

#ifndef UC_QEMU_TARGET_S390X_H
#define UC_QEMU_TARGET_S390X_H

// functions to read & write registers
// int s390_reg_read(struct uc_struct *uc, unsigned int *regs, void **vals, int
// count); int s390_reg_write(struct uc_struct *uc, unsigned int *regs, void
// *const *vals, int count);
int s390_context_reg_read(struct uc_context *ctx, unsigned int *regs,
                          void **vals, int count);
int s390_context_reg_write(struct uc_context *ctx, unsigned int *regs,
                           void *const *vals, int count);

void s390_reg_reset(struct uc_struct *uc);

void s390_uc_init(struct uc_struct *uc);
#endif
