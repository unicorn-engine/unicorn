/* Unicorn Emulator Engine */
/* By Damien Cauquil <dcauquil@quarkslab.com>, 2023 */

#ifndef UC_QEMU_TARGET_RH850_H
#define UC_QEMU_TARGET_RH850_H

// functions to read & write registers
// int s390_reg_read(struct uc_struct *uc, unsigned int *regs, void **vals, int
// count); int s390_reg_write(struct uc_struct *uc, unsigned int *regs, void
// *const *vals, int count);
int rh850_context_reg_read(struct uc_context *ctx, unsigned int *regs,
                          void **vals, int count);
int rh850_context_reg_write(struct uc_context *ctx, unsigned int *regs,
                           void *const *vals, int count);

void rh850_reg_reset(struct uc_struct *uc);

void rh850_uc_init(struct uc_struct *uc);
#endif
