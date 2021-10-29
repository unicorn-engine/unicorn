/* Unicorn Emulator Engine */
/* By Nguyen Anh Quynh <aquynh@gmail.com>, 2015 */

#ifndef UC_QEMU_TARGET_SPARC_H
#define UC_QEMU_TARGET_SPARC_H

// functions to read & write registers
int sparc_reg_read(struct uc_struct *uc, unsigned int *regs, void **vals,
                   int count);
int sparc_reg_write(struct uc_struct *uc, unsigned int *regs, void *const *vals,
                    int count);

int sparc_context_reg_read(struct uc_context *ctx, unsigned int *regs,
                           void **vals, int count);
int sparc_context_reg_write(struct uc_context *ctx, unsigned int *regs,
                            void *const *vals, int count);
int sparc64_context_reg_read(struct uc_context *ctx, unsigned int *regs,
                             void **vals, int count);
int sparc64_context_reg_write(struct uc_context *ctx, unsigned int *regs,
                              void *const *vals, int count);

void sparc_reg_reset(struct uc_struct *uc);

void sparc_uc_init(struct uc_struct *uc);
void sparc64_uc_init(struct uc_struct *uc);
#endif
