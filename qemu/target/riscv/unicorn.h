/* Unicorn Emulator Engine */
/* By Nguyen Anh Quynh <aquynh@gmail.com>, 2015 */
/* Modified for Unicorn Engine by Chen Huitao<chenhuitao@hfmrit.com>, 2020 */

#ifndef UC_QEMU_TARGET_RISCV_H
#define UC_QEMU_TARGET_RISCV_H

// functions to read & write registers
int riscv_reg_read(struct uc_struct *uc, unsigned int *regs, void **vals,
                   int count, uint32_t *reg_size);
int riscv_reg_write(struct uc_struct *uc, unsigned int *regs, void *const *vals,
                    int count, uint32_t *reg_size);

int riscv32_context_reg_read(struct uc_context *ctx, unsigned int *regs,
                             void **vals, int count, uint32_t *reg_size);
int riscv32_context_reg_write(struct uc_context *ctx, unsigned int *regs,
                              void *const *vals, int count, uint32_t *reg_size);
int riscv64_context_reg_read(struct uc_context *ctx, unsigned int *regs,
                             void **vals, int count, uint32_t *reg_size);
int riscv64_context_reg_write(struct uc_context *ctx, unsigned int *regs,
                              void *const *vals, int count, uint32_t *reg_size);

void riscv_reg_reset(struct uc_struct *uc);

void riscv32_uc_init(struct uc_struct *uc);
void riscv64_uc_init(struct uc_struct *uc);
#endif
