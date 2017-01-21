/* Unicorn Emulator Engine */
/* By Nguyen Anh Quynh <aquynh@gmail.com>, 2015 */

#ifndef UC_QEMU_TARGET_ARM_H
#define UC_QEMU_TARGET_ARM_H

// functions to read & write registers
int arm_reg_read(struct uc_struct *uc, unsigned int *regs, void **vals, int count);
int arm_reg_write(struct uc_struct *uc, unsigned int *regs, void *const *vals, int count);
int arm64_reg_read(struct uc_struct *uc, unsigned int *regs, void **vals, int count);
int arm64_reg_write(struct uc_struct *uc, unsigned int *regs, void *const *vals, int count);

void arm_reg_reset(struct uc_struct *uc);
void arm64_reg_reset(struct uc_struct *uc);

DEFAULT_VISIBILITY
void arm_uc_init(struct uc_struct* uc);

DEFAULT_VISIBILITY
void arm64_uc_init(struct uc_struct* uc);

extern const int ARM_REGS_STORAGE_SIZE;
extern const int ARM64_REGS_STORAGE_SIZE;

#endif
