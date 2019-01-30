/* Unicorn Emulator Engine */
/* By Nguyen Anh Quynh <aquynh@gmail.com>, 2015 */

#ifndef UC_QEMU_TARGET_MIPS_H
#define UC_QEMU_TARGET_MIPS_H

// functions to read & write registers
int mips_reg_read(struct uc_struct *uc, unsigned int *regs, void **vals, int count);
int mips_reg_write(struct uc_struct *uc, unsigned int *regs, void *const *vals, int count);

void mips_reg_reset(struct uc_struct *uc);

void mips_uc_init(struct uc_struct* uc);
void mipsel_uc_init(struct uc_struct* uc);
void mips64_uc_init(struct uc_struct* uc);
void mips64el_uc_init(struct uc_struct* uc);

extern const int MIPS_REGS_STORAGE_SIZE_mips;
extern const int MIPS_REGS_STORAGE_SIZE_mipsel;
extern const int MIPS64_REGS_STORAGE_SIZE_mips64;
extern const int MIPS64_REGS_STORAGE_SIZE_mips64el;

#endif
