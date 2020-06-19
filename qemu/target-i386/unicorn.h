/* Unicorn Emulator Engine */
/* By Nguyen Anh Quynh <aquynh@gmail.com>, 2015 */
/* Modified for Unicorn Engine by Chen Huitao<chenhuitao@hfmrit.com>, 2020 */

#ifndef UC_QEMU_TARGET_I386_H
#define UC_QEMU_TARGET_I386_H

// functions to read & write registers
int x86_reg_read(struct uc_struct *uc, unsigned int *regs, void **vals, int count);
int x86_reg_write(struct uc_struct *uc, unsigned int *regs, void *const *vals, int count);

void x86_reg_reset(struct uc_struct *uc);

void x86_uc_init(struct uc_struct* uc);

extern const int X86_REGS_STORAGE_SIZE;
#endif
