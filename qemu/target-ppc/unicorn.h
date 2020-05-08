/* Unicorn Emulator Engine */
/* By Nguyen Anh Quynh <aquynh@gmail.com>, 2015 */

#ifndef UC_QEMU_TARGET_PPC_H
#define UC_QEMU_TARGET_PPC_H

// functions to read & write registers
int ppc_reg_read(struct uc_struct *uc, unsigned int *regs, void **vals, int count);
int ppc_reg_write(struct uc_struct *uc, unsigned int *regs, void *const *vals, int count);

void ppc_reg_reset(struct uc_struct *uc);

void ppc_uc_init(struct uc_struct* uc);
void ppc64_uc_init(struct uc_struct* uc);

extern const int PPC_REGS_STORAGE_SIZE_ppc;
extern const int PPC64_REGS_STORAGE_SIZE_ppc64;

#endif
