/* Unicorn Emulator Engine */
/* By Nguyen Anh Quynh <aquynh@gmail.com>, 2015 */

/*
   Modified for Unicorn Engine by Eric Poole <eric.poole@aptiv.com>, 2022
   Copyright 2022 Aptiv
*/

#ifndef UC_QEMU_TARGET_TRICORE_H
#define UC_QEMU_TARGET_TRICORE_H

// functions to read & write registers
int tricore_reg_read(struct uc_struct *uc, unsigned int *regs, void **vals,
                     int count, uint32_t *reg_size);
int tricore_reg_write(struct uc_struct *uc, unsigned int *regs,
                      void *const *vals, int count, uint32_t *reg_size);

int tricore_context_reg_read(struct uc_context *uc, unsigned int *regs,
                             void **vals, int count, uint32_t *reg_size);
int tricore_context_reg_write(struct uc_context *uc, unsigned int *regs,
                              void *const *vals, int count, uint32_t *reg_size);

void tricore_reg_reset(struct uc_struct *uc);

void tricore_uc_init(struct uc_struct *uc);

#endif
