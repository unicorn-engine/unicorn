/* Unicorn Emulator Engine */
/* By Nguyen Anh Quynh <aquynh@gmail.com>, 2015 */

/*
   Modified for Unicorn Engine by Glenn Baker <glenn.baker@gmx.com>, 2024
*/

#ifndef UC_QEMU_TARGET_AVR_H
#define UC_QEMU_TARGET_AVR_H

// functions to read & write registers
int avr_reg_read(struct uc_struct *uc, unsigned int *regs, void **vals,
                     int count);
int avr_reg_write(struct uc_struct *uc, unsigned int *regs,
                      void *const *vals, int count);

int avr_context_reg_read(struct uc_context *uc, unsigned int *regs,
                             void **vals, int count);
int avr_context_reg_write(struct uc_context *uc, unsigned int *regs,
                              void *const *vals, int count);

void avr_reg_reset(struct uc_struct *uc);

void avr_uc_init(struct uc_struct *uc);

int avr_cpu_model_valid(int cpu_model);

#endif /* UC_QEMU_TARGET_AVR_H */
