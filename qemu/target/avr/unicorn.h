/* Unicorn Emulator Engine */
/* By Nguyen Anh Quynh <aquynh@gmail.com>, 2015 */

/*
   Modified for Unicorn Engine by Glenn Baker <glenn.baker@gmx.com>, 2024
*/

#ifndef UC_QEMU_TARGET_AVR_H
#define UC_QEMU_TARGET_AVR_H

// functions to read & write registers
uc_err reg_read_avr(void *env, int mode, unsigned int regid, void *value,
                    size_t *size);
uc_err reg_write_avr(void *env, int mode, unsigned int regid,
                     const void *value, size_t *size, int *setpc);

void uc_init_avr(struct uc_struct *uc);

int avr_cpu_model_valid(int cpu_model);

#endif /* UC_QEMU_TARGET_AVR_H */
