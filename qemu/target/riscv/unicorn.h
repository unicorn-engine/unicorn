/* Unicorn Emulator Engine */
/* By Nguyen Anh Quynh <aquynh@gmail.com>, 2015 */
/* Modified for Unicorn Engine by Chen Huitao<chenhuitao@hfmrit.com>, 2020 */

#ifndef UC_QEMU_TARGET_RISCV_H
#define UC_QEMU_TARGET_RISCV_H

// functions to read & write registers
uc_err reg_read_riscv32(void *env, int mode, unsigned int regid, void *value,
                        size_t *size);
uc_err reg_read_riscv64(void *env, int mode, unsigned int regid, void *value,
                        size_t *size);
uc_err reg_write_riscv32(void *env, int mode, unsigned int regid,
                         const void *value, size_t *size, int *setpc);
uc_err reg_write_riscv64(void *env, int mode, unsigned int regid,
                         const void *value, size_t *size, int *setpc);

void uc_init_riscv32(struct uc_struct *uc);
void uc_init_riscv64(struct uc_struct *uc);
#endif
