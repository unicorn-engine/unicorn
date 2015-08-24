/* Unicorn Emulator Engine */
/* By Nguyen Anh Quynh <aquynh@gmail.com>, 2015 */

#ifndef UC_QEMU_TARGET_ARM_H
#define UC_QEMU_TARGET_ARM_H

// functions to read & write registers
int arm_reg_read(uch handle, unsigned int regid, void *value);
int arm_reg_write(uch handle, unsigned int regid, const void *value);
int arm64_reg_read(uch handle, unsigned int regid, void *value);
int arm64_reg_write(uch handle, unsigned int regid, const void *value);

void arm_reg_reset(uch handle);
void arm64_reg_reset(uch handle);

__attribute__ ((visibility ("default")))
void arm_uc_init(struct uc_struct* uc);

__attribute__ ((visibility ("default")))
void arm64_uc_init(struct uc_struct* uc);

#endif
