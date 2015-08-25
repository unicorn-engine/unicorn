/* Unicorn Emulator Engine */
/* By Nguyen Anh Quynh <aquynh@gmail.com>, 2015 */

#ifndef UC_QEMU_TARGET_I386_H
#define UC_QEMU_TARGET_I386_H

// functions to read & write registers
int x86_reg_read(uch handle, unsigned int regid, void *value);
int x86_reg_write(uch handle, unsigned int regid, const void *value);

void x86_reg_reset(uch handle);

void x86_uc_init(struct uc_struct* uc);
int x86_uc_machine_init(struct uc_struct *uc);
#endif
