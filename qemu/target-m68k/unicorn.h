/* Unicorn Emulator Engine */
/* By Nguyen Anh Quynh <aquynh@gmail.com>, 2015 */

#ifndef UC_QEMU_TARGET_M68K_H
#define UC_QEMU_TARGET_M68K_H

// functions to read & write registers
int m68k_reg_read(uch handle, unsigned int regid, void *value);
int m68k_reg_write(uch handle, unsigned int regid, const void *value);

void m68k_reg_reset(uch handle);

void m68k_uc_init(struct uc_struct* uc);

#endif
