/* Unicorn Emulator Engine */
/* By Nguyen Anh Quynh <aquynh@gmail.com>, 2015 */

#ifndef UC_QEMU_TARGET_SPARC_H
#define UC_QEMU_TARGET_SPARC_H

// functions to read & write registers
int sparc_reg_read(uch handle, unsigned int regid, void *value);
int sparc_reg_write(uch handle, unsigned int regid, void *value);

void sparc_reg_reset(uch handle);

void sparc_uc_init(struct uc_struct* uc);
void sparc64_uc_init(struct uc_struct* uc);

#endif
