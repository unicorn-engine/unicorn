/* Unicorn Emulator Engine */
/* By Nguyen Anh Quynh <aquynh@gmail.com>, 2015 */

#ifndef UC_QEMU_TARGET_SPARC_H
#define UC_QEMU_TARGET_SPARC_H

// functions to read & write registers
uc_err reg_read_sparc(void *env, int mode, unsigned int regid, void *value,
                      size_t *size);
uc_err reg_read_sparc64(void *env, int mode, unsigned int regid, void *value,
                        size_t *size);
uc_err reg_write_sparc(void *env, int mode, unsigned int regid,
                       const void *value, size_t *size, int *setpc);
uc_err reg_write_sparc64(void *env, int mode, unsigned int regid,
                         const void *value, size_t *size, int *setpc);

void uc_init_sparc(struct uc_struct *uc);
void uc_init_sparc64(struct uc_struct *uc);
#endif
