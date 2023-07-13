/* Unicorn Emulator Engine */
/* By Nguyen Anh Quynh <aquynh@gmail.com>, 2015 */

#ifndef UC_QEMU_TARGET_PPC_H
#define UC_QEMU_TARGET_PPC_H

// functions to read & write registers
uc_err reg_read_ppc(void *env, int mode, unsigned int regid, void *value,
                    size_t *size);
uc_err reg_read_ppc64(void *env, int mode, unsigned int regid, void *value,
                      size_t *size);
uc_err reg_write_ppc(void *env, int mode, unsigned int regid, const void *value,
                     size_t *size, int *setpc);
uc_err reg_write_ppc64(void *env, int mode, unsigned int regid,
                       const void *value, size_t *size, int *setpc);

void uc_init_ppc(struct uc_struct *uc);
void uc_init_ppc64(struct uc_struct *uc);
#endif
