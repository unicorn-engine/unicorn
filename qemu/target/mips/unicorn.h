/* Unicorn Emulator Engine */
/* By Nguyen Anh Quynh <aquynh@gmail.com>, 2015 */

#ifndef UC_QEMU_TARGET_MIPS_H
#define UC_QEMU_TARGET_MIPS_H

// functions to read & write registers
uc_err reg_read_mips(void *env, int mode, unsigned int regid, void *value,
                     size_t *size);
uc_err reg_read_mipsel(void *env, int mode, unsigned int regid, void *value,
                       size_t *size);
uc_err reg_read_mips64(void *env, int mode, unsigned int regid, void *value,
                       size_t *size);
uc_err reg_read_mips64el(void *env, int mode, unsigned int regid, void *value,
                         size_t *size);

uc_err reg_write_mips(void *env, int mode, unsigned int regid,
                      const void *value, size_t *size, int *setpc);
uc_err reg_write_mipsel(void *env, int mode, unsigned int regid,
                        const void *value, size_t *size, int *setpc);
uc_err reg_write_mips64(void *env, int mode, unsigned int regid,
                        const void *value, size_t *size, int *setpc);
uc_err reg_write_mips64el(void *env, int mode, unsigned int regid,
                          const void *value, size_t *size, int *setpc);

void uc_init_mips(struct uc_struct *uc);
void uc_init_mipsel(struct uc_struct *uc);
void uc_init_mips64(struct uc_struct *uc);
void uc_init_mips64el(struct uc_struct *uc);
#endif
