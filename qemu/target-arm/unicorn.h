/* Unicorn Emulator Engine */
/* By Nguyen Anh Quynh <aquynh@gmail.com>, 2015 */

#ifndef UC_QEMU_TARGET_ARM_H
#define UC_QEMU_TARGET_ARM_H

typedef struct  {
    int uc_reg_id;

    uint8_t cp;
    uint8_t crn;
    uint8_t crm;
    uint8_t opc0;
    uint8_t opc1;
    uint8_t opc2;

} uc_arm_cp_reg;


// functions to read & write registers
int arm_reg_read(struct uc_struct *uc, unsigned int *regs, void **vals, int count);
int arm_reg_write(struct uc_struct *uc, unsigned int *regs, void *const *vals, int count);
int arm64_reg_read(struct uc_struct *uc, unsigned int *regs, void **vals, int count);
int arm64_reg_write(struct uc_struct *uc, unsigned int *regs, void *const *vals, int count);

// functions to read & write coprocessor registers
int arm_cpreg_read(	struct uc_struct *uc,
					uint8_t cp,
					uint8_t crn,
					uint8_t crm,
					uint8_t opc0,
					uint8_t opc1,
					uint8_t opc2,
					void *value);

int arm64_cpreg_read(	struct uc_struct *uc,
						uint8_t cp,
						uint8_t crn,
						uint8_t crm,
						uint8_t opc0,
						uint8_t opc1,
						uint8_t opc2,
						void *value);

int arm_cpreg_write(struct uc_struct *uc,
					uint8_t cp,
					uint8_t cr,
					uint8_t crm,
					uint8_t opc0,
					uint8_t opc1,
					uint8_t opc2,
					const void *value);
int arm64_cpreg_write(	struct uc_struct *uc,
						uint8_t cp,
						uint8_t cr,
						uint8_t crm,
						uint8_t opc0,
						uint8_t opc1,
						uint8_t opc2,
						const void *value);

void arm_reg_reset(struct uc_struct *uc);
void arm64_reg_reset(struct uc_struct *uc);

DEFAULT_VISIBILITY
void arm_uc_init(struct uc_struct* uc);
void armeb_uc_init(struct uc_struct* uc);

DEFAULT_VISIBILITY
void arm64_uc_init(struct uc_struct* uc);
void arm64eb_uc_init(struct uc_struct* uc);

extern const int ARM_REGS_STORAGE_SIZE_arm;
extern const int ARM_REGS_STORAGE_SIZE_armeb;
extern const int ARM64_REGS_STORAGE_SIZE_aarch64;
extern const int ARM64_REGS_STORAGE_SIZE_aarch64eb;

extern const uc_arm_cp_reg ARM_CP_REGS_INFO_arm[];
extern const uc_arm_cp_reg ARM_CP_REGS_INFO_armeb[];
extern const uc_arm_cp_reg ARM64_CP_REGS_INFO_aarch64eb[];
extern const uc_arm_cp_reg ARM64_CP_REGS_INFO_aarch64[];

#endif
