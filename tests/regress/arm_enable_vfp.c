#include <unicorn/unicorn.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#define ADDRESS 0x1000
#define ARM_VMOV "\xC0\xEF\x10\x00" // VMOV.I32 D16, #0 ; Vector Move

int main()
{
    uc_engine *uc;
    uc_err err;

    err = uc_open(UC_ARCH_ARM, UC_MODE_ARM, &uc);
    if (err) {
        printf("uc_open %d\n", err);
        return 1;
    }

    uint64_t tmp_val;

    err = uc_reg_read(uc, UC_ARM_REG_C1_C0_2, &tmp_val);
    if (err) {
        printf("uc_open %d\n", err);
        return 1;
    }

    tmp_val = tmp_val | (0xf << 20);
    err = uc_reg_write(uc, UC_ARM_REG_C1_C0_2, &tmp_val);
    if (err) {
        printf("uc_open %d\n", err);
        return 1;
    }

    size_t enable_vfp = 0x40000000;
    err = uc_reg_write(uc, UC_ARM_REG_FPEXC, &enable_vfp);
    if (err) {
        printf("uc_open %d\n", err);
        return 1;
    }

    err = uc_mem_map(uc, ADDRESS, 4 * 1024, UC_PROT_ALL);
    if (err) {
        printf("uc_mem_map %d\n", err);
        return 1;
    }

    err = uc_mem_write(uc, ADDRESS, ARM_VMOV, sizeof(ARM_VMOV) - 1);
    if (err) {
        printf("uc_mem_map %s\n", uc_strerror(err));
        return 1;
    }

    err = uc_emu_start(uc, ADDRESS, 0, 0, 1);
    if (err) {
        printf("uc_emu_start: %s\n", uc_strerror(err));
        return 1;
    }

    printf("Success\n");

    uc_close(uc);

    return 0;
}
