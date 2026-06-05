// Regression test for https://github.com/unicorn-engine/unicorn/issues/1779
// PPC64 std/ld instructions caused UC_ERR_EXCEPTION due to:
//   1. cpu_model index not offset into ppc_cpus[] for user-set PPC64 models
//   2. MSR[HV] dropped at reset, breaking POWER9/10 real-mode instruction fetch

#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include <unicorn/unicorn.h>

// std r3, 0(r4)   F8 64 00 00
// ld  r5, 0(r4)   E8 A4 00 00
#define PPC64_CODE "\xF8\x64\x00\x00\xE8\xA4\x00\x00"

#define CODE_ADDR 0x1000000ULL
#define DATA_ADDR 0x2000000ULL

static void test(const char *label, int model)
{
    uc_engine *uc;
    uc_err err;
    uint64_t r3 = 0xDEADBEEFCAFEBABEULL;
    uint64_t r4 = DATA_ADDR;
    uint64_t r5 = 0;

    err = uc_open(UC_ARCH_PPC, UC_MODE_PPC64 | UC_MODE_BIG_ENDIAN, &uc);
    assert(err == UC_ERR_OK);

    if (model != -1) {
        err = uc_ctl_set_cpu_model(uc, model);
        assert(err == UC_ERR_OK);
    }

    assert(uc_mem_map(uc, CODE_ADDR, 0x10000, UC_PROT_ALL) == UC_ERR_OK);
    assert(uc_mem_map(uc, DATA_ADDR, 0x10000, UC_PROT_ALL) == UC_ERR_OK);
    assert(uc_mem_write(uc, CODE_ADDR, PPC64_CODE, sizeof(PPC64_CODE) - 1) == UC_ERR_OK);
    assert(uc_reg_write(uc, UC_PPC_REG_3, &r3) == UC_ERR_OK);
    assert(uc_reg_write(uc, UC_PPC_REG_4, &r4) == UC_ERR_OK);

    err = uc_emu_start(uc, CODE_ADDR, CODE_ADDR + sizeof(PPC64_CODE) - 1, 0, 0);
    if (err != UC_ERR_OK) {
        fprintf(stderr, "FAIL [%s]: uc_emu_start: %s\n", label, uc_strerror(err));
        assert(0);
    }

    assert(uc_reg_read(uc, UC_PPC_REG_5, &r5) == UC_ERR_OK);
    if (r5 != r3) {
        fprintf(stderr, "FAIL [%s]: r5=0x%016llx want 0x%016llx\n",
                label, (unsigned long long)r5, (unsigned long long)r3);
        assert(0);
    }

    uc_close(uc);
}

int main(void)
{
    test("default cpu",         -1);
    test("970_v2.2",            UC_CPU_PPC64_970_V2_2);
    test("970fx_v3.1",          UC_CPU_PPC64_970FX_V3_1);
    test("power5+_v2.1",        UC_CPU_PPC64_POWER5_V2_1);
    test("power7_v2.3",         UC_CPU_PPC64_POWER7_V2_3);
    test("power8_v2.0",         UC_CPU_PPC64_POWER8_V2_0);
    test("power9_v2.0",         UC_CPU_PPC64_POWER9_V2_0);
    test("power10_v1.0",        UC_CPU_PPC64_POWER10_V1_0);
    return 0;
}
