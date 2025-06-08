#include "unicorn_test.h"

const uint64_t code_start = 0x1000;
const uint64_t code_len = 0x4000;

static void test_virtual_read(void)
{
    uc_engine *uc;
    uint8_t u8 = 8;

    OK(uc_open(UC_ARCH_SPARC, UC_MODE_SPARC32|UC_MODE_BIG_ENDIAN, &uc));
    OK(uc_mem_map(uc, code_start, code_len, UC_PROT_ALL));

    uc_assert_err(UC_ERR_ARG, uc_vmem_read(uc, code_start, UC_PROT_READ, &u8, sizeof(u8)));
    OK(uc_ctl_tlb_mode(uc, UC_TLB_VIRTUAL));
    OK(uc_vmem_read(uc, code_start, UC_PROT_READ, &u8, sizeof(u8)));
}

TEST_LIST = {
        {"test_virtual_read", test_virtual_read},
        {NULL, NULL}
};
