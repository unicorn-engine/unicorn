#include "unicorn_test.h"

const uint64_t code_start = 0x1000;
const uint64_t code_len = 0x4000;

static void uc_common_setup(uc_engine** uc, uc_arch arch, uc_mode mode, const char* code, uint64_t size) {
    OK(uc_open(arch, mode, uc));
    OK(uc_mem_map(*uc, code_start, code_len, UC_PROT_ALL));
    OK(uc_mem_write(*uc, code_start, code, size));
}


static void test_arm64_copregs() {
    uc_engine* uc;
    uint64_t val1= 0,val2 =0;
    uint64_t pmccntr = 0x1F;

    /*
    mov X1, 1
    LSL X1,X1,31
    MSR PMCNTENSET_EL0, X1
    MRS X1, PMCCNTR_EL0
    */
    char code[] = "\x21\x00\x80\xd2\x21\x80\x61\xd3\x21\x9c\x1b\xd5\x01\x9d\x3b\xd5";

    uc_common_setup(&uc, UC_ARCH_ARM64, UC_MODE_ARM, code, sizeof(code) );
    
    OK(uc_reg_write(uc, UC_ARM64_REG_PMCCNTR_EL0, &pmccntr));
    OK(uc_reg_read(uc, UC_ARM64_REG_PMCCNTR_EL0, &val2));
    TEST_CHECK(pmccntr == val2);
    OK(uc_emu_start(uc, code_start , code_start + sizeof(code) -1 , 0, 0));

    OK(uc_reg_read(uc, UC_ARM64_REG_PMCNTENSET_EL0, &val1));
    TEST_CHECK(val1 == 0x80000000);
   
    OK(uc_reg_read(uc, UC_ARM64_REG_X1, &val2));
    TEST_CHECK(pmccntr == val2);

}

TEST_LIST = {
    { "test_arm64_copregs", test_arm64_copregs },
    { NULL, NULL }
};