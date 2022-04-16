#include "unicorn_test.h"

const uint64_t code_start = 0x1000;
const uint64_t code_len = 0x4000;

static void uc_common_setup(uc_engine **uc, uc_arch arch, uc_mode mode,
                            const char *code, uint64_t size,
                            uc_cpu_m68k cpu_model)
{
    OK(uc_open(arch, mode, uc));
    OK(uc_ctl_set_cpu_model(*uc, cpu_model));
    OK(uc_mem_map(*uc, code_start, code_len, UC_PROT_ALL));
    OK(uc_mem_write(*uc, code_start, code, size));
}

static void test_move_to_sr(void)
{

    uc_engine *uc;
    char code[] = "\x46\xfc\x27\x00"; // move    #$2700,sr
    int r_sr;

    uc_common_setup(&uc, UC_ARCH_M68K, UC_MODE_BIG_ENDIAN, code,
                    sizeof(code) - 1, UC_CPU_M68K_M68000);
    OK(uc_reg_read(uc, UC_M68K_REG_SR, &r_sr));

    r_sr = r_sr | 0x2000;

    OK(uc_reg_write(uc, UC_M68K_REG_SR, &r_sr));

    OK(uc_emu_start(uc, code_start, code_start + sizeof(code) - 1, 0, 0));

    OK(uc_close(uc));
}

TEST_LIST = {{"test_move_to_sr", test_move_to_sr}, {NULL, NULL}};