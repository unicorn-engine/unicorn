#include "unicorn_test.h"

const uint64_t code_start = 0x10000;
const uint64_t code_len = 0x10000;

static void uc_common_setup(uc_engine **uc, uc_arch arch, uc_mode mode,
                            const char *code, uint64_t size)
{
    OK(uc_open(arch, mode, uc));
    OK(uc_mem_map(*uc, code_start, code_len, UC_PROT_ALL));
    OK(uc_mem_write(*uc, code_start, code, size));
}

static void test_tricore_ld_bu_preinc(void)
{
    uc_engine *uc;
    char code[] = "\x09\x2f\x41\x04"; // ld.bu d15, [+a2]0x1
    const uint64_t data_addr = 0x20000;
    uint32_t d15 = 0;
    uint32_t a2 = data_addr;
    uint8_t data = 0xbc;

    uc_common_setup(&uc, UC_ARCH_TRICORE, UC_MODE_LITTLE_ENDIAN, code,
                    sizeof(code) - 1);
    OK(uc_mem_map(uc, data_addr, 0x10000, UC_PROT_ALL));
    OK(uc_mem_write(uc, data_addr + 1, &data, sizeof(data)));
    OK(uc_reg_write(uc, UC_TRICORE_REG_A2, &a2));

    OK(uc_emu_start(uc, code_start, code_start + sizeof(code) - 1, 0, 1));

    OK(uc_reg_read(uc, UC_TRICORE_REG_D15, &d15));
    OK(uc_reg_read(uc, UC_TRICORE_REG_A2, &a2));

    TEST_CHECK(a2 == data_addr + 1);
    TEST_CHECK(d15 == 0x000000bc);

    OK(uc_close(uc));
}

static void test_tricore_mtcr_icr(void)
{
    uc_engine *uc;
    const uint32_t psw = 0x00000b7f;
    uint32_t icr = 0;
    char code[] = {
        0x0d, 0x00, 0x40, 0x03, /* disable */
        0x4d, 0xc0, 0xe2, 0xff, /* mfcr d15, icr */
        0x96, 0xff,             /* or d15, 0xff */
        0xcd, 0xcf, 0xe2, 0x0f, /* mtcr icr, d15 */
        0x0d, 0x00, 0x00, 0x03  /* enable */
    };

    uc_common_setup(&uc, UC_ARCH_TRICORE, UC_MODE_LITTLE_ENDIAN, code,
                    sizeof(code));
    OK(uc_reg_write(uc, UC_TRICORE_REG_PSW, &psw));
    OK(uc_reg_write(uc, UC_TRICORE_REG_ICR, &icr));

    OK(uc_emu_start(uc, code_start, code_start + sizeof(code), 0, 0));

    OK(uc_reg_read(uc, UC_TRICORE_REG_ICR, &icr));

    TEST_CHECK((icr & 0xff) == 0xff);
    TEST_MSG("icr = %#x", icr);

    OK(uc_close(uc));
}

TEST_LIST = {
    {"test_tricore_ld_bu_preinc", test_tricore_ld_bu_preinc},
    {"test_tricore_mtcr_icr", test_tricore_mtcr_icr},
    {NULL, NULL}};
