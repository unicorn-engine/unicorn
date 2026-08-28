#include "unicorn_test.h"

#include <string.h>

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

static void setup_stack_pointers(uc_engine *uc, uint32_t ssp,
                                 uint32_t usp, uint32_t isp)
{
    uint32_t sr = 0;

    OK(uc_reg_write(uc, UC_M68K_REG_SR, &sr));
    OK(uc_reg_write(uc, UC_M68K_REG_A7, &usp));
    OK(uc_reg_write(uc, UC_M68K_REG_CR_MSP, &ssp));
    OK(uc_reg_write(uc, UC_M68K_REG_CR_ISP, &isp));
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

    OK(uc_reg_read(uc, UC_M68K_REG_SR, &r_sr));

    TEST_CHECK(r_sr == 0x2700);

    OK(uc_close(uc));
}

static void test_sr_contains_flags(void)
{
    uc_engine *uc;
    uint8_t code[] = {
        0x76, 0xed, // moveq #-19, %d3
    };

    uint32_t d3, sr;

    uc_common_setup(&uc, UC_ARCH_M68K, UC_MODE_BIG_ENDIAN, code, sizeof(code),
                    UC_CPU_M68K_M68000);

    OK(uc_emu_start(uc, code_start, code_start + sizeof(code), 0, 0));

    OK(uc_reg_read(uc, UC_M68K_REG_D3, &d3));
    OK(uc_reg_read(uc, UC_M68K_REG_SR, &sr));

    TEST_CHECK(d3 == 0xFFFFFFED);
    TEST_CHECK((sr & 0x8) /* N flag */ == 0x8);

    OK(uc_close(uc));
}

static void test_fetoxm1(void)
{
    uc_engine *uc;
    uint8_t code[] = {
        0xf2, 0x10, 0x54, 0x00, /* fmove.d (a0), fp0 */
        0xf2, 0x00, 0x00, 0x08, /* fetoxm1 fp0, fp0 */
        0xf2, 0x10, 0x74, 0x00, /* fmove.d fp0, (a0) */
    };
    uint8_t input[] = {
        0x3f, 0xf0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    };
    uint8_t expected[] = {
        0x3f, 0xfb, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd3,
    };
    uint8_t result[sizeof(expected)];
    uint32_t a0 = code_start + 0x100;

    uc_common_setup(&uc, UC_ARCH_M68K, UC_MODE_BIG_ENDIAN, (char *)code,
                    sizeof(code), UC_CPU_M68K_M68020);
    OK(uc_mem_write(uc, a0, input, sizeof(input)));
    OK(uc_reg_write(uc, UC_M68K_REG_A0, &a0));

    OK(uc_emu_start(uc, code_start, code_start + sizeof(code), 0, 0));
    OK(uc_mem_read(uc, a0, result, sizeof(result)));

    TEST_CHECK(memcmp(result, expected, sizeof(expected)) == 0);

    OK(uc_close(uc));
}

static void test_coldfire_macsr_to_ccr(void)
{
    uc_engine *uc;
    uint8_t code[] = {
        0xa9, 0x00, /* move.l d0, MACSR */
        0xa9, 0xc0, /* MACSR -> CCR */
    };
    uint32_t d0 = 0x0f;
    uint32_t sr = 0x2700;

    uc_common_setup(&uc, UC_ARCH_M68K, UC_MODE_BIG_ENDIAN, (char *)code,
                    sizeof(code), UC_CPU_M68K_CFV4E);
    OK(uc_reg_write(uc, UC_M68K_REG_D0, &d0));
    OK(uc_reg_write(uc, UC_M68K_REG_SR, &sr));

    OK(uc_emu_start(uc, code_start, code_start + sizeof(code), 0, 0));
    OK(uc_reg_read(uc, UC_M68K_REG_SR, &sr));

    TEST_CHECK(sr == 0x270e);

    OK(uc_close(uc));
}

static void test_ftrapcc_false_consumes_immediate(void)
{
    uc_engine *uc;
    uint8_t code[] = {
        0xf2, 0x7a, 0x00, 0x00, 0x12, 0x34, /* ftrapf.w #$1234 */
        0x70, 0x2a,                         /* moveq #42, d0 */
    };
    uint32_t d0;
    uint32_t pc;

    uc_common_setup(&uc, UC_ARCH_M68K, UC_MODE_BIG_ENDIAN, (char *)code,
                    sizeof(code), UC_CPU_M68K_M68020);

    OK(uc_emu_start(uc, code_start, code_start + sizeof(code), 0, 0));
    OK(uc_reg_read(uc, UC_M68K_REG_D0, &d0));
    OK(uc_reg_read(uc, UC_M68K_REG_PC, &pc));

    TEST_CHECK(d0 == 42);
    TEST_CHECK(pc == (uint32_t)(code_start + sizeof(code)));

    OK(uc_close(uc));
}

static void test_ftrapcc_true_raises(void)
{
    uc_engine *uc;
    uint8_t code[] = {
        0xf2, 0x7c, 0x00, 0x0f, /* ftrapt */
        0x70, 0x2a,             /* moveq #42, d0 */
    };
    uint32_t d0 = 0;
    uint32_t pc;

    uc_common_setup(&uc, UC_ARCH_M68K, UC_MODE_BIG_ENDIAN, (char *)code,
                    sizeof(code), UC_CPU_M68K_M68020);

    uc_assert_err(UC_ERR_EXCEPTION,
                  uc_emu_start(uc, code_start, code_start + sizeof(code),
                               0, 0));
    OK(uc_reg_read(uc, UC_M68K_REG_D0, &d0));
    OK(uc_reg_read(uc, UC_M68K_REG_PC, &pc));

    TEST_CHECK(d0 == 0);
    TEST_CHECK(pc == (uint32_t)(code_start + 4));

    OK(uc_close(uc));
}

static void test_trapcc_false_consumes_immediate(void)
{
    uc_engine *uc;
    uint8_t code[] = {
        0x51, 0xfa, 0x12, 0x34, /* trapf.w #$1234 */
        0x70, 0x2a,             /* moveq #42, d0 */
    };
    uint32_t d0;
    uint32_t pc;

    uc_common_setup(&uc, UC_ARCH_M68K, UC_MODE_BIG_ENDIAN, (char *)code,
                    sizeof(code), UC_CPU_M68K_M68020);

    OK(uc_emu_start(uc, code_start, code_start + sizeof(code), 0, 0));
    OK(uc_reg_read(uc, UC_M68K_REG_D0, &d0));
    OK(uc_reg_read(uc, UC_M68K_REG_PC, &pc));

    TEST_CHECK(d0 == 42);
    TEST_CHECK(pc == (uint32_t)(code_start + sizeof(code)));

    OK(uc_close(uc));
}

static void test_trapcc_true_raises(void)
{
    uc_engine *uc;
    uint8_t code[] = {
        0x50, 0xfc, /* trapt */
        0x70, 0x2a, /* moveq #42, d0 */
    };
    uint32_t d0 = 0;
    uint32_t pc;

    uc_common_setup(&uc, UC_ARCH_M68K, UC_MODE_BIG_ENDIAN, (char *)code,
                    sizeof(code), UC_CPU_M68K_M68020);

    uc_assert_err(UC_ERR_EXCEPTION,
                  uc_emu_start(uc, code_start, code_start + sizeof(code),
                               0, 0));
    OK(uc_reg_read(uc, UC_M68K_REG_D0, &d0));
    OK(uc_reg_read(uc, UC_M68K_REG_PC, &pc));

    TEST_CHECK(d0 == 0);
    TEST_CHECK(pc == (uint32_t)(code_start + 2));

    OK(uc_close(uc));
}

static void test_m68010_rtd(void)
{
    uc_engine *uc;
    uint8_t code[] = {
        0x4e, 0x74, 0x00, 0x00, /* rtd #0 */
    };
    uint8_t retaddr[] = {
        0x00, 0x00, 0x10, 0x04,
    };
    uint32_t sp = code_start + 0x100;
    uint32_t pc;

    uc_common_setup(&uc, UC_ARCH_M68K, UC_MODE_BIG_ENDIAN, (char *)code,
                    sizeof(code), UC_CPU_M68K_M68010);
    OK(uc_mem_write(uc, sp, retaddr, sizeof(retaddr)));
    OK(uc_reg_write(uc, UC_M68K_REG_A7, &sp));

    OK(uc_emu_start(uc, code_start, code_start + sizeof(code), 0, 0));
    OK(uc_reg_read(uc, UC_M68K_REG_PC, &pc));

    TEST_CHECK(pc == (uint32_t)(code_start + sizeof(code)));

    OK(uc_close(uc));
}

static void test_m68010_supervisor_uses_ssp(void)
{
    uc_engine *uc;
    uint8_t code[] = {
        0x4e, 0x71, /* nop */
    };
    uint32_t ssp = code_start + 0x300;
    uint32_t usp = code_start + 0x500;
    uint32_t isp = code_start + 0x700;
    uint32_t sr;
    uint32_t a7;

    uc_common_setup(&uc, UC_ARCH_M68K, UC_MODE_BIG_ENDIAN, (char *)code,
                    sizeof(code), UC_CPU_M68K_M68010);
    setup_stack_pointers(uc, ssp, usp, isp);

    OK(uc_reg_read(uc, UC_M68K_REG_A7, &a7));
    TEST_CHECK(a7 == usp);

    sr = 0x2000;
    OK(uc_reg_write(uc, UC_M68K_REG_SR, &sr));
    OK(uc_reg_read(uc, UC_M68K_REG_A7, &a7));
    TEST_CHECK(a7 == ssp);

    sr = 0x3000;
    OK(uc_reg_write(uc, UC_M68K_REG_SR, &sr));
    OK(uc_reg_read(uc, UC_M68K_REG_A7, &a7));
    TEST_CHECK(a7 == ssp);

    OK(uc_close(uc));
}

static void test_m68020_supervisor_uses_isp_and_msp(void)
{
    uc_engine *uc;
    uint8_t code[] = {
        0x4e, 0x71, /* nop */
    };
    uint32_t ssp = code_start + 0x300;
    uint32_t usp = code_start + 0x500;
    uint32_t isp = code_start + 0x700;
    uint32_t sr;
    uint32_t a7;

    uc_common_setup(&uc, UC_ARCH_M68K, UC_MODE_BIG_ENDIAN, (char *)code,
                    sizeof(code), UC_CPU_M68K_M68020);
    setup_stack_pointers(uc, ssp, usp, isp);

    sr = 0x2000;
    OK(uc_reg_write(uc, UC_M68K_REG_SR, &sr));
    OK(uc_reg_read(uc, UC_M68K_REG_A7, &a7));
    TEST_CHECK(a7 == isp);

    sr = 0x3000;
    OK(uc_reg_write(uc, UC_M68K_REG_SR, &sr));
    OK(uc_reg_read(uc, UC_M68K_REG_A7, &a7));
    TEST_CHECK(a7 == ssp);

    sr = 0;
    OK(uc_reg_write(uc, UC_M68K_REG_SR, &sr));
    OK(uc_reg_read(uc, UC_M68K_REG_A7, &a7));
    TEST_CHECK(a7 == usp);

    OK(uc_close(uc));
}

static void test_m68060_supervisor_uses_isp_and_msp(void)
{
    uc_engine *uc;
    uint8_t code[] = {
        0x4e, 0x71, /* nop */
    };
    uint32_t ssp = code_start + 0x300;
    uint32_t usp = code_start + 0x500;
    uint32_t isp = code_start + 0x700;
    uint32_t sr;
    uint32_t a7;

    uc_common_setup(&uc, UC_ARCH_M68K, UC_MODE_BIG_ENDIAN, (char *)code,
                    sizeof(code), UC_CPU_M68K_M68060);
    setup_stack_pointers(uc, ssp, usp, isp);

    sr = 0x2000;
    OK(uc_reg_write(uc, UC_M68K_REG_SR, &sr));
    OK(uc_reg_read(uc, UC_M68K_REG_A7, &a7));
    TEST_CHECK(a7 == isp);

    sr = 0x3000;
    OK(uc_reg_write(uc, UC_M68K_REG_SR, &sr));
    OK(uc_reg_read(uc, UC_M68K_REG_A7, &a7));
    TEST_CHECK(a7 == ssp);

    sr = 0;
    OK(uc_reg_write(uc, UC_M68K_REG_SR, &sr));
    OK(uc_reg_read(uc, UC_M68K_REG_A7, &a7));
    TEST_CHECK(a7 == usp);

    OK(uc_close(uc));
}

static void test_m68020_movec_msp_isp(void)
{
    uc_engine *uc;
    uint8_t code[] = {
        0x4e, 0x7b, 0x08, 0x03, /* movec d0, msp */
        0x4e, 0x7b, 0x18, 0x04, /* movec d1, isp */
        0x4e, 0x7a, 0x28, 0x03, /* movec msp, d2 */
        0x4e, 0x7a, 0x38, 0x04, /* movec isp, d3 */
    };
    uint32_t sr = 0x2000;
    uint32_t d0 = code_start + 0x300;
    uint32_t d1 = code_start + 0x700;
    uint32_t d2 = 0;
    uint32_t d3 = 0;
    uint32_t msp = 0;
    uint32_t isp = 0;

    uc_common_setup(&uc, UC_ARCH_M68K, UC_MODE_BIG_ENDIAN, (char *)code,
                    sizeof(code), UC_CPU_M68K_M68020);
    OK(uc_reg_write(uc, UC_M68K_REG_SR, &sr));
    OK(uc_reg_write(uc, UC_M68K_REG_D0, &d0));
    OK(uc_reg_write(uc, UC_M68K_REG_D1, &d1));

    OK(uc_emu_start(uc, code_start, code_start + sizeof(code), 0, 0));
    OK(uc_reg_read(uc, UC_M68K_REG_CR_MSP, &msp));
    OK(uc_reg_read(uc, UC_M68K_REG_CR_ISP, &isp));
    OK(uc_reg_read(uc, UC_M68K_REG_D2, &d2));
    OK(uc_reg_read(uc, UC_M68K_REG_D3, &d3));

    TEST_CHECK(msp == d0);
    TEST_CHECK(isp == d1);
    TEST_CHECK(d2 == d0);
    TEST_CHECK(d3 == d1);

    OK(uc_close(uc));
}

static void test_m68010_movec_msp_invalid(void)
{
    uc_engine *uc;
    uint8_t code[] = {
        0x4e, 0x7b, 0x08, 0x03, /* movec d0, msp */
    };
    uint32_t sr = 0x2000;
    uint32_t d0 = code_start + 0x300;

    uc_common_setup(&uc, UC_ARCH_M68K, UC_MODE_BIG_ENDIAN, (char *)code,
                    sizeof(code), UC_CPU_M68K_M68010);
    OK(uc_reg_write(uc, UC_M68K_REG_SR, &sr));
    OK(uc_reg_write(uc, UC_M68K_REG_D0, &d0));

    uc_assert_err(UC_ERR_EXCEPTION,
                  uc_emu_start(uc, code_start, code_start + sizeof(code),
                               0, 0));

    OK(uc_close(uc));
}

static void test_m68060_movec_msp_invalid(void)
{
    uc_engine *uc;
    uint8_t code[] = {
        0x4e, 0x7a, 0x08, 0x03, /* movec msp, d0 */
    };
    uint32_t sr = 0x2000;

    uc_common_setup(&uc, UC_ARCH_M68K, UC_MODE_BIG_ENDIAN, (char *)code,
                    sizeof(code), UC_CPU_M68K_M68060);
    OK(uc_reg_write(uc, UC_M68K_REG_SR, &sr));

    uc_assert_err(UC_ERR_EXCEPTION,
                  uc_emu_start(uc, code_start, code_start + sizeof(code),
                               0, 0));

    OK(uc_close(uc));
}

static void test_rtr(void)
{
    uc_engine *uc;
    uint8_t code[] = {
        0x4e, 0x77, /* rtr */
    };
    uint8_t frame[] = {
        0x00, 0x15,             /* ccr: X, Z, C */
        0x00, 0x00, 0x10, 0x02, /* pc */
    };
    uint32_t sp = code_start + 0x100;
    uint32_t sr = 0x2700;
    uint32_t pc;

    uc_common_setup(&uc, UC_ARCH_M68K, UC_MODE_BIG_ENDIAN, (char *)code,
                    sizeof(code), UC_CPU_M68K_M68000);
    OK(uc_mem_write(uc, sp, frame, sizeof(frame)));
    OK(uc_reg_write(uc, UC_M68K_REG_SR, &sr));
    OK(uc_reg_write(uc, UC_M68K_REG_A7, &sp));

    OK(uc_emu_start(uc, code_start, code_start + sizeof(code), 0, 0));
    OK(uc_reg_read(uc, UC_M68K_REG_PC, &pc));
    OK(uc_reg_read(uc, UC_M68K_REG_A7, &sp));
    OK(uc_reg_read(uc, UC_M68K_REG_SR, &sr));

    TEST_CHECK(pc == (uint32_t)(code_start + sizeof(code)));
    TEST_CHECK(sp == (uint32_t)(code_start + 0x100 + sizeof(frame)));
    TEST_CHECK(sr == 0x2715);

    OK(uc_close(uc));
}

static void test_m68010_move_from_sr_privileged(void)
{
    uc_engine *uc;
    uint8_t code[] = {
        0x40, 0xc0, /* move.w sr, d0 */
    };
    uint32_t sr = 0;

    uc_common_setup(&uc, UC_ARCH_M68K, UC_MODE_BIG_ENDIAN, (char *)code,
                    sizeof(code), UC_CPU_M68K_M68010);
    OK(uc_reg_write(uc, UC_M68K_REG_SR, &sr));

    uc_assert_err(UC_ERR_EXCEPTION,
                  uc_emu_start(uc, code_start, code_start + sizeof(code),
                               0, 0));

    OK(uc_close(uc));
}

TEST_LIST = {{"test_move_to_sr", test_move_to_sr},
             {"test_sr_contains_flags", test_sr_contains_flags},
             {"test_fetoxm1", test_fetoxm1},
             {"test_coldfire_macsr_to_ccr", test_coldfire_macsr_to_ccr},
             {"test_ftrapcc_false_consumes_immediate",
              test_ftrapcc_false_consumes_immediate},
             {"test_ftrapcc_true_raises", test_ftrapcc_true_raises},
             {"test_trapcc_false_consumes_immediate",
              test_trapcc_false_consumes_immediate},
             {"test_trapcc_true_raises", test_trapcc_true_raises},
             {"test_m68010_rtd", test_m68010_rtd},
             {"test_m68010_supervisor_uses_ssp",
              test_m68010_supervisor_uses_ssp},
             {"test_m68020_supervisor_uses_isp_and_msp",
              test_m68020_supervisor_uses_isp_and_msp},
             {"test_m68060_supervisor_uses_isp_and_msp",
              test_m68060_supervisor_uses_isp_and_msp},
             {"test_m68020_movec_msp_isp", test_m68020_movec_msp_isp},
             {"test_m68010_movec_msp_invalid",
              test_m68010_movec_msp_invalid},
             {"test_m68060_movec_msp_invalid",
              test_m68060_movec_msp_invalid},
             {"test_rtr", test_rtr},
             {"test_m68010_move_from_sr_privileged",
              test_m68010_move_from_sr_privileged},
             {NULL, NULL}};
