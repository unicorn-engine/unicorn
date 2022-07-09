#include "unicorn_test.h"
#include <time.h>
#include <string.h>

// We have to copy this for Android.
#ifdef _WIN32

#include "windows.h"

#define NANOSECONDS_PER_SECOND 1000000000LL

static inline uint64_t muldiv64(uint64_t a, uint32_t b, uint32_t c)
{
    union {
        uint64_t ll;
        struct {
            uint32_t low, high;
        } l;
    } u, res;
    uint64_t rl, rh;

    u.ll = a;
    rl = (uint64_t)u.l.low * (uint64_t)b;
    rh = (uint64_t)u.l.high * (uint64_t)b;
    rh += (rl >> 32);
    res.l.high = rh / c;
    res.l.low = (((rh % c) << 32) + (rl & 0xffffffff)) / c;
    return res.ll;
}

static int64_t get_freq(void)
{
    LARGE_INTEGER freq;
    int ret = QueryPerformanceFrequency(&freq);
    if (ret == 0) {
        fprintf(stderr, "Could not calibrate ticks\n");
        exit(1);
    }
    return freq.QuadPart;
}

static inline int64_t get_clock_realtime(void)
{
    LARGE_INTEGER ti;
    QueryPerformanceCounter(&ti);
    return muldiv64(ti.QuadPart, NANOSECONDS_PER_SECOND, get_freq());
}

#else

#include <sys/time.h>
#include "sys/mman.h"

/* get host real time in nanosecond */
static inline int64_t get_clock_realtime(void)
{
    struct timeval tv;

    gettimeofday(&tv, NULL);
    return tv.tv_sec * 1000000000LL + (tv.tv_usec * 1000);
}

#endif

const uint64_t code_start = 0x1000;
const uint64_t code_len = 0x4000;

static void uc_common_setup(uc_engine **uc, uc_arch arch, uc_mode mode,
                            const char *code, uint64_t size)
{
    OK(uc_open(arch, mode, uc));
    OK(uc_mem_map(*uc, code_start, code_len, UC_PROT_ALL));
    OK(uc_mem_write(*uc, code_start, code, size));
}

#define GEN_SIMPLE_READ_TEST(field, ctl_type, arg_type, expected)              \
    static void test_uc_ctl_##field(void)                                      \
    {                                                                          \
        uc_engine *uc;                                                         \
        arg_type arg;                                                          \
        OK(uc_open(UC_ARCH_X86, UC_MODE_32, &uc));                             \
        OK(uc_ctl(uc, UC_CTL_READ(ctl_type, 1), &arg));                        \
        TEST_CHECK(arg == expected);                                           \
        OK(uc_close(uc));                                                      \
    }

GEN_SIMPLE_READ_TEST(mode, UC_CTL_UC_MODE, int, 4)
GEN_SIMPLE_READ_TEST(arch, UC_CTL_UC_ARCH, int, 4)
GEN_SIMPLE_READ_TEST(page_size, UC_CTL_UC_PAGE_SIZE, uint32_t, 4096)
GEN_SIMPLE_READ_TEST(time_out, UC_CTL_UC_TIMEOUT, uint64_t, 0)

static void test_uc_ctl_exits(void)
{
    uc_engine *uc;
    //   cmp eax, 0;
    //   jg lb;
    //   inc eax;
    //   nop;       <---- exit1
    // lb:
    //   inc ebx;
    //   nop;      <---- exit2
    char code[] = "\x83\xf8\x00\x7f\x02\x40\x90\x43\x90";
    int r_eax;
    int r_ebx;
    uint64_t exits[] = {code_start + 6, code_start + 8};

    uc_common_setup(&uc, UC_ARCH_X86, UC_MODE_32, code, sizeof(code) - 1);
    OK(uc_ctl_exits_enable(uc));
    OK(uc_ctl_set_exits(uc, exits, 2));
    r_eax = 0;
    r_ebx = 0;
    OK(uc_reg_write(uc, UC_X86_REG_EAX, &r_eax));
    OK(uc_reg_write(uc, UC_X86_REG_EAX, &r_ebx));

    // Run two times.
    OK(uc_emu_start(uc, code_start, 0, 0, 0));
    OK(uc_emu_start(uc, code_start, 0, 0, 0));

    OK(uc_reg_read(uc, UC_X86_REG_EAX, &r_eax));
    OK(uc_reg_read(uc, UC_X86_REG_EAX, &r_ebx));

    TEST_CHECK(r_eax == 1);
    TEST_CHECK(r_ebx == 1);

    OK(uc_close(uc));
}

double time_emulation(uc_engine *uc, uint64_t start, uint64_t end)
{
    int64_t t1, t2;

    t1 = get_clock_realtime();

    OK(uc_emu_start(uc, start, end, 0, 0));

    t2 = get_clock_realtime();

    return t2 - t1;
}

#define TB_COUNT (8)
#define TCG_MAX_INSNS (512) // from tcg.h
#define CODE_LEN TB_COUNT *TCG_MAX_INSNS

static void test_uc_ctl_tb_cache(void)
{
    uc_engine *uc;
    char code[CODE_LEN + 1];
    double standard, cached, evicted;

    memset(code, 0x90, CODE_LEN);
    code[CODE_LEN] = 0;

    uc_common_setup(&uc, UC_ARCH_X86, UC_MODE_32, code, sizeof(code) - 1);

    standard = time_emulation(uc, code_start, code_start + sizeof(code) - 1);

    for (int i = 0; i < TB_COUNT; i++) {
        OK(uc_ctl_request_cache(uc, code_start + i * TCG_MAX_INSNS, NULL));
    }

    cached = time_emulation(uc, code_start, code_start + sizeof(code) - 1);

    for (int i = 0; i < TB_COUNT; i++) {
        OK(uc_ctl_remove_cache(uc, code_start + i * TCG_MAX_INSNS,
                               code_start + i * TCG_MAX_INSNS + 1));
    }
    evicted = time_emulation(uc, code_start, code_start + sizeof(code) - 1);

    // In fact, evicted is also slightly faster than standard but we don't do
    // this guarantee.
    TEST_CHECK(cached < standard);
    TEST_CHECK(evicted > cached);

    OK(uc_close(uc));
}

static void test_uc_ctl_change_page_size(void)
{
    uc_engine *uc;
    uc_engine *uc2;

    OK(uc_open(UC_ARCH_ARM, UC_MODE_ARM, &uc));
    OK(uc_open(UC_ARCH_ARM, UC_MODE_ARM, &uc2));

    OK(uc_ctl_set_page_size(uc, 4096));

    OK(uc_mem_map(uc2, 1 << 10, 1 << 10, UC_PROT_ALL));
    uc_assert_err(UC_ERR_ARG, uc_mem_map(uc, 1 << 10, 1 << 10, UC_PROT_ALL));

    OK(uc_close(uc));
    OK(uc_close(uc2));
}

// Copy from test_arm.c but with new API.
static void test_uc_ctl_arm_cpu(void)
{
    uc_engine *uc;
    int r_control, r_msp, r_psp;

    OK(uc_open(UC_ARCH_ARM, UC_MODE_THUMB, &uc));

    OK(uc_ctl_set_cpu_model(uc, UC_CPU_ARM_CORTEX_M7));

    r_control = 0; // Make sure we are using MSP.
    OK(uc_reg_write(uc, UC_ARM_REG_CONTROL, &r_control));

    r_msp = 0x1000;
    OK(uc_reg_write(uc, UC_ARM_REG_R13, &r_msp));

    r_control = 0b10; // Make the switch.
    OK(uc_reg_write(uc, UC_ARM_REG_CONTROL, &r_control));

    OK(uc_reg_read(uc, UC_ARM_REG_R13, &r_psp));
    TEST_CHECK(r_psp != r_msp);

    r_psp = 0x2000;
    OK(uc_reg_write(uc, UC_ARM_REG_R13, &r_psp));

    r_control = 0; // Switch again
    OK(uc_reg_write(uc, UC_ARM_REG_CONTROL, &r_control));

    OK(uc_reg_read(uc, UC_ARM_REG_R13, &r_msp));
    TEST_CHECK(r_psp != r_msp);
    TEST_CHECK(r_msp == 0x1000);

    OK(uc_close(uc));
}

static void test_uc_hook_cached_cb(uc_engine *uc, uint64_t addr, size_t size,
                                   void *user_data)
{
    // Don't add any TEST_CHECK here since we can't refer to the global variable
    // here.
    uint64_t *p = (uint64_t *)user_data;
    (*p)++;
    return;
}

static void test_uc_hook_cached_uaf(void)
{
    uc_engine *uc;
    // "INC ecx; DEC edx; jmp t; t: nop"
    char code[] = "\x41\x4a\xeb\x00\x90";
    uc_hook h;
    uint64_t count = 0;
#ifndef _WIN32
    void *callback = mmap(NULL, 4096, PROT_READ | PROT_WRITE | PROT_EXEC,
                          MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
#else
    void *callback = VirtualAlloc(NULL, 4096, MEM_RESERVE | MEM_COMMIT,
                                  PAGE_EXECUTE_READWRITE);
#endif

    memcpy(callback, (void *)test_uc_hook_cached_cb, 4096);

    uc_common_setup(&uc, UC_ARCH_X86, UC_MODE_32, code, sizeof(code) - 1);

    OK(uc_hook_add(uc, &h, UC_HOOK_CODE, (void *)callback, (void *)&count, 1,
                   0));

    OK(uc_emu_start(uc, code_start, code_start + sizeof(code) - 1, 0, 0));

    // Move the hook to the deleted hooks list.
    OK(uc_hook_del(uc, h));

    // This will clear deleted hooks and SHOULD clear cache.
    OK(uc_emu_start(uc, code_start, code_start + sizeof(code) - 1, 0, 0));

    memset(callback, 0, 4096);

    // Now hooks are deleted and thus this will trigger a UAF
    OK(uc_emu_start(uc, code_start, code_start + sizeof(code) - 1, 0, 0));

    TEST_CHECK(count == 4);

    OK(uc_close(uc));

#ifndef _WIN32
    munmap(callback, 4096);
#else
    VirtualFree(callback, 0, MEM_RELEASE);
#endif
}

TEST_LIST = {{"test_uc_ctl_mode", test_uc_ctl_mode},
             {"test_uc_ctl_page_size", test_uc_ctl_page_size},
             {"test_uc_ctl_arch", test_uc_ctl_arch},
             {"test_uc_ctl_time_out", test_uc_ctl_time_out},
             {"test_uc_ctl_exits", test_uc_ctl_exits},
             {"test_uc_ctl_tb_cache", test_uc_ctl_tb_cache},
             {"test_uc_ctl_change_page_size", test_uc_ctl_change_page_size},
             {"test_uc_ctl_arm_cpu", test_uc_ctl_arm_cpu},
             {"test_uc_hook_cached_uaf", test_uc_hook_cached_uaf},
             {NULL, NULL}};