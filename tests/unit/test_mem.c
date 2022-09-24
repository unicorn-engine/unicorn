#include "unicorn_test.h"

static void test_map_correct(void)
{
    uc_engine *uc;

    OK(uc_open(UC_ARCH_X86, UC_MODE_64, &uc));
    OK(uc_mem_map(uc, 0x40000, 0x1000 * 16, UC_PROT_ALL)); // [0x40000, 0x50000]
    OK(uc_mem_map(uc, 0x60000, 0x1000 * 16, UC_PROT_ALL)); // [0x60000, 0x70000]
    OK(uc_mem_map(uc, 0x20000, 0x1000 * 16, UC_PROT_ALL)); // [0x20000, 0x30000]
    uc_assert_err(UC_ERR_MAP,
                  uc_mem_map(uc, 0x10000, 0x2000 * 16, UC_PROT_ALL));
    uc_assert_err(UC_ERR_MAP,
                  uc_mem_map(uc, 0x25000, 0x1000 * 16, UC_PROT_ALL));
    uc_assert_err(UC_ERR_MAP,
                  uc_mem_map(uc, 0x35000, 0x1000 * 16, UC_PROT_ALL));
    uc_assert_err(UC_ERR_MAP,
                  uc_mem_map(uc, 0x45000, 0x1000 * 16, UC_PROT_ALL));
    uc_assert_err(UC_ERR_MAP,
                  uc_mem_map(uc, 0x55000, 0x2000 * 16, UC_PROT_ALL));
    OK(uc_mem_map(uc, 0x35000, 0x5000, UC_PROT_ALL));
    OK(uc_mem_map(uc, 0x50000, 0x5000, UC_PROT_ALL));

    OK(uc_close(uc));
}

static void test_map_wrapping(void)
{
    uc_engine *uc;

    OK(uc_open(UC_ARCH_X86, UC_MODE_64, &uc));
    uc_assert_err(UC_ERR_ARG, uc_mem_map(uc, (~0ll - 0x4000) & ~0xfff, 0x8000,
                                         UC_PROT_ALL));

    OK(uc_close(uc));
}

static void test_mem_protect(void)
{
    uc_engine *qc;
    int r_eax = 0x2000;
    int r_esi = 0xdeadbeef;
    uint32_t mem;
    // add [eax + 4], esi
    char code[] = {0x01, 0x70, 0x04};

    OK(uc_open(UC_ARCH_X86, UC_MODE_32, &qc));
    OK(uc_reg_write(qc, UC_X86_REG_EAX, &r_eax));
    OK(uc_reg_write(qc, UC_X86_REG_ESI, &r_esi));
    OK(uc_mem_map(qc, 0x1000, 0x1000, UC_PROT_READ | UC_PROT_EXEC));
    OK(uc_mem_map(qc, 0x2000, 0x1000, UC_PROT_READ));
    OK(uc_mem_protect(qc, 0x2000, 0x1000, UC_PROT_READ | UC_PROT_WRITE));
    OK(uc_mem_write(qc, 0x1000, code, sizeof(code)));

    OK(uc_emu_start(qc, 0x1000, 0x1000 + sizeof(code) - 1, 0, 1));
    OK(uc_mem_read(qc, 0x2000 + 4, &mem, 4));

    TEST_CHECK(mem == 0xdeadbeef);

    OK(uc_close(qc));
}

static void test_splitting_mem_unmap(void)
{
    uc_engine *uc;

    OK(uc_open(UC_ARCH_X86, UC_MODE_32, &uc));

    OK(uc_mem_map(uc, 0x20000, 0x1000, UC_PROT_NONE));
    OK(uc_mem_map(uc, 0x21000, 0x2000, UC_PROT_NONE));

    OK(uc_mem_unmap(uc, 0x21000, 0x1000));

    OK(uc_close(uc));
}

static uint64_t test_splitting_mmio_unmap_read_callback(uc_engine *uc,
                                                        uint64_t offset,
                                                        unsigned size,
                                                        void *user_data)
{
    TEST_CHECK(offset == 4);
    TEST_CHECK(size == 4);

    return 0x19260817;
}

static void test_splitting_mmio_unmap(void)
{
    uc_engine *uc;
    // mov ecx, [0x3004] <-- normal read
    // mov ebx, [0x4004] <-- mmio read
    char code[] = "\x8b\x0d\x04\x30\x00\x00\x8b\x1d\x04\x40\x00\x00";
    int r_ecx, r_ebx;
    int bytes = 0xdeadbeef;

    OK(uc_open(UC_ARCH_X86, UC_MODE_32, &uc));

    OK(uc_mem_map(uc, 0x1000, 0x1000, UC_PROT_ALL));
    OK(uc_mem_write(uc, 0x1000, code, sizeof(code) - 1));

    OK(uc_mmio_map(uc, 0x3000, 0x2000, test_splitting_mmio_unmap_read_callback,
                   NULL, NULL, NULL));

    // Map a ram area instead
    OK(uc_mem_unmap(uc, 0x3000, 0x1000));
    OK(uc_mem_map(uc, 0x3000, 0x1000, UC_PROT_ALL));
    OK(uc_mem_write(uc, 0x3004, &bytes, 4));

    OK(uc_emu_start(uc, 0x1000, 0x1000 + sizeof(code) - 1, 0, 0));

    OK(uc_reg_read(uc, UC_X86_REG_ECX, &r_ecx));
    OK(uc_reg_read(uc, UC_X86_REG_EBX, &r_ebx));

    TEST_CHECK(r_ecx == 0xdeadbeef);
    TEST_CHECK(r_ebx == 0x19260817);

    OK(uc_close(uc));
}

static void test_mem_protect_map_ptr(void)
{
    uc_engine *uc;
    uint64_t val = 0x114514;
    uint8_t *data1 = NULL;
    uint8_t *data2 = NULL;
    uint64_t mem;

    data1 = calloc(sizeof(*data1), 0x4000);
    data2 = calloc(sizeof(*data2), 0x2000);

    OK(uc_open(UC_ARCH_X86, UC_MODE_64, &uc));

    OK(uc_mem_map_ptr(uc, 0x4000, 0x4000, UC_PROT_ALL, data1));
    OK(uc_mem_unmap(uc, 0x6000, 0x2000));
    OK(uc_mem_map_ptr(uc, 0x6000, 0x2000, UC_PROT_ALL, data2));

    OK(uc_mem_write(uc, 0x6004, &val, 8));
    OK(uc_mem_protect(uc, 0x6000, 0x1000, UC_PROT_READ));
    OK(uc_mem_read(uc, 0x6004, (void *)&mem, 8));

    TEST_CHECK(val == mem);

    OK(uc_close(uc));
}

static void test_map_at_the_end(void)
{
    uc_engine *uc;
    uint8_t mem[0x1000];

    memset(mem, 0xff, 0x100);

    OK(uc_open(UC_ARCH_X86, UC_MODE_64, &uc));

    OK(uc_mem_map(uc, 0xfffffffffffff000, 0x1000, UC_PROT_ALL));
    OK(uc_mem_write(uc, 0xfffffffffffff000, mem, sizeof(mem)));

    uc_assert_err(UC_ERR_WRITE_UNMAPPED,
                  uc_mem_write(uc, 0xffffffffffffff00, mem, sizeof(mem)));
    uc_assert_err(UC_ERR_WRITE_UNMAPPED, uc_mem_write(uc, 0, mem, sizeof(mem)));

    OK(uc_close(uc));
}

static void test_map_wrap(void)
{
    uc_engine *uc;

    OK(uc_open(UC_ARCH_X86, UC_MODE_64, &uc));

    uc_assert_err(UC_ERR_ARG,
                  uc_mem_map(uc, 0xfffffffffffff000, 0x2000, UC_PROT_ALL));

    OK(uc_close(uc));
}

static void test_map_big_memory(void)
{
    uc_engine *uc;

    OK(uc_open(UC_ARCH_X86, UC_MODE_64, &uc));

#if defined(_WIN32) || defined(__WIN32__) || defined(__WINDOWS__)
    uint64_t requested_size = 0xfffffffffffff000;  // assume 4K page size
#else
    long ps = sysconf(_SC_PAGESIZE);
    uint64_t requested_size = (uint64_t)(-ps);
#endif

    uc_assert_err(UC_ERR_NOMEM,
                  uc_mem_map(uc, 0x0, requested_size, UC_PROT_ALL));

    OK(uc_close(uc));
}

static void test_mem_protect_remove_exec_callback(uc_engine *uc, uint64_t addr,
                                                  size_t size, void *data)
{
    uint64_t *p = (uint64_t *)data;
    (*p)++;

    OK(uc_mem_protect(uc, 0x2000, 0x1000, UC_PROT_READ));
}

static void test_mem_protect_remove_exec(void)
{
    uc_engine *uc;
    char code[] = "\x90\xeb\x00\x90";
    uc_hook hk;
    uint64_t called_count = 0;

    OK(uc_open(UC_ARCH_X86, UC_MODE_64, &uc));
    OK(uc_mem_map(uc, 0x1000, 0x1000, UC_PROT_ALL));
    OK(uc_mem_map(uc, 0x2000, 0x1000, UC_PROT_ALL));

    OK(uc_mem_write(uc, 0x1000, code, sizeof(code) - 1));
    OK(uc_hook_add(uc, &hk, UC_HOOK_BLOCK,
                   test_mem_protect_remove_exec_callback, (void *)&called_count,
                   1, 0));

    OK(uc_emu_start(uc, 0x1000, 0x1000 + sizeof(code) - 1, 0, 0));

    TEST_CHECK(called_count == 2);

    OK(uc_close(uc));
}

static uint64_t test_mem_protect_mmio_read_cb(struct uc_struct *uc,
                                              uint64_t addr, unsigned size,
                                              void *user_data)
{
    TEST_CHECK(addr == 0x20); // note, it's not 0x1020

    *(uint64_t *)user_data = *(uint64_t *)user_data + 1;
    return 0x114514;
}

static void test_mem_protect_mmio_write_cb(struct uc_struct *uc, uint64_t addr,
                                           unsigned size, uint64_t data,
                                           void *user_data)
{
    TEST_CHECK(false);
    return;
}

static void test_mem_protect_mmio(void)
{
    uc_engine *uc;
    // mov eax, [0x2020]; mov [0x2020], eax
    char code[] = "\xa1\x20\x20\x00\x00\x00\x00\x00\x00\xa3\x20\x20\x00\x00\x00"
                  "\x00\x00\x00";
    uint64_t called = 0;
    uint64_t r_eax;

    OK(uc_open(UC_ARCH_X86, UC_MODE_64, &uc));
    OK(uc_mem_map(uc, 0x8000, 0x1000, UC_PROT_ALL));
    OK(uc_mem_write(uc, 0x8000, code, sizeof(code) - 1));

    OK(uc_mmio_map(uc, 0x1000, 0x3000, test_mem_protect_mmio_read_cb,
                   (void *)&called, test_mem_protect_mmio_write_cb,
                   (void *)&called));
    OK(uc_mem_protect(uc, 0x2000, 0x1000, UC_PROT_READ));

    uc_assert_err(UC_ERR_WRITE_PROT,
                  uc_emu_start(uc, 0x8000, 0x8000 + sizeof(code) - 1, 0, 0));
    OK(uc_reg_read(uc, UC_X86_REG_RAX, &r_eax));

    TEST_CHECK(called == 1);
    TEST_CHECK(r_eax == 0x114514);

    OK(uc_close(uc));
}

TEST_LIST = {{"test_map_correct", test_map_correct},
             {"test_map_wrapping", test_map_wrapping},
             {"test_mem_protect", test_mem_protect},
             {"test_splitting_mem_unmap", test_splitting_mem_unmap},
             {"test_splitting_mmio_unmap", test_splitting_mmio_unmap},
             {"test_mem_protect_map_ptr", test_mem_protect_map_ptr},
             {"test_map_at_the_end", test_map_at_the_end},
             {"test_map_wrap", test_map_wrap},
             {"test_map_big_memory", test_map_big_memory},
             {"test_mem_protect_remove_exec", test_mem_protect_remove_exec},
             {"test_mem_protect_mmio", test_mem_protect_mmio},
             {NULL, NULL}};
