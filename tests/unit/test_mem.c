#include "unicorn_test.h"

#if !(defined(_WIN32) || defined(__WIN32__) || defined(__WINDOWS__))
#include <sys/mman.h>
#endif

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

    TEST_CHECK(LEINT32(mem) == 0xdeadbeef);

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
    int bytes = LEINT32(0xdeadbeef);

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

    free(data2);
    free(data1);
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
    uint64_t requested_size = 0xfffffffffffff000; // assume 4K page size
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

    *(uint64_t *)user_data += 1;
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

static void test_snapshot(void)
{
    uc_engine *uc;
    uc_context *c0, *c1;
    uint32_t mem;
    uint8_t code_data;
    // mov eax, [0x2020]; inc eax; mov [0x2020], eax
    char code[] = "\xa1\x20\x20\x00\x00\x00\x00\x00\x00\xff\xc0\xa3\x20\x20\x00"
                  "\x00\x00\x00\x00\x00";

    OK(uc_open(UC_ARCH_X86, UC_MODE_64, &uc));
    OK(uc_context_alloc(uc, &c0));
    OK(uc_context_alloc(uc, &c1));
    OK(uc_ctl_context_mode(uc, UC_CTL_CONTEXT_MEMORY));
    OK(uc_mem_map(uc, 0x1000, 0x1000, UC_PROT_ALL));
    OK(uc_mem_write(uc, 0x1000, code, sizeof(code) - 1));

    OK(uc_mem_map(uc, 0x2000, 0x1000, UC_PROT_ALL));
    OK(uc_context_save(uc, c0));

    OK(uc_emu_start(uc, 0x1000, 0x1000 + sizeof(code) - 1, 0, 0));
    OK(uc_mem_read(uc, 0x2020, &mem, sizeof(mem)));
    TEST_CHECK(LEINT32(mem) == 1);
    OK(uc_context_save(uc, c1));
    OK(uc_emu_start(uc, 0x1000, 0x1000 + sizeof(code) - 1, 0, 0));
    OK(uc_mem_read(uc, 0x2020, &mem, sizeof(mem)));
    TEST_CHECK(LEINT32(mem) == 2);
    OK(uc_context_restore(uc, c1));

    OK(uc_mem_read(uc, 0x2020, &mem, sizeof(mem)));
    TEST_CHECK(LEINT32(mem) == 1);
    OK(uc_context_restore(uc, c0));
    OK(uc_mem_read(uc, 0x2020, &mem, sizeof(mem)));
    TEST_CHECK(LEINT32(mem) == 0);

    OK(uc_mem_read(uc, 0x1000, &code_data, sizeof(code_data)));
    TEST_CHECK(code_data == 0xa1);

    OK(uc_context_free(c0));
    OK(uc_context_free(c1));
    OK(uc_close(uc));
}

static bool test_snapshot_with_vtlb_callback(uc_engine *uc, uint64_t addr,
                                             uc_mem_type type,
                                             uc_tlb_entry *result,
                                             void *user_data)
{
    result->paddr = addr - 0x400000000;
    result->perms = UC_PROT_ALL;
    return true;
}

static void test_snapshot_with_vtlb(void)
{
    uc_engine *uc;
    uc_context *c0, *c1;
    uint32_t mem;
    uc_hook hook;

    // mov eax, [0x2020]; inc eax; mov [0x2020], eax
    char code[] = "\xA1\x20\x20\x00\x00\x04\x00\x00\x00\xFF\xC0\xA3\x20\x20\x00"
                  "\x00\x04\x00\x00\x00";

    OK(uc_open(UC_ARCH_X86, UC_MODE_64, &uc));

    // Allocate contexts
    OK(uc_context_alloc(uc, &c0));
    OK(uc_context_alloc(uc, &c1));
    OK(uc_ctl_context_mode(uc, UC_CTL_CONTEXT_MEMORY));

    OK(uc_ctl_tlb_mode(uc, UC_TLB_VIRTUAL));
    OK(uc_hook_add(uc, &hook, UC_HOOK_TLB_FILL,
                   test_snapshot_with_vtlb_callback, NULL, 1, 0));

    // Map physical memory
    OK(uc_mem_map(uc, 0x1000, 0x1000, UC_PROT_EXEC | UC_PROT_READ));
    OK(uc_mem_write(uc, 0x1000, code, sizeof(code) - 1));
    OK(uc_mem_map(uc, 0x2000, 0x1000, UC_PROT_ALL));

    // Initial context save
    OK(uc_context_save(uc, c0));

    OK(uc_emu_start(uc, 0x400000000 + 0x1000,
                    0x400000000 + 0x1000 + sizeof(code) - 1, 0, 0));
    OK(uc_mem_read(uc, 0x2020, &mem, sizeof(mem)));
    TEST_CHECK(LEINT32(mem) == 1);
    OK(uc_context_save(uc, c1));
    OK(uc_emu_start(uc, 0x400000000 + 0x1000,
                    0x400000000 + 0x1000 + sizeof(code) - 1, 0, 0));
    OK(uc_mem_read(uc, 0x2020, &mem, sizeof(mem)));
    TEST_CHECK(LEINT32(mem) == 2);
    OK(uc_context_restore(uc, c1));
    // TODO check mem
    OK(uc_mem_read(uc, 0x2020, &mem, sizeof(mem)));
    TEST_CHECK(LEINT32(mem) == 1);
    OK(uc_context_restore(uc, c0));
    OK(uc_mem_read(uc, 0x2020, &mem, sizeof(mem)));
    TEST_CHECK(LEINT32(mem) == 0);
    // TODO check mem

    OK(uc_context_free(c0));
    OK(uc_context_free(c1));
    OK(uc_close(uc));
}

static void test_context_snapshot(void)
{
    uc_engine *uc;
    uc_context *ctx;
    uint64_t baseaddr = 0xfffff1000;
    uint64_t offset = 0x10;
    uint64_t tmp = 1;
    OK(uc_open(UC_ARCH_X86, UC_MODE_64, &uc));
    OK(uc_ctl_context_mode(uc, UC_CTL_CONTEXT_MEMORY | UC_CTL_CONTEXT_CPU));
    OK(uc_mem_map(uc, baseaddr, 0x1000, UC_PROT_ALL));
    OK(uc_context_alloc(uc, &ctx));
    OK(uc_context_save(uc, ctx));

    OK(uc_mem_write(uc, baseaddr + offset, &tmp, sizeof(tmp)));
    OK(uc_mem_read(uc, baseaddr + offset, &tmp, sizeof(tmp)));
    TEST_CHECK(tmp == 1);
    OK(uc_context_restore(uc, ctx));
    OK(uc_mem_read(uc, baseaddr + offset, &tmp, sizeof(tmp)));
    TEST_CHECK(tmp == 0);

    tmp = 2;
    OK(uc_mem_write(uc, baseaddr + offset, &tmp, sizeof(tmp)));
    OK(uc_mem_read(uc, baseaddr + offset, &tmp, sizeof(tmp)));
    TEST_CHECK(tmp == 2);
    OK(uc_context_restore(uc, ctx));
    OK(uc_mem_read(uc, baseaddr + offset, &tmp, sizeof(tmp)));
    TEST_CHECK(tmp == 0);

    OK(uc_context_free(ctx));
    OK(uc_close(uc));
}

static void test_snapshot_unmap(void)
{
    uc_engine *uc;
    uc_context *ctx;
    uint64_t tmp;

    OK(uc_open(UC_ARCH_X86, UC_MODE_64, &uc));
    OK(uc_ctl_context_mode(uc, UC_CTL_CONTEXT_MEMORY | UC_CTL_CONTEXT_CPU));
    OK(uc_mem_map(uc, 0x1000, 0x2000, UC_PROT_ALL));

    tmp = 1;
    OK(uc_mem_write(uc, 0x1000, &tmp, sizeof(tmp)));
    tmp = 2;
    OK(uc_mem_write(uc, 0x2000, &tmp, sizeof(tmp)));

    OK(uc_context_alloc(uc, &ctx));
    OK(uc_context_save(uc, ctx));

    uc_assert_err(UC_ERR_ARG, uc_mem_unmap(uc, 0x1000, 0x1000));
    OK(uc_mem_unmap(uc, 0x1000, 0x2000));
    uc_assert_err(UC_ERR_READ_UNMAPPED,
                  uc_mem_read(uc, 0x1000, &tmp, sizeof(tmp)));
    uc_assert_err(UC_ERR_READ_UNMAPPED,
                  uc_mem_read(uc, 0x2000, &tmp, sizeof(tmp)));

    OK(uc_context_restore(uc, ctx));
    OK(uc_mem_read(uc, 0x1000, &tmp, sizeof(tmp)));
    TEST_CHECK(tmp == 1);
    OK(uc_mem_read(uc, 0x2000, &tmp, sizeof(tmp)));
    TEST_CHECK(tmp == 2);

    OK(uc_context_free(ctx));
    OK(uc_close(uc));
}

static void parts_increment(size_t idx, char parts[3])
{
    if (idx && idx % 3 == 0) {
        if (++parts[2] > '9') {
            parts[2] = '0';
            if (++parts[1] > 'z') {
                parts[1] = 'a';
                if (++parts[0] > 'Z')
                    parts[0] = 'A';
            }
        }
    }
}

// Create a pattern string. It works the same as
// https://github.com/rapid7/metasploit-framework/blob/master/tools/exploit/pattern_create.rb
static void pattern_create(char *buf, size_t len)
{
    char parts[] = {'A', 'a', '0'};
    size_t i;

    for (i = 0; i < len; i++) {
        buf[i] = parts[i % 3];
        parts_increment(i, parts);
    }
}

static bool pattern_verify(const char *buf, size_t len)
{
    char parts[] = {'A', 'a', '0'};
    size_t i;

    for (i = 0; i < len; i++) {
        if (buf[i] != parts[i % 3])
            return false;
        parts_increment(i, parts);
    }

    return true;
}

// Test for reading and writing memory block that are bigger than INT_MAX.
static void test_mem_read_and_write_large_memory_block(void)
{
    uc_engine *uc;
    uint64_t mem_addr = 0x1000000;
    uint64_t mem_size = 0x9f000000;
    char *pmem = NULL;

    if (sizeof(void *) < 8) {
        // Don't perform the test on a 32-bit platforms since we may not have
        // enough memory space.
        return;
    }
    // Android CI/CD services do not have enough memory capacity for this
    // test to work. Executing it will result in a permanent loop with the
    // low memory killer daemon. 
#ifdef __ANDROID__
    return;
#endif 

    OK(uc_open(UC_ARCH_ARM64, UC_MODE_ARM, &uc));
    OK(uc_mem_map(uc, mem_addr, mem_size, UC_PROT_ALL));

    pmem = malloc(mem_size);
    if (TEST_CHECK(pmem != NULL)) {
        pattern_create(pmem, mem_size);

        OK(uc_mem_write(uc, mem_addr, pmem, mem_size));
        memset(pmem, 'a', mem_size);
        OK(uc_mem_read(uc, mem_addr, pmem, mem_size));
        TEST_CHECK(pattern_verify(pmem, mem_size));
        free(pmem);
    }

    OK(uc_mem_unmap(uc, mem_addr, mem_size));
    OK(uc_close(uc));
}

static bool test_v2p_tlb_fill(uc_engine *uc, uint64_t addr, uc_mem_type type,
                               uc_tlb_entry *result, void *user_data)               
{
    if (type != UC_MEM_READ)
        return false;
    result->paddr = addr;
    result->perms = UC_PROT_READ;
    return true;
}

static void test_virtual_to_physical(void)
{
    uc_engine *uc;
    uc_hook hook;
    uint64_t res;

    OK(uc_open(UC_ARCH_X86, UC_MODE_64, &uc));
    OK(uc_ctl_tlb_mode(uc, UC_TLB_VIRTUAL));
    OK(uc_hook_add(uc, &hook, UC_HOOK_TLB_FILL, test_v2p_tlb_fill, NULL, 1, 0));

    OK(uc_vmem_translate(uc, 0x1000, UC_PROT_READ, &res));
    uc_assert_err(UC_ERR_WRITE_PROT,
                  uc_vmem_translate(uc, 0x1000, UC_PROT_WRITE, &res));
    OK(uc_close(uc));
}

static bool test_virtual_write_tlb_fill(uc_engine *uc, uint64_t addr, uc_mem_type type,
                                        uc_tlb_entry *result, void *user_data)
{
    if (addr < 0x1000)
        return false;
    result->paddr = addr - 0x1000;
    result->perms = UC_PROT_ALL;
    return true;
}

static void test_virtual_write(void)
{
    uc_engine *uc;
    uc_hook hook;
    uint64_t rax = 21;
    uint64_t res = 0;
    /*
     * mov rax, [0x2000]
     */
    char code[] = { 0x48, 0x8B, 0x04, 0x25, 0x00, 0x20, 0x00, 0x00 };

    OK(uc_open(UC_ARCH_X86, UC_MODE_64, &uc));
    OK(uc_ctl_tlb_mode(uc, UC_TLB_VIRTUAL));
    OK(uc_hook_add(uc, &hook, UC_HOOK_TLB_FILL, test_virtual_write_tlb_fill, NULL, 1, 0));
    OK(uc_mem_map(uc, 0x0, 0x2000, UC_PROT_ALL));

    OK(uc_vmem_write(uc, 0x1000, UC_PROT_EXEC, code, sizeof(code)));
    OK(uc_vmem_write(uc, 0x2000, UC_PROT_READ, &rax, sizeof(rax)));

    OK(uc_emu_start(uc, 0x1000, 0x1000 + sizeof(code), 0, 1));
    OK(uc_reg_read(uc, UC_X86_REG_RAX, &res));
    TEST_CHECK(rax == res);

    OK(uc_close(uc));
}

// Regression test for issue #2321. With two legal mappings (top page and
// page 0), an address+size that wraps used to let check_mem_area() walk
// from the top of the address space back to 0 and treat the wrapping
// range as fully mapped. uc_mem_read then memcpy'd 0x2000 bytes into a
// 0x1000 buffer; uc_mem_unmap silently dropped both regions. After the
// fix, check_mem_area() rejects the wrap up front so the four entry
// points fall back to their existing not-mapped error codes.
static void test_mem_addr_size_wraparound(void)
{
    uc_engine *uc;
    uint8_t buf[0x1000];

    OK(uc_open(UC_ARCH_X86, UC_MODE_64, &uc));
    OK(uc_mem_map(uc, 0,                     0x1000, UC_PROT_ALL));
    OK(uc_mem_map(uc, 0xFFFFFFFFFFFFF000ULL, 0x1000, UC_PROT_ALL));

    uc_assert_err(UC_ERR_READ_UNMAPPED,
        uc_mem_read(uc, 0xFFFFFFFFFFFFF000ULL, buf, 0x2000));
    uc_assert_err(UC_ERR_WRITE_UNMAPPED,
        uc_mem_write(uc, 0xFFFFFFFFFFFFF000ULL, buf, 0x2000));
    uc_assert_err(UC_ERR_NOMEM,
        uc_mem_unmap(uc, 0xFFFFFFFFFFFFF000ULL, 0x2000));
    uc_assert_err(UC_ERR_NOMEM,
        uc_mem_protect(uc, 0xFFFFFFFFFFFFF000ULL, 0x2000, UC_PROT_READ));

    // The non-wrapping single-page case must still work for both regions.
    OK(uc_mem_read(uc, 0xFFFFFFFFFFFFF000ULL, buf, 0x1000));
    OK(uc_mem_read(uc, 0,                     buf, 0x1000));

    OK(uc_close(uc));
}

/* SMC test: verifies that a store which overwrites code on
 * the same page invalidates any cached TBs translated from that
 * page, so subsequent execution sees the new instructions.
 */
static void test_smc(void)
{
    uc_engine *uc;
    uint64_t r_rax;
    uint64_t r_rsp;

    char code[] = (                    // 00: do_inc_dec:
        "\x48\xff\xc0"                 // 00:    inc %rax
        "\xc3"                         // 03:    ret
        "\xe8\xf7\xff\xff\xff"         // 04: call do_inc_dec
        "\xc6\x05\xf2\xff\xff\xff\xc8" // 09: movb $0xc8, -0xe(%rip)
        "\xe8\xeb\xff\xff\xff"         // 16: call do_inc_dec
    );

    r_rax = 0x1234;
    r_rsp = 0x5000;
    OK(uc_open(UC_ARCH_X86, UC_MODE_64, &uc));
    OK(uc_mem_map  (uc, 0x0,    0x1000, UC_PROT_ALL));                // text
    OK(uc_mem_map  (uc, 0x4000, 0x1000, UC_PROT_READ|UC_PROT_WRITE)); // stack
    OK(uc_mem_write(uc, 0x0,    code,   sizeof(code)-1));
    OK(uc_reg_write(uc, UC_X86_REG_RAX, &r_rax));
    OK(uc_reg_write(uc, UC_X86_REG_RSP, &r_rsp));
    OK(uc_emu_start(uc, 0x4, sizeof(code)-1, 0, 0));

    OK(uc_reg_read(uc, UC_X86_REG_RAX, &r_rax));
    OK(uc_mem_read(uc, 0x0, code, sizeof(code)-1));
    TEST_CHECK(r_rax == 0x1234);
    TEST_CHECK((code[2] & 0xFF) == 0xC8);

    OK(uc_close(uc));
}

/*
 * Ensures that a code section initially as RW, if marked later as RX
 * still works as expected
 */
static void test_tlbdirty_exec(void)
{
    uc_engine *uc;
    uint32_t eax;

    char code[] = ("\x40"); // inc eax
    eax = 41;
    OK(uc_open(UC_ARCH_X86, UC_MODE_32, &uc));
    OK(uc_reg_write  (uc, UC_X86_REG_EAX, &eax));
    OK(uc_mem_map    (uc, 0x0, 0x1000, UC_PROT_READ|UC_PROT_WRITE));
    OK(uc_mem_write  (uc, 0x0, code,   sizeof(code)-1));
    OK(uc_mem_protect(uc, 0x0, 0x1000, UC_PROT_READ|UC_PROT_EXEC));
    OK(uc_emu_start  (uc, 0x0, sizeof(code)-1, 0, 0));

    OK(uc_reg_read(uc, UC_X86_REG_EAX, &eax));
    TEST_CHECK(eax == 42);

    OK(uc_close(uc));
}

/*
 * Memory protection hooks, see
 * https://github.com/unicorn-engine/unicorn/issues/2368
 *
 * Returning true from a UC_HOOK_MEM_*_PROT callback lets the access go ahead,
 * whether or not the callback changed the page permissions. Returning false
 * stops emulation with the matching UC_ERR_*_PROT error.
 */
#define PROT_CODE_ADDR 0x1000
#define PROT_DATA_ADDR 0x2000

typedef struct {
    int count;
    uc_mem_type type;
    uint64_t address;
    int size;
    int64_t value;
    // When non-zero, the callback applies these permissions to the page
    uint32_t new_perms;
    // When true, the callback unmaps the page
    bool unmap;
    bool ret;
    // When non-zero, the callback returns false for addresses from here on
    uint64_t deny_from;
} mem_prot_hook_ctx;

static bool test_mem_prot_hook_cb(uc_engine *uc, uc_mem_type type,
                                  uint64_t address, int size, int64_t value,
                                  void *user_data)
{
    mem_prot_hook_ctx *ctx = (mem_prot_hook_ctx *)user_data;

    // Fetches report once per byte, keep the first fault
    if (ctx->count++ == 0) {
        ctx->type = type;
        ctx->address = address;
        ctx->size = size;
        ctx->value = value;
    }
    if (ctx->unmap) {
        OK(uc_mem_unmap(uc, address & ~0xfffULL, 0x1000));
    } else if (ctx->new_perms) {
        OK(uc_mem_protect(uc, address & ~0xfffULL, 0x1000, ctx->new_perms));
    }
    if (ctx->deny_from && address >= ctx->deny_from) {
        return false;
    }
    return ctx->ret;
}

// Runs x86-32 code at PROT_CODE_ADDR with a data page at PROT_DATA_ADDR
// mapped with data_perms and filled with data. The engine is returned open
// so the caller can inspect it.
static uc_err test_mem_prot_run(uc_engine **uc, const char *code,
                                size_t code_len, uint32_t data_perms,
                                const char *data, size_t data_len,
                                uint64_t until, int hook_type,
                                mem_prot_hook_ctx *ctx)
{
    uc_hook hook;

    OK(uc_open(UC_ARCH_X86, UC_MODE_32, uc));
    OK(uc_mem_map(*uc, PROT_CODE_ADDR, 0x1000, UC_PROT_ALL));
    OK(uc_mem_map(*uc, PROT_DATA_ADDR, 0x1000, data_perms));
    OK(uc_mem_write(*uc, PROT_CODE_ADDR, code, code_len));
    if (data_len) {
        OK(uc_mem_write(*uc, PROT_DATA_ADDR, data, data_len));
    }
    if (hook_type) {
        OK(uc_hook_add(*uc, &hook, hook_type, test_mem_prot_hook_cb, ctx, 1,
                       0));
    }
    return uc_emu_start(*uc, PROT_CODE_ADDR, until, 0, 0);
}

// mov eax, [0x2000]
static const char prot_read_code[] = "\xa1\x00\x20\x00\x00";
// mov dword [0x2000], 0x12345678
static const char prot_write_code[] =
    "\xc7\x05\x00\x20\x00\x00\x78\x56\x34\x12";
// mov eax, 0x2000; jmp eax
static const char prot_fetch_code[] = "\xb8\x00\x20\x00\x00\xff\xe0";
// mov ebx, 0x42
static const char prot_fetch_target[] = "\xbb\x42\x00\x00\x00";
static const char prot_data[] = "\x78\x56\x34\x12";

static void test_mem_read_prot_hook(uint32_t new_perms, bool ret,
                                    uc_err expected_err)
{
    uc_engine *uc;
    mem_prot_hook_ctx ctx = {0};
    uint32_t eax = 0;

    ctx.new_perms = new_perms;
    ctx.ret = ret;
    uc_assert_err(expected_err,
                  test_mem_prot_run(&uc, prot_read_code,
                                    sizeof(prot_read_code) - 1, UC_PROT_NONE,
                                    prot_data, sizeof(prot_data) - 1,
                                    PROT_CODE_ADDR + sizeof(prot_read_code) - 1,
                                    UC_HOOK_MEM_READ_PROT, &ctx));
    TEST_CHECK(ctx.count == 1);
    TEST_CHECK(ctx.type == UC_MEM_READ_PROT);
    TEST_CHECK(ctx.address == PROT_DATA_ADDR);

    OK(uc_reg_read(uc, UC_X86_REG_EAX, &eax));
    TEST_CHECK(eax == (expected_err == UC_ERR_OK ? 0x12345678 : 0));

    OK(uc_close(uc));
}

static void test_mem_write_prot_hook(uint32_t new_perms, bool ret,
                                     uc_err expected_err)
{
    uc_engine *uc;
    mem_prot_hook_ctx ctx = {0};
    uint32_t value = 0;

    ctx.new_perms = new_perms;
    ctx.ret = ret;
    uc_assert_err(expected_err,
                  test_mem_prot_run(
                      &uc, prot_write_code, sizeof(prot_write_code) - 1,
                      UC_PROT_READ, NULL, 0,
                      PROT_CODE_ADDR + sizeof(prot_write_code) - 1,
                      UC_HOOK_MEM_WRITE_PROT, &ctx));
    TEST_CHECK(ctx.count == 1);
    TEST_CHECK(ctx.type == UC_MEM_WRITE_PROT);
    TEST_CHECK(ctx.address == PROT_DATA_ADDR);

    OK(uc_mem_read(uc, PROT_DATA_ADDR, &value, sizeof(value)));
    TEST_CHECK(value == (expected_err == UC_ERR_OK ? 0x12345678 : 0));

    OK(uc_close(uc));
}

static void test_mem_fetch_prot_hook(uint32_t new_perms, bool ret,
                                     uc_err expected_err)
{
    uc_engine *uc;
    mem_prot_hook_ctx ctx = {0};
    uint32_t ebx = 0;

    ctx.new_perms = new_perms;
    ctx.ret = ret;
    uc_assert_err(expected_err,
                  test_mem_prot_run(
                      &uc, prot_fetch_code, sizeof(prot_fetch_code) - 1,
                      UC_PROT_READ, prot_fetch_target,
                      sizeof(prot_fetch_target) - 1,
                      PROT_DATA_ADDR + sizeof(prot_fetch_target) - 1,
                      UC_HOOK_MEM_FETCH_PROT, &ctx));
    // Once the hook made the page executable, later fetches do not call it
    TEST_CHECK(new_perms & UC_PROT_EXEC ? ctx.count == 1 : ctx.count >= 1);
    TEST_CHECK(ctx.type == UC_MEM_FETCH_PROT);
    TEST_CHECK(ctx.address == PROT_DATA_ADDR);

    OK(uc_reg_read(uc, UC_X86_REG_EBX, &ebx));
    TEST_CHECK(ebx == (expected_err == UC_ERR_OK ? 0x42 : 0));

    OK(uc_close(uc));
}

static void test_mem_read_prot_hook_allow(void)
{
    test_mem_read_prot_hook(0, true, UC_ERR_OK);
}

static void test_mem_read_prot_hook_grant(void)
{
    test_mem_read_prot_hook(UC_PROT_READ | UC_PROT_WRITE, true, UC_ERR_OK);
}

static void test_mem_read_prot_hook_deny(void)
{
    test_mem_read_prot_hook(0, false, UC_ERR_READ_PROT);
}

static void test_mem_write_prot_hook_allow(void)
{
    test_mem_write_prot_hook(0, true, UC_ERR_OK);
}

static void test_mem_write_prot_hook_grant(void)
{
    test_mem_write_prot_hook(UC_PROT_READ | UC_PROT_WRITE, true, UC_ERR_OK);
}

static void test_mem_write_prot_hook_deny(void)
{
    test_mem_write_prot_hook(0, false, UC_ERR_WRITE_PROT);
}

static void test_mem_fetch_prot_hook_allow(void)
{
    test_mem_fetch_prot_hook(0, true, UC_ERR_OK);
}

static void test_mem_fetch_prot_hook_grant(void)
{
    test_mem_fetch_prot_hook(UC_PROT_ALL, true, UC_ERR_OK);
}

static void test_mem_fetch_prot_hook_deny(void)
{
    test_mem_fetch_prot_hook(0, false, UC_ERR_FETCH_PROT);
}

// Without a hook, every protection fault stops emulation.
static void test_mem_prot_no_hook(void)
{
    uc_engine *uc;
    uint32_t value = 0;

    uc_assert_err(UC_ERR_READ_PROT,
                  test_mem_prot_run(&uc, prot_read_code,
                                    sizeof(prot_read_code) - 1, UC_PROT_NONE,
                                    prot_data, sizeof(prot_data) - 1,
                                    PROT_CODE_ADDR + sizeof(prot_read_code) - 1,
                                    0, NULL));
    OK(uc_close(uc));

    uc_assert_err(UC_ERR_WRITE_PROT,
                  test_mem_prot_run(
                      &uc, prot_write_code, sizeof(prot_write_code) - 1,
                      UC_PROT_READ, NULL, 0,
                      PROT_CODE_ADDR + sizeof(prot_write_code) - 1, 0, NULL));
    OK(uc_mem_read(uc, PROT_DATA_ADDR, &value, sizeof(value)));
    TEST_CHECK(value == 0);
    OK(uc_close(uc));

    uc_assert_err(UC_ERR_FETCH_PROT,
                  test_mem_prot_run(
                      &uc, prot_fetch_code, sizeof(prot_fetch_code) - 1,
                      UC_PROT_READ, prot_fetch_target,
                      sizeof(prot_fetch_target) - 1,
                      PROT_DATA_ADDR + sizeof(prot_fetch_target) - 1, 0, NULL));
    OK(uc_close(uc));
}

// A write accepted by the hook must drop code translated from the page.
static void test_mem_write_prot_hook_smc(void)
{
    uc_engine *uc;
    uc_hook hook;
    mem_prot_hook_ctx ctx = {0};
    uint32_t eax = 0;

    const char code[] = "\x40"                         // 00: inc eax
                        "\xc3"                         // 01: ret
                        "\xe8\xf9\xff\xff\xff"         // 02: call 0x00
                        "\xc6\x05\x00\x10\x00\x00\x48" // 07: mov [0x1000], 0x48
                        "\xe8\xed\xff\xff\xff";        // 0e: call 0x00
    uint32_t esp = PROT_DATA_ADDR + 0x1000;

    ctx.ret = true;
    OK(uc_open(UC_ARCH_X86, UC_MODE_32, &uc));
    OK(uc_mem_map(uc, PROT_CODE_ADDR, 0x1000, UC_PROT_READ | UC_PROT_EXEC));
    OK(uc_mem_map(uc, PROT_DATA_ADDR, 0x1000, UC_PROT_READ | UC_PROT_WRITE));
    OK(uc_mem_write(uc, PROT_CODE_ADDR, code, sizeof(code) - 1));
    OK(uc_reg_write(uc, UC_X86_REG_ESP, &esp));
    OK(uc_hook_add(uc, &hook, UC_HOOK_MEM_WRITE_PROT, test_mem_prot_hook_cb,
                   &ctx, 1, 0));
    OK(uc_emu_start(uc, PROT_CODE_ADDR + 2, PROT_CODE_ADDR + sizeof(code) - 1,
                    0, 0));

    // The store turns "inc eax" into "dec eax", so the second call undoes the
    // first one only if the stale translation was dropped.
    OK(uc_reg_read(uc, UC_X86_REG_EAX, &eax));
    TEST_CHECK(ctx.count == 1);
    TEST_CHECK(eax == 0);

    OK(uc_close(uc));
}

// A hook that unmaps the page and returns true cannot let the access through.
static void test_mem_read_prot_hook_unmap(void)
{
    uc_engine *uc;
    mem_prot_hook_ctx ctx = {0};

    ctx.unmap = true;
    ctx.ret = true;
    uc_assert_err(UC_ERR_MAP,
                  test_mem_prot_run(&uc, prot_read_code,
                                    sizeof(prot_read_code) - 1, UC_PROT_NONE,
                                    prot_data, sizeof(prot_data) - 1,
                                    PROT_CODE_ADDR + sizeof(prot_read_code) - 1,
                                    UC_HOOK_MEM_READ_PROT, &ctx));
    TEST_CHECK(ctx.count == 1);

    OK(uc_close(uc));
}

static void test_mem_write_prot_hook_unmap(void)
{
    uc_engine *uc;
    mem_prot_hook_ctx ctx = {0};

    ctx.unmap = true;
    ctx.ret = true;
    uc_assert_err(UC_ERR_MAP,
                  test_mem_prot_run(
                      &uc, prot_write_code, sizeof(prot_write_code) - 1,
                      UC_PROT_READ, NULL, 0,
                      PROT_CODE_ADDR + sizeof(prot_write_code) - 1,
                      UC_HOOK_MEM_WRITE_PROT, &ctx));
    TEST_CHECK(ctx.count == 1);

    OK(uc_close(uc));
}

// The hook may unmap the page it was called for during a fetch too.
static void test_mem_fetch_prot_hook_unmap(void)
{
    uc_engine *uc;
    mem_prot_hook_ctx ctx = {0};

    ctx.unmap = true;
    ctx.ret = true;
    uc_assert_err(UC_ERR_MAP,
                  test_mem_prot_run(
                      &uc, prot_fetch_code, sizeof(prot_fetch_code) - 1,
                      UC_PROT_READ, prot_fetch_target,
                      sizeof(prot_fetch_target) - 1,
                      PROT_DATA_ADDR + sizeof(prot_fetch_target) - 1,
                      UC_HOOK_MEM_FETCH_PROT, &ctx));
    TEST_CHECK(ctx.count == 1);

    OK(uc_close(uc));
}

// An unaligned store to a read-only page is split into byte stores. The hook
// runs once and all bytes are written.
static void test_mem_write_prot_hook_unaligned(void)
{
    uc_engine *uc;
    mem_prot_hook_ctx ctx = {0};
    uint32_t value = 0;
    // mov dword [0x2001], 0x12345678
    const char code[] = "\xc7\x05\x01\x20\x00\x00\x78\x56\x34\x12";

    ctx.ret = true;
    OK(test_mem_prot_run(&uc, code, sizeof(code) - 1, UC_PROT_READ, NULL, 0,
                         PROT_CODE_ADDR + sizeof(code) - 1,
                         UC_HOOK_MEM_WRITE_PROT, &ctx));
    TEST_CHECK(ctx.count == 1);
    TEST_CHECK(ctx.address == PROT_DATA_ADDR + 1);

    OK(uc_mem_read(uc, PROT_DATA_ADDR + 1, &value, sizeof(value)));
    TEST_CHECK(value == 0x12345678);

    OK(uc_close(uc));
}

/*
 * Accesses to the 4 bytes at 0x2ffe cross from a read-write page into the
 * page at PROT_PAGE2_ADDR. The hook must run for the second page too, and
 * only once.
 */
#define PROT_PAGE2_ADDR 0x3000

static uc_err test_mem_prot_run_cross_page(uc_engine **uc, const char *code,
                                           size_t code_len,
                                           uint32_t page2_perms,
                                           int hook_type,
                                           mem_prot_hook_ctx *ctx)
{
    uc_hook hook;

    OK(uc_open(UC_ARCH_X86, UC_MODE_32, uc));
    OK(uc_mem_map(*uc, PROT_CODE_ADDR, 0x1000, UC_PROT_ALL));
    OK(uc_mem_map(*uc, PROT_DATA_ADDR, 0x1000, UC_PROT_READ | UC_PROT_WRITE));
    OK(uc_mem_map(*uc, PROT_PAGE2_ADDR, 0x1000, page2_perms));
    OK(uc_mem_write(*uc, PROT_CODE_ADDR, code, code_len));
    OK(uc_mem_write(*uc, PROT_PAGE2_ADDR - 2, prot_data,
                    sizeof(prot_data) - 1));
    if (hook_type) {
        OK(uc_hook_add(*uc, &hook, hook_type, test_mem_prot_hook_cb, ctx, 1,
                       0));
    }
    return uc_emu_start(*uc, PROT_CODE_ADDR, PROT_CODE_ADDR + code_len, 0, 0);
}

// mov eax, [0x2ffe]
static const char prot_read_cross_code[] = "\xa1\xfe\x2f\x00\x00";
// mov dword [0x2ffe], 0x87654321
static const char prot_write_cross_code[] =
    "\xc7\x05\xfe\x2f\x00\x00\x21\x43\x65\x87";

static void test_mem_read_prot_hook_cross_page(bool ret, uc_err expected_err)
{
    uc_engine *uc;
    mem_prot_hook_ctx ctx = {0};
    uint32_t eax = 0;

    ctx.ret = ret;
    uc_assert_err(expected_err,
                  test_mem_prot_run_cross_page(
                      &uc, prot_read_cross_code,
                      sizeof(prot_read_cross_code) - 1, UC_PROT_NONE,
                      UC_HOOK_MEM_READ_PROT, &ctx));
    TEST_CHECK(ctx.count == 1);
    TEST_CHECK(ctx.type == UC_MEM_READ_PROT);
    // The hook covers the 2 bytes the load reads on the second page
    TEST_CHECK(ctx.address == PROT_PAGE2_ADDR);
    TEST_CHECK(ctx.size == 2);

    OK(uc_reg_read(uc, UC_X86_REG_EAX, &eax));
    TEST_CHECK(eax == (expected_err == UC_ERR_OK ? 0x12345678 : 0));

    OK(uc_close(uc));
}

static void test_mem_write_prot_hook_cross_page(bool ret, uc_err expected_err)
{
    uc_engine *uc;
    mem_prot_hook_ctx ctx = {0};
    uint32_t value = 0;

    ctx.ret = ret;
    uc_assert_err(expected_err,
                  test_mem_prot_run_cross_page(
                      &uc, prot_write_cross_code,
                      sizeof(prot_write_cross_code) - 1, UC_PROT_READ,
                      UC_HOOK_MEM_WRITE_PROT, &ctx));
    TEST_CHECK(ctx.count == 1);
    TEST_CHECK(ctx.type == UC_MEM_WRITE_PROT);
    // The hook covers the 2 bytes the store writes on the second page
    TEST_CHECK(ctx.address == PROT_PAGE2_ADDR);
    TEST_CHECK(ctx.size == 2);
    TEST_CHECK(ctx.value == 0x8765);

    // A denied store leaves the first page alone too
    OK(uc_mem_read(uc, PROT_PAGE2_ADDR - 2, &value, sizeof(value)));
    TEST_CHECK(value ==
               (expected_err == UC_ERR_OK ? 0x87654321 : 0x12345678));

    OK(uc_close(uc));
}

static void test_mem_read_prot_hook_cross_page_allow(void)
{
    test_mem_read_prot_hook_cross_page(true, UC_ERR_OK);
}

static void test_mem_read_prot_hook_cross_page_deny(void)
{
    test_mem_read_prot_hook_cross_page(false, UC_ERR_READ_PROT);
}

static void test_mem_write_prot_hook_cross_page_allow(void)
{
    test_mem_write_prot_hook_cross_page(true, UC_ERR_OK);
}

static void test_mem_write_prot_hook_cross_page_deny(void)
{
    test_mem_write_prot_hook_cross_page(false, UC_ERR_WRITE_PROT);
}

// Without a hook, a load that crosses into a non-readable page fails.
static void test_mem_read_prot_cross_page_no_hook(void)
{
    uc_engine *uc;

    uc_assert_err(UC_ERR_READ_PROT,
                  test_mem_prot_run_cross_page(
                      &uc, prot_read_cross_code,
                      sizeof(prot_read_cross_code) - 1, UC_PROT_NONE, 0,
                      NULL));
    OK(uc_close(uc));
}

// A write accepted on a read-only page is undone by restoring a snapshot.
static void test_mem_write_prot_hook_snapshot(void)
{
    uc_engine *uc;
    uc_hook hook;
    uc_context *ctx0;
    mem_prot_hook_ctx ctx = {0};
    uint32_t value = 0;

    ctx.ret = true;
    OK(uc_open(UC_ARCH_X86, UC_MODE_32, &uc));
    OK(uc_ctl_context_mode(uc, UC_CTL_CONTEXT_MEMORY));
    OK(uc_mem_map(uc, PROT_CODE_ADDR, 0x1000, UC_PROT_ALL));
    OK(uc_mem_map(uc, PROT_DATA_ADDR, 0x1000, UC_PROT_READ));
    OK(uc_mem_write(uc, PROT_CODE_ADDR, prot_write_code,
                    sizeof(prot_write_code) - 1));
    OK(uc_mem_write(uc, PROT_DATA_ADDR, "\x11\x11\x11\x11", 4));
    OK(uc_context_alloc(uc, &ctx0));
    OK(uc_context_save(uc, ctx0));
    OK(uc_hook_add(uc, &hook, UC_HOOK_MEM_WRITE_PROT, test_mem_prot_hook_cb,
                   &ctx, 1, 0));

    OK(uc_emu_start(uc, PROT_CODE_ADDR,
                    PROT_CODE_ADDR + sizeof(prot_write_code) - 1, 0, 0));
    TEST_CHECK(ctx.count == 1);
    OK(uc_mem_read(uc, PROT_DATA_ADDR, &value, sizeof(value)));
    TEST_CHECK(value == 0x12345678);

    OK(uc_context_restore(uc, ctx0));
    OK(uc_mem_read(uc, PROT_DATA_ADDR, &value, sizeof(value)));
    TEST_CHECK(value == 0x11111111);

    OK(uc_context_free(ctx0));
    OK(uc_close(uc));
}

// UC_HOOK_MEM_READ and UC_HOOK_MEM_WRITE callback that changes the
// permissions of the page, splitting the region it sits in
static void test_mem_access_protect_cb(uc_engine *uc, uc_mem_type type,
                                       uint64_t address, int size,
                                       int64_t value, void *user_data)
{
    mem_prot_hook_ctx *ctx = (mem_prot_hook_ctx *)user_data;

    ctx->count++;
    OK(uc_mem_protect(uc, address & ~0xfffULL, 0x1000, ctx->new_perms));
}

// A UC_HOOK_MEM_WRITE callback that makes the page writable lets the store
// through.
static void test_mem_write_hook_grant(void)
{
    uc_engine *uc;
    uc_hook hook;
    mem_prot_hook_ctx ctx = {0};
    uint32_t value = 0;

    ctx.new_perms = UC_PROT_READ | UC_PROT_WRITE;
    OK(uc_open(UC_ARCH_X86, UC_MODE_32, &uc));
    OK(uc_mem_map(uc, PROT_CODE_ADDR, 0x1000, UC_PROT_ALL));
    OK(uc_mem_map(uc, PROT_DATA_ADDR, 0x2000, UC_PROT_READ));
    OK(uc_mem_write(uc, PROT_CODE_ADDR, prot_write_code,
                    sizeof(prot_write_code) - 1));
    OK(uc_hook_add(uc, &hook, UC_HOOK_MEM_WRITE, test_mem_access_protect_cb,
                   &ctx, 1, 0));
    OK(uc_emu_start(uc, PROT_CODE_ADDR,
                    PROT_CODE_ADDR + sizeof(prot_write_code) - 1, 0, 0));
    TEST_CHECK(ctx.count == 1);

    OK(uc_mem_read(uc, PROT_DATA_ADDR, &value, sizeof(value)));
    TEST_CHECK(value == 0x12345678);

    OK(uc_close(uc));
}

// A UC_HOOK_MEM_READ callback that makes the page unreadable stops the load.
// The page sits in the middle of a larger region, so the region is split up.
static void test_mem_read_hook_revoke(void)
{
    uc_engine *uc;
    uc_hook hook;
    mem_prot_hook_ctx ctx = {0};
    uint32_t eax = 0;
    // mov eax, [0x3000]
    const char code[] = "\xa1\x00\x30\x00\x00";

    ctx.new_perms = UC_PROT_NONE;
    OK(uc_open(UC_ARCH_X86, UC_MODE_32, &uc));
    OK(uc_mem_map(uc, PROT_CODE_ADDR, 0x1000, UC_PROT_ALL));
    OK(uc_mem_map(uc, PROT_DATA_ADDR, 0x3000, UC_PROT_READ));
    OK(uc_mem_write(uc, PROT_CODE_ADDR, code, sizeof(code) - 1));
    OK(uc_mem_write(uc, PROT_PAGE2_ADDR, prot_data, sizeof(prot_data) - 1));
    OK(uc_hook_add(uc, &hook, UC_HOOK_MEM_READ, test_mem_access_protect_cb,
                   &ctx, 1, 0));
    uc_assert_err(UC_ERR_READ_PROT,
                  uc_emu_start(uc, PROT_CODE_ADDR,
                               PROT_CODE_ADDR + sizeof(code) - 1, 0, 0));
    TEST_CHECK(ctx.count == 1);

    OK(uc_reg_read(uc, UC_X86_REG_EAX, &eax));
    TEST_CHECK(eax == 0);

    OK(uc_close(uc));
}

// Code on a non-executable page runs after a UC_HOOK_MEM_FETCH_PROT callback
// accepts the fetch. A store into it accepted by a UC_HOOK_MEM_WRITE_PROT
// callback must drop that translation.
static void test_mem_write_prot_hook_smc_no_exec(void)
{
    uc_engine *uc;
    uc_hook hook;
    mem_prot_hook_ctx ctx = {0};
    uint32_t eax = 0;
    uint32_t esp = PROT_PAGE2_ADDR + 0x1000;

    const char code[] = "\xe8\xfb\x0f\x00\x00"         // 00: call 0x2000
                        "\xc6\x05\x00\x20\x00\x00\x48" // 05: mov [0x2000], 0x48
                        "\xe8\xef\x0f\x00\x00";        // 0c: call 0x2000
    // inc eax; ret
    const char target[] = "\x40\xc3";

    ctx.ret = true;
    OK(uc_open(UC_ARCH_X86, UC_MODE_32, &uc));
    OK(uc_mem_map(uc, PROT_CODE_ADDR, 0x1000, UC_PROT_ALL));
    OK(uc_mem_map(uc, PROT_DATA_ADDR, 0x1000, UC_PROT_READ));
    OK(uc_mem_map(uc, PROT_PAGE2_ADDR, 0x1000, UC_PROT_READ | UC_PROT_WRITE));
    OK(uc_mem_write(uc, PROT_CODE_ADDR, code, sizeof(code) - 1));
    OK(uc_mem_write(uc, PROT_DATA_ADDR, target, sizeof(target) - 1));
    OK(uc_reg_write(uc, UC_X86_REG_ESP, &esp));
    OK(uc_hook_add(uc, &hook, UC_HOOK_MEM_FETCH_PROT | UC_HOOK_MEM_WRITE_PROT,
                   test_mem_prot_hook_cb, &ctx, 1, 0));
    OK(uc_emu_start(uc, PROT_CODE_ADDR, PROT_CODE_ADDR + sizeof(code) - 1, 0,
                    0));

    // The store turns "inc eax" into "dec eax", so the second call undoes the
    // first one only if the stale translation was dropped.
    OK(uc_reg_read(uc, UC_X86_REG_EAX, &eax));
    TEST_CHECK(eax == 0);

    OK(uc_close(uc));
}

// An accepted unaligned store into the running block restarts the
// instruction partway through the split store. The page must not stay
// accepted afterwards, so a later store the hook denies still fails.
static void test_mem_write_prot_hook_unaligned_smc(void)
{
    uc_engine *uc;
    uc_hook hook;
    mem_prot_hook_ctx ctx = {0};
    uint32_t eax = 0;
    uint8_t byte = 0xff;

    const char code[] =
        "\xc7\x05\x11\x10\x00\x00\x90\x90\x90\x90" // 00: mov dword [0x1011], nops
        "\x90\x90\x90\x90\x90\x90\x90"             // 0a: nop x7
        "\x40\x40\x40\x40"                         // 11: inc eax x4
        "\xc6\x05\x30\x10\x00\x00\x01";            // 15: mov byte [0x1030], 1

    ctx.ret = true;
    ctx.deny_from = PROT_CODE_ADDR + 0x20;
    OK(uc_open(UC_ARCH_X86, UC_MODE_32, &uc));
    OK(uc_mem_map(uc, PROT_CODE_ADDR, 0x1000, UC_PROT_READ | UC_PROT_EXEC));
    OK(uc_mem_write(uc, PROT_CODE_ADDR, code, sizeof(code) - 1));
    OK(uc_hook_add(uc, &hook, UC_HOOK_MEM_WRITE_PROT, test_mem_prot_hook_cb,
                   &ctx, 1, 0));
    uc_assert_err(UC_ERR_WRITE_PROT,
                  uc_emu_start(uc, PROT_CODE_ADDR,
                               PROT_CODE_ADDR + sizeof(code) - 1, 0, 0));

    OK(uc_reg_read(uc, UC_X86_REG_EAX, &eax));
    TEST_CHECK(eax == 0);
    OK(uc_mem_read(uc, PROT_CODE_ADDR + 0x30, &byte, 1));
    TEST_CHECK(byte == 0);

    OK(uc_close(uc));
}

// A page mapped with uc_mem_map_ptr() is host memory, and the host may have
// mapped it read-only. A store that a UC_HOOK_MEM_WRITE_PROT callback accepted
// without making the page writable is dropped there, for whole and split
// stores, instead of crashing the process. uc_mem_protect() makes the page
// read-only, which sends stores to it through the slow path.
static void test_mem_write_prot_hook_map_ptr(void)
{
    uc_engine *uc;
    uc_hook hook;
    mem_prot_hook_ctx ctx = {0};
    uint8_t *host;
    uint32_t value = 0;
    const char code[] =
        "\xc7\x05\x00\x20\x00\x00\x21\x43\x65\x87"  // mov dword [0x2000], ...
        "\xc7\x05\x01\x20\x00\x00\x21\x43\x65\x87"; // mov dword [0x2001], ...

#if defined(_WIN32) || defined(__WIN32__) || defined(__WINDOWS__)
    DWORD old_protect;

    host = VirtualAlloc(NULL, 0x1000, MEM_COMMIT | MEM_RESERVE,
                        PAGE_READWRITE);
    TEST_CHECK(host != NULL);
    memcpy(host, prot_data, sizeof(prot_data) - 1);
    TEST_CHECK(VirtualProtect(host, 0x1000, PAGE_READONLY, &old_protect));
#else
    host = mmap(NULL, 0x1000, PROT_READ | PROT_WRITE,
                MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    TEST_CHECK(host != MAP_FAILED);
    memcpy(host, prot_data, sizeof(prot_data) - 1);
    TEST_CHECK(mprotect(host, 0x1000, PROT_READ) == 0);
#endif

    ctx.ret = true;
    OK(uc_open(UC_ARCH_X86, UC_MODE_32, &uc));
    OK(uc_mem_map(uc, PROT_CODE_ADDR, 0x1000, UC_PROT_ALL));
    OK(uc_mem_map_ptr(uc, PROT_DATA_ADDR, 0x1000, UC_PROT_ALL, host));
    OK(uc_mem_protect(uc, PROT_DATA_ADDR, 0x1000, UC_PROT_READ));
    OK(uc_mem_write(uc, PROT_CODE_ADDR, code, sizeof(code) - 1));
    OK(uc_hook_add(uc, &hook, UC_HOOK_MEM_WRITE_PROT, test_mem_prot_hook_cb,
                   &ctx, 1, 0));
    OK(uc_emu_start(uc, PROT_CODE_ADDR, PROT_CODE_ADDR + sizeof(code) - 1, 0,
                    0));
    TEST_CHECK(ctx.count == 2);

    OK(uc_mem_read(uc, PROT_DATA_ADDR, &value, sizeof(value)));
    TEST_CHECK(value == 0x12345678);

    OK(uc_close(uc));

#if defined(_WIN32) || defined(__WIN32__) || defined(__WINDOWS__)
    VirtualFree(host, 0, MEM_RELEASE);
#else
    munmap(host, 0x1000);
#endif
}

// UC_HOOK_MEM_*_UNMAPPED callback that maps the page as read-write, fills it
// with prot_data and returns true
static bool test_mem_map_on_fault_cb(uc_engine *uc, uc_mem_type type,
                                     uint64_t address, int size, int64_t value,
                                     void *user_data)
{
    mem_prot_hook_ctx *ctx = (mem_prot_hook_ctx *)user_data;

    if (ctx->count++ == 0) {
        ctx->type = type;
        ctx->address = address;
        ctx->size = size;
        ctx->value = value;
    }
    OK(uc_mem_map(uc, address & ~0xfffULL, 0x1000,
                  UC_PROT_READ | UC_PROT_WRITE));
    OK(uc_mem_write(uc, address & ~0xfffULL, prot_data, sizeof(prot_data) - 1));
    return true;
}

// Without a hook, a store that crosses into an unmapped page fails before it
// writes anything to the first page.
static void test_mem_write_cross_page_unmapped(void)
{
    uc_engine *uc;
    uint16_t value = 0;

    OK(uc_open(UC_ARCH_X86, UC_MODE_32, &uc));
    OK(uc_mem_map(uc, PROT_CODE_ADDR, 0x1000, UC_PROT_ALL));
    OK(uc_mem_map(uc, PROT_DATA_ADDR, 0x1000, UC_PROT_READ | UC_PROT_WRITE));
    OK(uc_mem_write(uc, PROT_CODE_ADDR, prot_write_cross_code,
                    sizeof(prot_write_cross_code) - 1));
    OK(uc_mem_write(uc, PROT_PAGE2_ADDR - 2, "\x78\x56", 2));
    uc_assert_err(UC_ERR_WRITE_UNMAPPED,
                  uc_emu_start(uc, PROT_CODE_ADDR,
                               PROT_CODE_ADDR +
                                   sizeof(prot_write_cross_code) - 1,
                               0, 0));

    OK(uc_mem_read(uc, PROT_PAGE2_ADDR - 2, &value, sizeof(value)));
    TEST_CHECK(value == 0x5678);

    OK(uc_close(uc));
}

// A UC_HOOK_MEM_WRITE_UNMAPPED callback for the second page of a split store
// gets the part of the store on that page, and can map the page to let the
// whole store through.
static void test_mem_write_unmapped_hook_cross_page(void)
{
    uc_engine *uc;
    uc_hook hook;
    mem_prot_hook_ctx ctx = {0};
    uint32_t value = 0;

    OK(uc_open(UC_ARCH_X86, UC_MODE_32, &uc));
    OK(uc_mem_map(uc, PROT_CODE_ADDR, 0x1000, UC_PROT_ALL));
    OK(uc_mem_map(uc, PROT_DATA_ADDR, 0x1000, UC_PROT_READ | UC_PROT_WRITE));
    OK(uc_mem_write(uc, PROT_CODE_ADDR, prot_write_cross_code,
                    sizeof(prot_write_cross_code) - 1));
    OK(uc_hook_add(uc, &hook, UC_HOOK_MEM_WRITE_UNMAPPED,
                   test_mem_map_on_fault_cb, &ctx, 1, 0));
    OK(uc_emu_start(uc, PROT_CODE_ADDR,
                    PROT_CODE_ADDR + sizeof(prot_write_cross_code) - 1, 0, 0));
    TEST_CHECK(ctx.count == 1);
    TEST_CHECK(ctx.type == UC_MEM_WRITE_UNMAPPED);
    TEST_CHECK(ctx.address == PROT_PAGE2_ADDR);
    TEST_CHECK(ctx.size == 2);
    TEST_CHECK(ctx.value == 0x8765);

    OK(uc_mem_read(uc, PROT_PAGE2_ADDR - 2, &value, sizeof(value)));
    TEST_CHECK(value == 0x87654321);

    OK(uc_close(uc));
}

// A UC_HOOK_MEM_READ_UNMAPPED callback for the second page of a split load
// gets the part of the load on that page.
static void test_mem_read_unmapped_hook_cross_page(void)
{
    uc_engine *uc;
    uc_hook hook;
    mem_prot_hook_ctx ctx = {0};
    uint32_t eax = 0;

    OK(uc_open(UC_ARCH_X86, UC_MODE_32, &uc));
    OK(uc_mem_map(uc, PROT_CODE_ADDR, 0x1000, UC_PROT_ALL));
    OK(uc_mem_map(uc, PROT_DATA_ADDR, 0x1000, UC_PROT_READ | UC_PROT_WRITE));
    OK(uc_mem_write(uc, PROT_CODE_ADDR, prot_read_cross_code,
                    sizeof(prot_read_cross_code) - 1));
    OK(uc_mem_write(uc, PROT_PAGE2_ADDR - 2, "\x78\x56", 2));
    OK(uc_hook_add(uc, &hook, UC_HOOK_MEM_READ_UNMAPPED,
                   test_mem_map_on_fault_cb, &ctx, 1, 0));
    OK(uc_emu_start(uc, PROT_CODE_ADDR,
                    PROT_CODE_ADDR + sizeof(prot_read_cross_code) - 1, 0, 0));
    TEST_CHECK(ctx.count == 1);
    TEST_CHECK(ctx.type == UC_MEM_READ_UNMAPPED);
    TEST_CHECK(ctx.address == PROT_PAGE2_ADDR);
    TEST_CHECK(ctx.size == 2);

    OK(uc_reg_read(uc, UC_X86_REG_EAX, &eax));
    TEST_CHECK(eax == 0x56785678);

    OK(uc_close(uc));
}

// UC_HOOK_MEM_READ and UC_HOOK_MEM_WRITE callback that unmaps the page
static void test_mem_access_unmap_cb(uc_engine *uc, uc_mem_type type,
                                     uint64_t address, int size, int64_t value,
                                     void *user_data)
{
    OK(uc_mem_unmap(uc, address & ~0xfffULL, 0x1000));
}

// A page that a UC_HOOK_MEM_WRITE callback unmaps goes to the
// UC_HOOK_MEM_WRITE_UNMAPPED hooks, which can map it again.
static void test_mem_write_hook_unmap(void)
{
    uc_engine *uc;
    uc_hook hook1, hook2;
    mem_prot_hook_ctx ctx = {0};
    uint32_t value = 0;

    OK(uc_open(UC_ARCH_X86, UC_MODE_32, &uc));
    OK(uc_mem_map(uc, PROT_CODE_ADDR, 0x1000, UC_PROT_ALL));
    OK(uc_mem_map(uc, PROT_DATA_ADDR, 0x1000, UC_PROT_READ | UC_PROT_WRITE));
    OK(uc_mem_write(uc, PROT_CODE_ADDR, prot_write_code,
                    sizeof(prot_write_code) - 1));
    OK(uc_hook_add(uc, &hook1, UC_HOOK_MEM_WRITE, test_mem_access_unmap_cb,
                   NULL, 1, 0));
    OK(uc_hook_add(uc, &hook2, UC_HOOK_MEM_WRITE_UNMAPPED,
                   test_mem_map_on_fault_cb, &ctx, 1, 0));
    OK(uc_emu_start(uc, PROT_CODE_ADDR,
                    PROT_CODE_ADDR + sizeof(prot_write_code) - 1, 0, 0));
    TEST_CHECK(ctx.count == 1);
    TEST_CHECK(ctx.address == PROT_DATA_ADDR);

    OK(uc_mem_read(uc, PROT_DATA_ADDR, &value, sizeof(value)));
    TEST_CHECK(value == 0x12345678);

    OK(uc_close(uc));
}

// A page that a UC_HOOK_MEM_READ callback unmaps goes to the
// UC_HOOK_MEM_READ_UNMAPPED hooks, which can map it again.
static void test_mem_read_hook_unmap(void)
{
    uc_engine *uc;
    uc_hook hook1, hook2;
    mem_prot_hook_ctx ctx = {0};
    uint32_t eax = 0;

    OK(uc_open(UC_ARCH_X86, UC_MODE_32, &uc));
    OK(uc_mem_map(uc, PROT_CODE_ADDR, 0x1000, UC_PROT_ALL));
    OK(uc_mem_map(uc, PROT_DATA_ADDR, 0x1000, UC_PROT_READ | UC_PROT_WRITE));
    OK(uc_mem_write(uc, PROT_CODE_ADDR, prot_read_code,
                    sizeof(prot_read_code) - 1));
    OK(uc_hook_add(uc, &hook1, UC_HOOK_MEM_READ, test_mem_access_unmap_cb,
                   NULL, 1, 0));
    OK(uc_hook_add(uc, &hook2, UC_HOOK_MEM_READ_UNMAPPED,
                   test_mem_map_on_fault_cb, &ctx, 1, 0));
    OK(uc_emu_start(uc, PROT_CODE_ADDR,
                    PROT_CODE_ADDR + sizeof(prot_read_code) - 1, 0, 0));
    TEST_CHECK(ctx.count == 1);
    TEST_CHECK(ctx.address == PROT_DATA_ADDR);

    OK(uc_reg_read(uc, UC_X86_REG_EAX, &eax));
    TEST_CHECK(eax == 0x12345678);

    OK(uc_close(uc));
}

// A UC_HOOK_MEM_READ callback that makes a whole one-page region unreadable
// stops the load. This change neither splits the region nor toggles write
// access, so it does not flush the TLB.
static void test_mem_read_hook_revoke_no_flush(void)
{
    uc_engine *uc;
    uc_hook hook;
    mem_prot_hook_ctx ctx = {0};
    uint32_t eax = 0;

    ctx.new_perms = UC_PROT_NONE;
    OK(uc_open(UC_ARCH_X86, UC_MODE_32, &uc));
    OK(uc_mem_map(uc, PROT_CODE_ADDR, 0x1000, UC_PROT_ALL));
    OK(uc_mem_map(uc, PROT_DATA_ADDR, 0x1000, UC_PROT_READ));
    OK(uc_mem_write(uc, PROT_CODE_ADDR, prot_read_code,
                    sizeof(prot_read_code) - 1));
    OK(uc_mem_write(uc, PROT_DATA_ADDR, prot_data, sizeof(prot_data) - 1));
    OK(uc_hook_add(uc, &hook, UC_HOOK_MEM_READ, test_mem_access_protect_cb,
                   &ctx, 1, 0));
    uc_assert_err(UC_ERR_READ_PROT,
                  uc_emu_start(uc, PROT_CODE_ADDR,
                               PROT_CODE_ADDR + sizeof(prot_read_code) - 1, 0,
                               0));
    TEST_CHECK(ctx.count == 1);

    OK(uc_reg_read(uc, UC_X86_REG_EAX, &eax));
    TEST_CHECK(eax == 0);

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
             {"test_snapshot", test_snapshot},
             {"test_snapshot_with_vtlb", test_snapshot_with_vtlb},
             {"test_context_snapshot", test_context_snapshot},
             {"test_snapshot_unmap", test_snapshot_unmap},
             {"test_mem_read_and_write_large_memory_block",
              test_mem_read_and_write_large_memory_block},
             {"test_virtual_to_physical", test_virtual_to_physical},
             {"test_virtual_write", test_virtual_write},
             {"test_mem_addr_size_wraparound", test_mem_addr_size_wraparound},
             {"test_smc", test_smc},
             {"test_tlbdirty_exec", test_tlbdirty_exec},
             {"test_mem_read_prot_hook_allow", test_mem_read_prot_hook_allow},
             {"test_mem_read_prot_hook_grant", test_mem_read_prot_hook_grant},
             {"test_mem_read_prot_hook_deny", test_mem_read_prot_hook_deny},
             {"test_mem_write_prot_hook_allow", test_mem_write_prot_hook_allow},
             {"test_mem_write_prot_hook_grant", test_mem_write_prot_hook_grant},
             {"test_mem_write_prot_hook_deny", test_mem_write_prot_hook_deny},
             {"test_mem_fetch_prot_hook_allow", test_mem_fetch_prot_hook_allow},
             {"test_mem_fetch_prot_hook_grant", test_mem_fetch_prot_hook_grant},
             {"test_mem_fetch_prot_hook_deny", test_mem_fetch_prot_hook_deny},
             {"test_mem_prot_no_hook", test_mem_prot_no_hook},
             {"test_mem_write_prot_hook_smc", test_mem_write_prot_hook_smc},
             {"test_mem_read_prot_hook_unmap", test_mem_read_prot_hook_unmap},
             {"test_mem_write_prot_hook_unmap", test_mem_write_prot_hook_unmap},
             {"test_mem_fetch_prot_hook_unmap", test_mem_fetch_prot_hook_unmap},
             {"test_mem_write_prot_hook_unaligned",
              test_mem_write_prot_hook_unaligned},
             {"test_mem_read_prot_hook_cross_page_allow",
              test_mem_read_prot_hook_cross_page_allow},
             {"test_mem_read_prot_hook_cross_page_deny",
              test_mem_read_prot_hook_cross_page_deny},
             {"test_mem_write_prot_hook_cross_page_allow",
              test_mem_write_prot_hook_cross_page_allow},
             {"test_mem_write_prot_hook_cross_page_deny",
              test_mem_write_prot_hook_cross_page_deny},
             {"test_mem_read_prot_cross_page_no_hook",
              test_mem_read_prot_cross_page_no_hook},
             {"test_mem_write_prot_hook_snapshot",
              test_mem_write_prot_hook_snapshot},
             {"test_mem_write_hook_grant", test_mem_write_hook_grant},
             {"test_mem_read_hook_revoke", test_mem_read_hook_revoke},
             {"test_mem_write_prot_hook_smc_no_exec",
              test_mem_write_prot_hook_smc_no_exec},
             {"test_mem_write_prot_hook_unaligned_smc",
              test_mem_write_prot_hook_unaligned_smc},
             {"test_mem_write_prot_hook_map_ptr",
              test_mem_write_prot_hook_map_ptr},
             {"test_mem_write_cross_page_unmapped",
              test_mem_write_cross_page_unmapped},
             {"test_mem_write_unmapped_hook_cross_page",
              test_mem_write_unmapped_hook_cross_page},
             {"test_mem_read_unmapped_hook_cross_page",
              test_mem_read_unmapped_hook_cross_page},
             {"test_mem_write_hook_unmap", test_mem_write_hook_unmap},
             {"test_mem_read_hook_unmap", test_mem_read_hook_unmap},
             {"test_mem_read_hook_revoke_no_flush",
              test_mem_read_hook_revoke_no_flush},
             {NULL, NULL}};
