/* Unicorn Emulator Engine */
/* By Lazymio(@wtdcode), 2021 */

/* Sample code to demonstrate how to use uc_ctl */

#include <unicorn/unicorn.h>
#include <string.h>
#include <time.h>

// code to be emulated

// INC ecx; DEC edx; PXOR xmm0, xmm1
#define X86_CODE32 "\x41\x4a"
//   cmp eax, 0;
//   jg lb;
//   inc eax;
//   nop;
// lb:
//   inc ebx;
//   nop;
#define X86_JUMP_CODE "\x83\xf8\x00\x7f\x02\x40\x90\x43\x90"

// memory address where emulation starts
#define ADDRESS 0x10000

static void test_uc_ctl_read(void)
{
    uc_engine *uc;
    uc_err err;
    int mode, arch;
    uint32_t pagesize;
    uint64_t timeout;

    printf("Reading some properties by uc_ctl.\n");

    // Initialize emulator in X86-32bit mode
    err = uc_open(UC_ARCH_X86, UC_MODE_32, &uc);
    if (err) {
        printf("Failed on uc_open() with error returned: %u\n", err);
        return;
    }

    // Let's query some properties by uc_ctl.
    // Note uc_ctl_* is just tiny macro wrappers for uc_ctl().
    err = uc_ctl_get_mode(uc, &mode);
    if (err) {
        printf("Failed on uc_ctl() with error returned: %u\n", err);
        return;
    }

    err = uc_ctl_get_arch(uc, &arch);
    if (err) {
        printf("Failed on uc_ctl() with error returned: %u\n", err);
        return;
    }

    err = uc_ctl_get_timeout(uc, &timeout);
    if (err) {
        printf("Failed on uc_ctl() with error returned: %u\n", err);
        return;
    }

    err = uc_ctl_get_page_size(uc, &pagesize);
    if (err) {
        printf("Failed on uc_ctl() with error returned: %u\n", err);
        return;
    }

    printf(">>> mode = %d, arch = %d, timeout=%" PRIu64 ", pagesize=%" PRIu32
           "\n",
           mode, arch, timeout, pagesize);

    uc_close(uc);
}

static void trace_new_edge(uc_engine *uc, uc_tb *cur, uc_tb *prev, void *data)
{
    printf(">>> Getting a new edge from 0x%" PRIx64 " to 0x%" PRIx64 ".\n",
           prev->pc + prev->size - 1, cur->pc);
}

void test_uc_ctl_exits(void)
{
    uc_engine *uc;
    uc_err err;
    uc_hook h;
    int r_eax, r_ebx;
    uint64_t exits[] = {ADDRESS + 6, ADDRESS + 8};

    printf("Using multiple exits by uc_ctl.\n");

    // Initialize emulator in X86-32bit mode
    err = uc_open(UC_ARCH_X86, UC_MODE_32, &uc);
    if (err) {
        printf("Failed on uc_open() with error returned: %u\n", err);
        return;
    }

    err = uc_mem_map(uc, ADDRESS, 0x1000, UC_PROT_ALL);
    if (err) {
        printf("Failed on uc_mem_map() with error returned: %u\n", err);
        return;
    }

    // Write our code to the memory.
    err = uc_mem_write(uc, ADDRESS, X86_JUMP_CODE, sizeof(X86_JUMP_CODE) - 1);
    if (err) {
        printf("Failed on uc_mem_write() with error returned: %u\n", err);
        return;
    }

    // We trace if any new edge is generated.
    err = uc_hook_add(uc, &h, UC_HOOK_EDGE_GENERATED, trace_new_edge, NULL, 0,
                      -1);
    if (err) {
        printf("Failed on uc_hook_add() with error returned: %u\n", err);
        return;
    }

    // Enable multiple exits.
    err = uc_ctl_exits_enable(uc);
    if (err) {
        printf("Failed on uc_ctl() with error returned: %u\n", err);
        return;
    }

    err = uc_ctl_set_exits(uc, exits, 2);
    if (err) {
        printf("Failed on uc_ctl() with error returned: %u\n", err);
        return;
    }

    // This should stop at ADDRESS + 6 and increase eax, even thouhg we don't
    // provide an exit.
    err = uc_emu_start(uc, ADDRESS, 0, 0, 0);
    if (err) {
        printf("Failed on uc_emu_start() with error returned: %u\n", err);
        return;
    }

    err = uc_reg_read(uc, UC_X86_REG_EAX, &r_eax);
    if (err) {
        printf("Failed on uc_reg_read() with error returned: %u\n", err);
        return;
    }
    err = uc_reg_read(uc, UC_X86_REG_EBX, &r_ebx);
    if (err) {
        printf("Failed on uc_reg_read() with error returned: %u\n", err);
        return;
    }
    printf(">>> eax = %" PRId32 " and ebx = %" PRId32
           " after the first emulation\n",
           r_eax, r_ebx);

    // This should stop at ADDRESS + 8, even thouhg we don't provide an exit.
    err = uc_emu_start(uc, ADDRESS, 0, 0, 0);
    if (err) {
        printf("Failed on uc_emu_start() with error returned: %u\n", err);
        return;
    }

    err = uc_reg_read(uc, UC_X86_REG_EAX, &r_eax);
    if (err) {
        printf("Failed on uc_reg_read() with error returned: %u\n", err);
        return;
    }
    err = uc_reg_read(uc, UC_X86_REG_EBX, &r_ebx);
    if (err) {
        printf("Failed on uc_reg_read() with error returned: %u\n", err);
        return;
    }
    printf(">>> eax = %" PRId32 " and ebx = %" PRId32
           " after the second emulation\n",
           r_eax, r_ebx);

    uc_close(uc);
}

#define TB_COUNT (8)
#define TCG_MAX_INSNS (512) // from tcg.h
#define CODE_LEN TB_COUNT *TCG_MAX_INSNS

double time_emulation(uc_engine *uc, uint64_t start, uint64_t end)
{
    time_t t1, t2;

    t1 = clock();

    uc_emu_start(uc, start, end, 0, 0);

    t2 = clock();

    return (t2 - t1) * 1000.0 / CLOCKS_PER_SEC;
}

static void test_uc_ctl_tb_cache(void)
{
    uc_engine *uc;
    uc_err err;
    uc_tb tb;
    uc_hook h;
    char code[CODE_LEN];
    double standard, cached, evicted;

    printf("Controling the TB cache in a finer granularity by uc_ctl.\n");

    // Fill the code buffer with NOP.
    memset(code, 0x90, CODE_LEN);

    // Initialize emulator in X86-32bit mode
    err = uc_open(UC_ARCH_X86, UC_MODE_32, &uc);
    if (err) {
        printf("Failed on uc_open() with error returned: %u\n", err);
        return;
    }

    err = uc_mem_map(uc, ADDRESS, 0x10000, UC_PROT_ALL);
    if (err) {
        printf("Failed on uc_mem_map() with error returned: %u\n", err);
        return;
    }

    // Write our code to the memory.
    err = uc_mem_write(uc, ADDRESS, code, sizeof(code) - 1);
    if (err) {
        printf("Failed on uc_mem_write() with error returned: %u\n", err);
        return;
    }

    // We trace if any new edge is generated.
    // Note: In this sample, there is only **one** basic block while muliple
    // translation blocks is generated due to QEMU tcg buffer limit. In this
    // case, we don't consider it as a new edge.
    err = uc_hook_add(uc, &h, UC_HOOK_EDGE_GENERATED, trace_new_edge, NULL, 0,
                      -1);
    if (err) {
        printf("Failed on uc_hook_add() with error returned: %u\n", err);
        return;
    }

    // Do emulation without any cache.
    standard = time_emulation(uc, ADDRESS, ADDRESS + sizeof(code) - 1);

    // Now we request cache for all TBs.
    for (int i = 0; i < TB_COUNT; i++) {
        err = uc_ctl_request_cache(uc, (uint64_t)(ADDRESS + i * TCG_MAX_INSNS),
                                   &tb);
        printf(">>> TB is cached at 0x%" PRIx64 " which has %" PRIu16
               " instructions with %" PRIu16 " bytes.\n",
               tb.pc, tb.icount, tb.size);
        if (err) {
            printf("Failed on uc_ctl() with error returned: %u\n", err);
            return;
        }
    }

    // Do emulation with all TB cached.
    cached = time_emulation(uc, ADDRESS, ADDRESS + sizeof(code) - 1);

    // Now we clear cache for all TBs.
    for (int i = 0; i < TB_COUNT; i++) {
        err = uc_ctl_remove_cache(uc, (uint64_t)(ADDRESS + i * TCG_MAX_INSNS),
                                  (uint64_t)(ADDRESS + i * TCG_MAX_INSNS + 1));
        if (err) {
            printf("Failed on uc_ctl() with error returned: %u\n", err);
            return;
        }
    }

    // Do emulation with all TB cache evicted.
    evicted = time_emulation(uc, ADDRESS, ADDRESS + sizeof(code) - 1);

    printf(">>> Run time: First time: %f, Cached: %f, Cache evicted: %f\n",
           standard, cached, evicted);

    uc_close(uc);
}

int main(int argc, char **argv, char **envp)
{
    test_uc_ctl_read();
    printf("====================\n");
    test_uc_ctl_exits();
    printf("====================\n");
    test_uc_ctl_tb_cache();

    return 0;
}
