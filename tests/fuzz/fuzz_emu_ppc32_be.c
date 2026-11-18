#include <unicorn/unicorn.h>

/* unicorn-ppc-1: engine-lifetime leak (cpu_ppc_tb_init timebase timer,
 * qemu/hw/ppc/ppc.c) fires on every uc_open(UC_ARCH_PPC) until upstream
 * fixes it (regression of the class fixed in #1680/#1686). LSan tracking is
 * suppressed ONLY for the init path below via weak symbols (no-op on builds
 * without the ASan runtime); allocations made during emulation stay tracked.
 */
extern void __lsan_disable(void) __attribute__((weak));
extern void __lsan_enable(void) __attribute__((weak));


// memory address where emulation starts
#define ADDRESS 0x1000000

uc_engine *uc;
int initialized = 0;
FILE * outfile = NULL;


int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    uc_err err;

    if (initialized == 0) {
        if (outfile == NULL) {
            // we compute the output
            outfile = fopen("/dev/null", "w");
            if (outfile == NULL) {
                printf("failed opening /dev/null\n");
                abort();
                return 0;
            }
        }

        initialized = 1;
    }

    // Not global as we must reset this structure
    // Initialize emulator in supplied mode
    // unicorn-ppc-1: disable LSan for the engine-init path (see comment above)
    if (__lsan_disable) {
        __lsan_disable();
    }
    err = uc_open(UC_ARCH_PPC, UC_MODE_PPC32 | UC_MODE_BIG_ENDIAN, &uc);
    if (err != UC_ERR_OK) {
        printf("Failed on uc_open() with error returned: %u\n", err);
        abort();
    }

    // map 4MB memory for this emulation
    uc_mem_map(uc, ADDRESS, 4 * 1024 * 1024, UC_PROT_ALL);
    if (__lsan_enable) {
        __lsan_enable();
    }

    // write machine code to be emulated to memory
    if (uc_mem_write(uc, ADDRESS, Data, Size)) {
        printf("Failed to write emulation code to memory, quit!\n");
        abort();
    }

    // emulate code in infinite time & 4096 instructions
    // avoid timeouts with infinite loops
    err=uc_emu_start(uc, ADDRESS, ADDRESS + Size, 0, 0x1000);
    if (err) {
        fprintf(outfile, "Failed on uc_emu_start() with error returned %u: %s\n", err, uc_strerror(err));
    }

    uc_close(uc);

    return 0;
}
