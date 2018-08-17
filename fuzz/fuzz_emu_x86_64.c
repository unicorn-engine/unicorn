#include <unicorn/unicorn.h>


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
    err = uc_open(UC_ARCH_X86, UC_MODE_64, &uc);
    if (err != UC_ERR_OK) {
        printf("Failed on uc_open() with error returned: %u\n", err);
        abort();
    }

    // map 4MB memory for this emulation
    uc_mem_map(uc, ADDRESS, 4 * 1024 * 1024, UC_PROT_ALL);

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
