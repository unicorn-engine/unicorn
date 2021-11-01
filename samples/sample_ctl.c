/* Unicorn Emulator Engine */
/* By Lazymio(@wtdcode), 2021 */

/* Sample code to demonstrate how to use uc_ctl */

#include <unicorn/unicorn.h>
#include <string.h>

// code to be emulated
#define X86_CODE32 "\x41\x4a" // INC ecx; DEC edx; PXOR xmm0, xmm1

// memory address where emulation starts
#define ADDRESS 0x10000

static void test_uc_ctl_read(void)
{
    uc_engine *uc;
    uc_err err;
    uint32_t tmp;
    uc_hook trace1, trace2;
    int mode, arch;
    uint32_t pagesize;
    uint64_t timeout;

    int r_ecx = 0x1234; // ECX register
    int r_edx = 0x7890; // EDX register

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

int main(int argc, char **argv, char **envp)
{
    test_uc_ctl_read();

    return 0;
}
