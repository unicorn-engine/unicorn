#define __STDC_FORMAT_MACROS
#include <string.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <unicorn/unicorn.h>

int main(int argc, char **argv, char **envp)
{
    uc_engine *uc;
    uc_err err;

    // Initialize emulator in X86-32bit mode
    err = uc_open(UC_ARCH_X86, UC_MODE_32, &uc);
    if (err) {
        printf("not ok - Failed on uc_open() with error returned: %u\n", err);
        return -1;
    }

    uc_mem_map(uc, 0x1000, 0x1000, UC_PROT_ALL);
    if (err) {
        printf("not ok - Failed on uc_mem_map() with error returned: %u\n", err);
        return -1;
    }

    uc_mem_map(uc, 0x4000, 0x1000, UC_PROT_ALL);
    if (err) {
        printf("not ok - Failed on uc_mem_map() with error returned: %u\n", err);
        return -1;
    }

    err = uc_mem_unmap(uc, 0x4000, 0x1000);
    if (err) {
        printf("not ok - Failed on uc_mem_unmap() with error returned: %u\n", err);
        return -1;
    }

    err = uc_mem_unmap(uc, 0x4000, 0x1000);
    if (!err) {
        printf("not ok - second unmap succeeded\n");
        return -1;
    }

    printf("Tests OK\n");
    uc_close(uc);
    return 0;
}
