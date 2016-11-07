#include <unicorn/unicorn.h>
#include <stdio.h>

int main() {
    uc_engine *u;
    uc_err err;
    if ((err = uc_open(UC_ARCH_X86, UC_MODE_32, &u)) != UC_ERR_OK) {
        printf("uc_open() failed: %s\n", uc_strerror(err));
    }
    printf("Trying large map.\n");
    if ((err = uc_mem_map(u, 0x60802000, (unsigned) 0x28bd211200004000, UC_PROT_ALL)) != UC_ERR_OK) {
        printf("uc_mem_map() failed: %s\n", uc_strerror(err));
        return -1;
    }
    printf("Success.\n");
    return 0;
}
