#include <unicorn/unicorn.h>
#include <stdio.h>

int main() {
    uc_engine *u;
    uc_err err;
    
    printf("mem_map_0x100000000.c \n");
    
    if ((err = uc_open(UC_ARCH_X86, UC_MODE_32, &u)) != UC_ERR_OK) {
        printf("uc_open() failed: %s\n", uc_strerror(err));
        return -1;
    }

    if ((err = uc_mem_map(u, 0x100000000, 0x002c0000, UC_PROT_ALL)) != UC_ERR_OK) {
        printf("uc_mem_map() failed: %s\n", uc_strerror(err));
        return -1;
    }
    if ((err = uc_mem_map(u, 0x0018D000, 0x00006000, UC_PROT_ALL)) != UC_ERR_OK) {
        printf("uc_mem_map() failed: %s\n", uc_strerror(err));
        return -1;
    }
    
    if ((err = uc_close(u)) != UC_ERR_OK) {
        printf("uc_close() failed: %s\n", uc_strerror(err));
        return -1;
    }
    
    printf("Success.\n");
    return 0;
}
