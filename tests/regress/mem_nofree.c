#include <stdlib.h>
#include <stdio.h>

#include <unicorn/unicorn.h>

#define ADDRESS1 0x10000000
#define ADDRESS2 0x20000000
#define SIZE (80 * 1024 * 1024)

static void VM_exec()
{
    int c;
    uc_engine *uc;
    uc_err err;

    // Initialize emulator in X86-64bit mode
    err = uc_open(UC_ARCH_X86, UC_MODE_32, &uc);
    if(err)
    {
        printf("Failed on uc_open() with error returned: %s\n", uc_strerror(err));
        return;
    }

repeat:
    err = uc_mem_map(uc, ADDRESS1, SIZE, UC_PROT_ALL);
    if(err != UC_ERR_OK)
    {
        printf("Failed to map memory %s\n", uc_strerror(err));
        goto err;
    }

    err = uc_mem_map(uc, ADDRESS2, SIZE, UC_PROT_ALL);
    if(err != UC_ERR_OK)
    {
        printf("Failed to map memory %s\n", uc_strerror(err));
        goto err;
    }

    err = uc_mem_unmap(uc, ADDRESS1, SIZE);
    if(err != UC_ERR_OK)
    {
        printf("Failed to unmap memory %s\n", uc_strerror(err));
        goto err;
    }

    err = uc_mem_unmap(uc, ADDRESS2, SIZE);
    if(err != UC_ERR_OK)
    {
        printf("Failed to unmap memory %s\n", uc_strerror(err));
        goto err;
    }

    for(;;)
    {
        c = getchar(); //pause here and analyse memory usage before exiting with a program like VMMap;
        if(c != 'e')
            goto repeat;
        else
            break;
    }

err:
    uc_close(uc);
}

int main(int argc, char *argv[])
{
    VM_exec();
    return 0;
}
