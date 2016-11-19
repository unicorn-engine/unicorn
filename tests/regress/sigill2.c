#include <unicorn/unicorn.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#define UC_BUG_WRITE_SIZE 128
#define UC_BUG_WRITE_ADDR 0x2000

int main()
{
    int size;
    uc_engine *uc;

    uc_err err = uc_open (UC_ARCH_X86, UC_MODE_64, &uc);
    if (err) {
        fprintf (stderr, "Cannot initialize unicorn\n");
        return 1;
    }
    size = UC_BUG_WRITE_SIZE;
    if (!uc_mem_map (uc, UC_BUG_WRITE_ADDR, size, UC_PROT_ALL)) {
        uc_mem_write (uc, UC_BUG_WRITE_ADDR,
                (const uint8_t*)"\xff\xff\xff\xff\xff\xff\xff\xff", 8);
    }
    err = uc_emu_start(uc, UC_BUG_WRITE_ADDR, UC_BUG_WRITE_ADDR+8, 0, 1);
    uc_close(uc);
    printf ("Error = %u (%s)\n", err, uc_strerror(err));
    return err? -1: 0;
}
