#include <unicorn/unicorn.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#define UC_BUG_WRITE_SIZE 13000
#define UC_BUG_WRITE_ADDR 0x1000

int main()
{
    int size;
    uint8_t *buf;
    uc_engine *uc;
    uc_err err = uc_open (UC_ARCH_X86, UC_MODE_64, &uc);
    if (err) {
        fprintf (stderr, "Cannot initialize unicorn\n");
        return 1;
    }
    size = UC_BUG_WRITE_SIZE;
    buf = malloc (size);
    if (!buf) {
        fprintf (stderr, "Cannot allocate\n");
        return 1;
    }
    memset (buf, 0, size);
    if (!uc_mem_map (uc, UC_BUG_WRITE_ADDR, size, UC_PROT_ALL)) {
        uc_mem_write (uc, UC_BUG_WRITE_ADDR, buf, size);
    }
    uc_close(uc);
    free(buf);
    return 0;
}
