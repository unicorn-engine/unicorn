#include <unicorn/unicorn.h>
#include <stdio.h>
#include <stdlib.h>

#define ADDR 0x00400000
#define SIZE 1024*64
#define OVERFLOW 1

int main()
{
    uc_engine *uc = NULL;
    uint8_t *buf = NULL, *buf2 = NULL;
    int i;
    uc_err err;

    err = uc_open (UC_ARCH_X86, UC_MODE_64, &uc);
    if (err) {
        printf ("uc_open %d\n", err);
        goto exit;
    }
    err = uc_mem_map (uc, ADDR, SIZE, UC_PROT_ALL);
    if (err) {
        printf ("uc_mem_map %d\n", err);
        goto exit;
    }
    buf = calloc (SIZE*2, 1);
    buf2 = calloc (SIZE, 1);
    for (i=0;i<SIZE; i++) {
        buf[i] = i & 0xff;
    }
    /* crash here */
    err = uc_mem_write (uc, ADDR, buf, SIZE+OVERFLOW); 
    if (err) {
        printf ("uc_mem_write %d\n", err);
        goto exit;
    }
    err = uc_mem_read (uc, ADDR+10, buf2, 4);
    if (err) {
        printf ("uc_mem_read %d\n", err);
        goto exit;
    }
    if (buf2[0] != 0xa) {
        printf ("mem contents are wrong\n");
        goto exit;
    }
    printf ("OK\n");

exit:
    if (uc)
        uc_close (uc);
    free (buf);
    free (buf2);
    return err ? 1 : 0;
}
