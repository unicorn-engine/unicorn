#include <unicorn/unicorn.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#define UC_BUG_WRITE_SIZE 128
#define UC_BUG_WRITE_ADDR 0x1000    // fix this by change this to 0x2000

int got_sigill = 0;

void _interrupt(uch handle, uint32_t intno, void *user_data)
{
    if (intno == 6) {
        uc_emu_stop (handle);
        got_sigill = 1;
    }
}

int main()
{
    int size;
    uint8_t *buf;
    uch uh;
    uch uh_trap;
    uc_err err = uc_open (UC_ARCH_X86, UC_MODE_64, &uh);
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
    if (!uc_mem_map (uh, UC_BUG_WRITE_ADDR, size)) {
        uc_mem_write (uh, UC_BUG_WRITE_ADDR,
                (const uint8_t*)"\xff\xff\xff\xff\xff\xff\xff\xff", 8);
    }
    uc_hook_add (uh, &uh_trap, UC_HOOK_INTR, _interrupt, NULL);
    uc_emu_start (uh, UC_BUG_WRITE_ADDR, UC_BUG_WRITE_ADDR+8, 0, 1);
    uc_close (&uh);
    printf ("Correct: %s\n", got_sigill? "YES": "NO");
    return got_sigill? 0: 1;
}
