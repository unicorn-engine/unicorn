#include "unicorn/unicorn.h"
#include <assert.h>
#include <stdio.h>


#define OK(x) {uc_err __err; if ((__err = x)) { fprintf(stderr, "%s", uc_strerror(__err)); assert(false); } }
static void test_vmovdqu(void)
{
    uc_engine *uc;

    int r_esi = 0x1234;
    int r_edi = 0x7890;

    uint64_t r_xmm0[2] = {0x08090a0b0c0d0e0f, 0x0001020304050607};

    /* 128 bit at address esi (0x1234) this should not be read into xmm0 */
    char mem_esi[] = { '\xE7', '\x1D', '\xA7', '\xE8', '\x88', '\xE4', '\x94', '\x40', '\x54', '\x74', '\x24', '\x97', '\x1F', '\x2E', '\xB6', '\x40' };

    /* 128 bit at address edi (0x7890) this SHOULD be read into xmm0 */
    char mem_edi[] = { '\xAD', '\xFA', '\x5C', '\x6D', '\x45', '\x4A', '\x93', '\x40', '\xD2', '\x00', '\xDE', '\x02', '\x89', '\xE8', '\x94', '\x40' };
    
    /* vmovdqu xmm0, [edi] */
    char code[] = { '\xC5', '\xFA', '\x6F', '\x07' };

    /* initialize memory and run emulation  */
    OK(uc_open(UC_ARCH_X86, UC_MODE_32, &uc));
    OK(uc_mem_map(uc, 0, 2 * 1024 * 1024, UC_PROT_ALL));

    OK(uc_mem_write(uc, 0, code, sizeof(code) / sizeof(code[0])));

    // initialize machine registers;
    OK(uc_reg_write(uc, UC_X86_REG_XMM0, &r_xmm0));
    
    OK(uc_reg_write(uc, UC_X86_REG_ESI, &r_esi));
    OK(uc_reg_write(uc, UC_X86_REG_EDI, &r_edi));
    OK(uc_mem_write(uc, r_esi, mem_esi, sizeof(mem_esi) / sizeof(mem_esi[0])));
    OK(uc_mem_write(uc, r_edi, mem_edi, sizeof(mem_edi) / sizeof(mem_edi[0])));

    OK(uc_emu_start(uc, 0, sizeof(code) / sizeof(code[0]), 0, 0));

    /* Read xmm0 after emulation */
    OK(uc_reg_read(uc, UC_X86_REG_XMM0, &r_xmm0));


    assert(0x4094e88902de00d2 == r_xmm0[0] && 0x40934a456d5cfaad == r_xmm0[1]);

    OK(uc_close(uc));
}


/* TODO: Add more vex prefixed instructions
         Suggestions: vxorpd, vxorps, vandpd, ... */
int main(int argc, char **argv, char **envp)
{
        test_vmovdqu();
        return 0;
}

