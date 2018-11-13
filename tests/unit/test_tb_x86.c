/**
 * Unicorn x86_32 self-modifying unit test
 *
 * This test demonstrates the flushing of instruction translation cache
 * after a self-modification of Intel's x8's "IMUL Gv,Ev,Ib" instruction.
 */
#include "unicorn_test.h"
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include "unicorn/unicorn.h"

#define RIP_NEXT_TO_THE_SELFMODIFY_OPCODE (1)


//  Demostration of a self-modifying "IMUL eax,mem,Ib" opcode
//  And the QEMU's ability to flush the translation buffer properly

#define MIN(a, b) (a < b? a: b)

#define CODE_SPACE (2 * 1024 * 1024)
#define PHY_STACK_REGION (0x60000000)

/* Called before every test to set up a new instance */
static int setup(void **state)
{
    uc_engine *uc;

    uc_assert_success(uc_open(UC_ARCH_X86, UC_MODE_64, &uc));

    *state = uc;
    return 0;
}


/* Called after every test to clean up */
static int teardown(void **state)
{
    uc_engine *uc = *state;

    uc_assert_success(uc_close(uc));

    *state = NULL;
    return 0;
}



static void dump_stack_mem(uc_engine *uc, const struct stat info)
{
    uint8_t tmp[256];
    uint32_t size;

    size = sizeof(info.st_size);
    if (size > 255) size = 255;
    if (!uc_mem_read(uc, PHY_STACK_REGION, tmp, size)) 
    {
        uint32_t i;

        printf("Stack region dump");
        for (i=0; i<size; i++) {
            if ((i % 16) == 0) printf("\n%x: ", PHY_STACK_REGION+i);
            printf("%x ", tmp[i]);
        }
        printf("\n");
    }
}

static void print_registers(uc_engine *uc)
{
    int32_t eax, ecx, edx, ebx;
    int32_t esp, ebp, esi, edi;
    uc_reg_read(uc, UC_X86_REG_EAX, &eax);
    uc_reg_read(uc, UC_X86_REG_ECX, &ecx);
    uc_reg_read(uc, UC_X86_REG_EDX, &edx);
    uc_reg_read(uc, UC_X86_REG_EBX, &ebx);
    uc_reg_read(uc, UC_X86_REG_ESP, &esp);
    uc_reg_read(uc, UC_X86_REG_EBP, &ebp);
    uc_reg_read(uc, UC_X86_REG_ESI, &esi);
    uc_reg_read(uc, UC_X86_REG_EDI, &edi);

    printf("Register dump:\n");
    printf("eax %8.8x ", eax);
    printf("ecx %8.8x ", ecx);
    printf("edx %8.8x ", edx);
    printf("ebx %8.8x\n", ebx);
    printf("esp %8.8x ", esp);
    printf("ebp %8.8x ", ebp);
    printf("esi %8.8x ", esi);
    printf("edi %8.8x ", edi);
    printf("\n");
}


static void hook_code32(uc_engine *uc, 
                        uint64_t address, 
                        uint32_t size, 
                        void *user_data,
                        const struct stat info)
{
    //uint8_t opcode[256];
    uint8_t tmp[16];
    uint32_t tmp4[1];
    uint32_t ecx;

    printf("\nhook_code32: Address: %"PRIx64", Opcode Size: %d\n", address, size);
    print_registers(uc);
    size = MIN(sizeof(tmp), size);
    if (!uc_mem_read(uc, address, tmp, size)) 
    {
        uint32_t i;

        printf("Opcode: ");
        for (i=0; i<size; i++) {
            printf("%x ", tmp[i]);
        }
        printf("\n");
    }
    dump_stack_mem(uc, info);


    if (address == 0x60000025)
    {
        //  double-check that opcode is
        //      IMUL aex,[eax+0x41],0x10
        if ((tmp[0] != 0x6b) ||
            (tmp[1] != 0x41) ||
            (tmp[2] != 0x41) ||
            (tmp[3] != 0x10))
        {
            printf("FAILED set-up of opcode\n");
            exit(-1);
        }
        printf("IMUL eax,[ecx+0x41],0x10\n");

        //  double-check that memory operand points to 0x6000003a
        uc_reg_read(uc, UC_X86_REG_ECX, &ecx);
        if (ecx != 0x5ffffff9)
        {
            printf("FAILED EAX register not having 0x5ffffff9\n");
            exit(-1);
        }
        printf("ECX = %8.8x\n", ecx);

        printf("%8.8x + 0x41 = %8.8x\n", 0x5ffffff9, 0x5ffffff9 + 0x41);

        //  double-check that memory location 0x60000039
        //  contains 0x5151494a
        if (!uc_mem_read(uc, 0x6000003a, tmp4, 4)) 
        {
            if (tmp4[0] != 0x5151494a)
            {
                printf("FAILED set-up\n");
                exit(-1);
            }
            printf("Proved that 0x6000003a contains the proper 0x5151494a\n");
        }
    //    dump_stack_mem(uc);
    }

    // Stop after 'imul eax,[ecx+0x41],0x10
    if (address == 0x60000029)
    {
        uint32_t eax;
        // IMUL eax,mem,Ib
        // mem = [ecx+0x41]
        // ecx = 0x5ffffff9
        // [6000003A] = 0x5151494a
        // Stop after 'imul eax,[ecx+0x41],0x10
        // This step basically shifts left 8-bit...elaborately.
        // multiplying 0x5151494a x 0x10 = 0x151494a0
        uc_reg_read(uc, UC_X86_REG_EAX, &eax);
        if (eax != 0x151494a0)
        {
            fail_msg("FAIL: TB did not flush; eax is not the expected 0x151494a0\n");
            print_registers(uc);
            //dump_stack_mem(uc);
            exit(-1);
        }
        printf("PASS\n");
    }
    print_registers(uc);
    // dump_stack_mem(uc);
      
    return;
}

static void hook_mem32(uc_engine *uc, 
                       uc_mem_type type, 
                       uint64_t address, 
                       int size, 
                       uint64_t value, 
                       void *user_data)
{
    char ctype;
    //uint32_t tmp[1];

    ctype = '?';
    if (type == UC_MEM_READ) ctype = 'R';
    if (type == UC_MEM_WRITE) ctype = 'W';
    printf("hook_mem32(%c): Address: 0x%"PRIx64", Size: %d, Value:0x%"PRIx64"\n", ctype, address, size, value);

    // if (!uc_mem_read(uc, 0x6000003a, tmp, 4)) 
    // {
        // printf("  hook_mem32  0x6000003a: %8.8x\n", tmp[0]);
    // }
    return;
}


static void test_tb_x86_64_32_imul_Gv_Ev_Ib(void **state)
{
    uc_engine *uc = *state;
    uc_hook trace1, trace2;
    struct stat info;
    char * code = read_file("tb_x86.bin", &info);
    //void *mem;
#ifdef RIP_NEXT_TO_THE_SELFMODIFY_OPCODE
    // These values assumes just before PC = 0x60000021
    int64_t eax = 0x00000041;
    int64_t ecx = 0x5ffffff8;
    int64_t edx = 0x5ffffff8;
    int64_t ebx = 0x034a129b;
    int64_t esp = 0x6010229a;
    int64_t ebp = 0x60000002;
    int64_t esi = 0x1f350211;
    int64_t edi = 0x488ac239;
#else
    //  These values assumes PC == 0x6000000
    int64_t eax = 0x73952c43;
    int64_t ecx = 0x6010229a;
    int64_t edx = 0x2a500e50;
    int64_t ebx = 0x034a1295;
    int64_t esp = 0x6010229a;
    int64_t ebp = 0x60000000;
    int64_t esi = 0x1f350211;
    int64_t edi = 0x488ac239;
#endif

    //mem = calloc(1, CODE_SPACE);
    // TODO examine
    //assert_int_not_equal(0, mem);

    uc_assert_success(uc_open(UC_ARCH_X86, 
                              UC_MODE_32, 
                              &uc));
    uc_assert_success(uc_mem_map(uc, 
                                 PHY_STACK_REGION, 
                                 CODE_SPACE, 
                                 UC_PROT_ALL));
    uc_assert_success(uc_mem_write(uc,
                                   PHY_STACK_REGION,
                                   code,
                                   info.st_size));
    uc_assert_success(uc_reg_write(uc, UC_X86_REG_EAX, &eax));
    uc_assert_success(uc_reg_write(uc, UC_X86_REG_ECX, &ecx));
    uc_assert_success(uc_reg_write(uc, UC_X86_REG_EDX, &edx));
    uc_assert_success(uc_reg_write(uc, UC_X86_REG_EBX, &ebx));
    uc_assert_success(uc_reg_write(uc, UC_X86_REG_ESP, &esp));
    uc_assert_success(uc_reg_write(uc, UC_X86_REG_EBP, &ebp));
    uc_assert_success(uc_reg_write(uc, UC_X86_REG_ESI, &esi));
    uc_assert_success(uc_reg_write(uc, UC_X86_REG_EDI, &edi));

    uc_assert_success(uc_hook_add(uc,
                &trace1,
                UC_HOOK_CODE,
                hook_code32,
                NULL,
                1,
                0,
                info));

    uc_assert_success(uc_hook_add(uc,
                &trace2,
                UC_HOOK_MEM_VALID,
                hook_mem32,
                NULL,
                1,
                0));

    uc_assert_success(uc_emu_start(uc,
#ifdef RIP_NEXT_TO_THE_SELFMODIFY_OPCODE
    //  Register set (before self-modifying IMUL opcode)
    //  Start at "0x00000021: xorb   %al, 0x30(%ecx)
    //  Start at "0x00000021: xor    byte ptr [ecx + 0x30], al
                       PHY_STACK_REGION+0x0021,   //  0x0024 didn't work
#else
                       PHY_STACK_REGION+0x0000,
#endif
                       PHY_STACK_REGION+info.st_size,
                       0, 0));

    uc_assert_success(uc_close(uc));
}

int
main(void)
{
#define test(x)	cmocka_unit_test_setup_teardown(x, setup, teardown)
    const struct CMUnitTest tests[] = {
        test(test_tb_x86_64_32_imul_Gv_Ev_Ib)
    };
#undef test
    return cmocka_run_group_tests(tests, NULL, NULL);
}
