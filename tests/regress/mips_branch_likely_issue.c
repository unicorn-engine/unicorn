/*
   Test for MIPS branch likely instructions only executing their delay slot instruction when the branch is taken.
   Currently it seems to always execute the delay slot instruction like a normal non-"likely" style branch.
 */

// windows specific
#ifdef _MSC_VER
#include <io.h>
#include <windows.h>
#include <process.h>
#define PRIx64 "llX"
#ifdef DYNLOAD
#include <unicorn_dynload.h>
#else // DYNLOAD
#include <unicorn/unicorn.h>
#ifdef _WIN64
#pragma comment(lib, "unicorn_staload64.lib")
#else // _WIN64
#pragma comment(lib, "unicorn_staload.lib")
#endif // _WIN64
#endif // DYNLOAD

// posix specific
#else // _MSC_VER
#include <unicorn/unicorn.h>
#include "pthread.h"
#endif // _MSC_VER

// common includes
#include <string.h>


const uint64_t addr = 0x100000;
// This code SHOULD execute the instruction at 0x100010.
const unsigned char test_code_1[] = {
    0x00,0x00,0x04,0x24,	// 100000: li      $a0, 0
    0x01,0x00,0x02,0x24,	// 100004: li      $v0, 1
    0x02,0x00,0x03,0x24,	// 100008: li      $v1, 2
    0x01,0x00,0x62,0x54,	// 10000C: bnel    $v1, $v0, 0x100014
    0x21,0x20,0x62,0x00,	// 100010: addu    $a0, $v1, $v0
};
// This code SHOULD NOT execute the instruction at 0x100010.
const unsigned char test_code_2[] = {
    0x00,0x00,0x04,0x24,	// 100000: li      $a0, 0
    0x01,0x00,0x02,0x24,	// 100004: li      $v0, 1
    0x01,0x00,0x03,0x24,	// 100008: li      $v1, 1
    0x01,0x00,0x62,0x54,	// 10000C: bnel    $v1, $v0, 0x100014
    0x21,0x20,0x62,0x00,	// 100010: addu    $a0, $v1, $v0
};
int test_num = 0;
// flag for whether the delay slot was executed by the emulator
bool test1_delayslot_executed = false;
bool test2_delayslot_executed = false;
// flag for whether the delay slot had a code hook called for it
bool test1_delayslot_hooked = false;
bool test2_delayslot_hooked = false;


// This hook is used to show that code is executing in the emulator.
static void mips_codehook(uc_engine *uc, uint64_t address, uint32_t size, void *user_data)
{
    printf("Test %d Executing: %"PRIx64"\n", test_num, address);
    if( test_num == 1 && address == 0x100010 )
    {
        printf("Delay slot hook called!\n");
        test1_delayslot_hooked = true;
    }
    if( test_num == 2 && address == 0x100010 )
    {
        printf("Delay slot hook called!\n");
        test2_delayslot_hooked = true;
    }
}


int main(int argc, char **argv, char **envp)
{
    uc_engine *uc;
    uc_err err;
    uc_hook hhc;
    uint32_t val;

    // dynamically load shared library
#ifdef DYNLOAD
    uc_dyn_load(NULL, 0);
#endif

    // Initialize emulator in MIPS 32bit little endian mode
    printf("uc_open()\n");
    err = uc_open(UC_ARCH_MIPS, UC_MODE_MIPS32, &uc);
    if (err)
    {
        printf("Failed on uc_open() with error returned: %u\n", err);
        return err;
    }

    // map in a page of mem
    printf("uc_mem_map()\n");
    err = uc_mem_map(uc, addr, 0x1000, UC_PROT_ALL);
    if (err)
    {
        printf("Failed on uc_mem_map() with error returned: %u\n", err);
        return err;
    }

    // hook all instructions by having @begin > @end
    printf("uc_hook_add()\n");
    uc_hook_add(uc, &hhc, UC_HOOK_CODE, mips_codehook, NULL, 1, 0);
    if( err )
    {
        printf("Failed on uc_hook_add(code) with error returned: %u\n", err);
        return err;
    }


    // write test1 code to be emulated to memory
    test_num = 1;
    printf("\nuc_mem_write(1)\n");
    err = uc_mem_write(uc, addr, test_code_1, sizeof(test_code_1));
    if( err )
    {
        printf("Failed on uc_mem_write() with error returned: %u\n", err);
        return err;
    }
    // start executing test code 1
    printf("uc_emu_start(1)\n");
    uc_emu_start(uc, addr, addr+sizeof(test_code_1), 0, 0);
    // read the value from a0 when finished executing
    uc_reg_read(uc, UC_MIPS_REG_A0, &val);	printf("a0 is %X\n", val);
    if( val != 0 )
        test1_delayslot_executed = true;


    // write test2 code to be emulated to memory
    test_num = 2;
    printf("\nuc_mem_write(2)\n");
    err = uc_mem_write(uc, addr, test_code_2, sizeof(test_code_2));
    if( err )
    {
        printf("Failed on uc_mem_write() with error returned: %u\n", err);
        return err;
    }
    // start executing test code 2
    printf("uc_emu_start(2)\n");
    uc_emu_start(uc, addr, addr+sizeof(test_code_2), 0, 0);
    // read the value from a0 when finished executing
    uc_reg_read(uc, UC_MIPS_REG_A0, &val);	printf("a0 is %X\n", val);
    if( val != 0 )
        test2_delayslot_executed = true;


    // free resources
    printf("\nuc_close()\n");
    uc_close(uc);


    // print test results
    printf("\n\nTest 1 SHOULD execute the delay slot instruction:\n");
    printf("  Emulator %s execute the delay slot:  %s\n",
            test1_delayslot_executed ? "did" : "did not",
            test1_delayslot_executed ? "CORRECT" : "WRONG");
    printf("  Emulator %s hook the delay slot:  %s\n",
            test1_delayslot_hooked ? "did" : "did not",
            test1_delayslot_hooked ? "CORRECT" : "WRONG");

    printf("\n\nTest 2 SHOULD NOT execute the delay slot instruction:\n");
    printf("  Emulator %s execute the delay slot:  %s\n",
            test2_delayslot_executed ? "did" : "did not",
            !test2_delayslot_executed ? "CORRECT" : "WRONG");
    printf("  Emulator %s hook the delay slot:  %s\n",
            test2_delayslot_hooked ? "did" : "did not",
            !test2_delayslot_hooked ? "CORRECT" : "WRONG");


    // test 1 SHOULD execute the instruction in the delay slot
    if( test1_delayslot_hooked == true && test1_delayslot_executed == true )
        printf("\n\nTEST 1 PASSED!\n");
    else
        printf("\n\nTEST 1 FAILED!\n");

    // test 2 SHOULD NOT execute the instruction in the delay slot
    if( test2_delayslot_hooked == false && test2_delayslot_executed == false )
        printf("TEST 2 PASSED!\n\n");
    else
        printf("TEST 2 FAILED!\n\n");


    // dynamically free shared library
#ifdef DYNLOAD
    uc_dyn_free();
#endif

    return 0;
}

