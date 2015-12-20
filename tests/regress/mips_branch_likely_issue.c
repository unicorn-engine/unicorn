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
#include <unistd.h>
#include <inttypes.h>
#include <unicorn/unicorn.h>
#include "pthread.h"
#endif // _MSC_VER

// common includes
#include <string.h>


const uint64_t addr = 0x100000;
// This code SHOULD execute the instruction at 0x10000C.
const unsigned char test_code_1[] = {
    0x01,0x00,0x02,0x24,	// 100000: li      $v0, 1
    0x02,0x00,0x03,0x24,	// 100004: li      $v1, 2
    0x01,0x00,0x62,0x54,	// 100008: bnel    $v1, $v0, 0x100010
    0x00,0x00,0x00,0x00,	// 10000C: nop
};
// This code SHOULD NOT execute the instruction at 0x10000C.
const unsigned char test_code_2[] = {
    0x01,0x00,0x02,0x24,	// 100000: li      $v0, 1
    0x01,0x00,0x03,0x24,	// 100004: li      $v1, 1
    0x01,0x00,0x62,0x54,	// 100008: bnel    $v1, $v0, 0x100010
    0x00,0x00,0x00,0x00,	// 10000C: nop
};
int test_num = 0;
bool test1_delayslot_executed = false;
bool test2_delayslot_executed = false;


// This hook is used to show that code is executing in the emulator.
static void mips_codehook(uc_engine *uc, uint64_t address, uint32_t size, void *user_data)
{
    printf("Test %d Executing: %llX\n", test_num, address);
    if( test_num == 1 && address == 0x10000C )
    {
        printf("Delay slot executed!\n");
        test1_delayslot_executed = true;
    }
    if( test_num == 2 && address == 0x10000C )
    {
        printf("Delay slot executed!\n");
        test2_delayslot_executed = true;
    }
}


int main(int argc, char **argv, char **envp)
{
    uc_engine *uc;
    uc_err err;
    uc_hook hhc;

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
    uc_hook_add(uc, &hhc, UC_HOOK_CODE, mips_codehook, NULL, (uint64_t)1, (uint64_t)0);
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


    // free resources
    printf("\nuc_close()\n");
    uc_close(uc);

    // print test results

    // test 1 SHOULD execute the instruction at 0x10000C.
    if( test1_delayslot_executed == true )
        printf("\n\nTEST 1 PASSED!\n");
    else
        printf("\n\nTEST 1 FAILED!\n");

    // test 2 SHOULD NOT execute the instruction at 0x10000C.
    if( test2_delayslot_executed == false )
        printf("TEST 2 PASSED!\n\n");
    else
        printf("TEST 2 FAILED!\n\n");

    // dynamically free shared library
#ifdef DYNLOAD
    uc_dyn_free();
#endif

    return 0;
}

