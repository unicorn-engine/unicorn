/*
Test for uc_emu_stop() in code hook not always stopping the emu at the current instruction.
(Sometimes it will execute and stop at the next instruction).
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


// Test MIPS little endian code.
// This should loop forever.
const uint64_t addr = 0x100000;
const unsigned char test_code[] = {
    0x00,0x00,0x00,0x00,	// 100000:	nop
    0x00,0x00,0x00,0x00,	// 100004:	nop
    0x00,0x00,0x00,0x00,	// 100008:	nop
    0x00,0x00,0x00,0x00,	// 10000C:	nop
};
bool test_passed_ok = false;


// This hook is used to show that code is executing in the emulator.
static void mips_codehook(uc_engine *uc, uint64_t address, uint32_t size, void *user_data)
{
    printf("Executing: %"PRIx64"\n", address);
    if( address == 0x100008 )
    {
        printf("Stopping at: %"PRIx64"\n", address);
        uc_emu_stop(uc);
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

    // write machine code to be emulated to memory
    printf("uc_mem_write()\n");
    err = uc_mem_write(uc, addr, test_code, sizeof(test_code));
    if( err )
    {
        printf("Failed on uc_mem_write() with error returned: %u\n", err);
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

    // start executing code
    printf("uc_emu_start()\n");
    uc_emu_start(uc, addr, addr+sizeof(test_code), 0, 0);


    // done executing, print some reg values as a test
    uc_reg_read(uc, UC_MIPS_REG_PC, &val);	printf("pc is %X\n", val);
    test_passed_ok = val == 0x100008;

    // free resources
    printf("uc_close()\n");
    uc_close(uc);

    if( test_passed_ok )
        printf("\n\nTEST PASSED!\n\n");
    else
        printf("\n\nTEST FAILED!\n\n");

    // dynamically free shared library
#ifdef DYNLOAD
    uc_dyn_free();
#endif

    return 0;
}

