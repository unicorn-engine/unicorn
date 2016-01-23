// 
// Simple code as an example for building apps with MSVC++ using the Unicorn Engine.
// 
// Zak Escano  -  December 2015
// 

// windows specific
#ifdef _MSC_VER
#include <io.h>
#include <windows.h>
#define PRIx64 "llX"
#ifdef DYNLOAD
#include "unicorn_dynload.h"
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
#endif // _MSC_VER


// Test MIPS little endian code.
// It should loop 3 times before ending.
const uint64_t addr = 0x100000;
const unsigned char loop_test_code[] = {
	0x02,0x00,0x04,0x24,	// 100000:	li      $a0, 2
	// loop1
	0x00,0x00,0x00,0x00,	// 100004:	nop
	0xFE,0xFF,0x80,0x14,	// 100008:	bnez    $a0, loop1
	0xFF,0xFF,0x84,0x24,	// 10000C:	addiu   $a0, -1
};
bool test_passed_ok = false;
int loop_count = 0;


static void mips_codehook(uc_engine *uc, uint64_t address, uint32_t size, void *user_data)
{
	if( address == 0x10000C )
		test_passed_ok = true;
	if( address == 0x100004 )
	{
		printf("\nloop %d:\n", loop_count);
		loop_count++;
	}
	printf("Code: %llX\n", address);
}


int main(int argc, char **argv, char **envp)
{
    uc_engine *uc;
    uc_err err;
	uc_hook hhc;
	uint32_t val;

	// dynamically load shared library
#ifdef DYNLOAD
	if( !uc_dyn_load(NULL, 0) )
	{
		printf("Error dynamically loading shared library.\n");
		printf("Please check that unicorn.dll/unicorn.so is available as well as\n");
		printf("any other dependent dll/so files.\n");
		printf("The easiest way is to place them in the same directory as this app.\n");
		return 1;
	}
#endif

	// Initialize emulator in MIPS 32bit little endian mode
    err = uc_open(UC_ARCH_MIPS, UC_MODE_MIPS32 | UC_MODE_LITTLE_ENDIAN, &uc);
    if (err)
	{
        printf("Failed on uc_open() with error returned: %u\n", err);
        return err;
    }

	// map in a page of mem
	err = uc_mem_map(uc, addr, 0x1000, UC_PROT_ALL);
    if (err)
	{
        printf("Failed on uc_mem_map() with error returned: %u\n", err);
        return err;
    }

	// write machine code to be emulated to memory
    err = uc_mem_write(uc, addr, loop_test_code, sizeof(loop_test_code));
	if( err )
	{
        printf("Failed on uc_mem_write() with error returned: %u\n", err);
        return err;
    }
	
    // hook all instructions by having @begin > @end
    uc_hook_add(uc, &hhc, UC_HOOK_CODE, mips_codehook, NULL, (uint64_t)1, (uint64_t)0);
	if( err )
	{
        printf("Failed on uc_hook_add(code) with error returned: %u\n", err);
        return err;
    }
	
    // execute code
	printf("---- Executing Code ----\n");
	err = uc_emu_start(uc, addr, addr + sizeof(loop_test_code), 0, 0);
    if (err)
	{
        printf("Failed on uc_emu_start() with error returned %u: %s\n",
                err, uc_strerror(err));
		return err;
    }

	// done executing, print some reg values as a test
	printf("---- Execution Complete ----\n\n");
	uc_reg_read(uc, UC_MIPS_REG_PC, &val);	printf("pc is %X\n", val);
	uc_reg_read(uc, UC_MIPS_REG_A0, &val);	printf("a0 is %X\n", val);
	
	// free resources
	uc_close(uc);
	
	// dynamically free shared library
#ifdef DYNLOAD
    uc_dyn_free();
#endif

	return 0;
}

