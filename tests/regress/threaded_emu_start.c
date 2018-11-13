/*
Test for uc_open() and uc_emu_start() being called by different threads.

This code will call uc_open() in the main thread and then attempt
to call uc_emu_start() from its own thread. This would enable the emulator
to run in the background while you do other things like handle user interface
etc in the foreground.

Currently "uc->qemu_global_mutex" is locked by uc_open() and unlocked
by uc_emu_start(). This is a problem because the mutex implementation
must be locked and unlocked by the same thread. This means that uc_open()
and uc_emu_start() must be executed in the same thread. This is an unnecessary
limitation which prevents the emulator from being able to be executed in the
background.
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

// for win32 threads in mingw
#ifdef _WIN32
#include <windows.h>
#endif

// common includes
#include <string.h>


// Test MIPS little endian code.
// This should loop forever.
const uint64_t addr = 0x100000;
const unsigned char loop_test_code[] = {
    0x02,0x00,0x04,0x24,	// 100000:	li      $a0, 2
    // loop1
    0x00,0x00,0x00,0x00,	// 100004:	nop
    0xFE,0xFF,0x80,0x14,	// 100008:	bnez    $a0, loop1
    0x00,0x00,0x00,0x00,	// 10000C:	nop
};
bool test_passed_ok = false;
int loop_count = 0;


// This hook is used to show that code is executing in the emulator.
static void mips_codehook(uc_engine *uc, uint64_t address, uint32_t size, void *user_data)
{
    printf("Code: %"PRIx64"\n", address);
}


typedef struct {
    uc_engine *uc;
    uint64_t startAddr;
    uint64_t endAddr;
} EmuStarterParam_t;

// This is a thread that just runs uc_emu_start() in it.
// The code that it is executing in this case will run forever until it is stopped by uc_emu_stop().
static uc_err emu_starter(void* param)
{
    uc_engine *uc;
    uint64_t start_addr;
    uint64_t end_addr;
    uc_err err;
    
    EmuStarterParam_t* starter_params = (EmuStarterParam_t *)param;
    uc = starter_params->uc;
    start_addr = starter_params->startAddr;
    end_addr = starter_params->endAddr;
    
    printf("uc_emu_start()\n");
    err = uc_emu_start(uc, start_addr, end_addr, 0, 0);
    if (err)
    {
        printf("Failed on uc_emu_start() with error returned %u: %s\n",
                err, uc_strerror(err));
    }

    return err;
}

#ifdef _WIN32
static unsigned int __stdcall win32_emu_starter(void* param)
{
    uc_err err = emu_starter(param);
    _endthreadex(err);
    return err;
}
#else
static void* posix_emu_starter(void* param)
{
    uc_err err = emu_starter(param);
    return (void*)err;
}
#endif


int main(int argc, char **argv, char **envp)
{
    uc_engine *uc;
    uc_err err;
    int ret;
    uc_hook hhc;
    uint32_t val;
    EmuStarterParam_t starter_params;
#ifdef _WIN32
    HANDLE th = (HANDLE)-1;
#else
    pthread_t th;
#endif

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
    err = uc_mem_write(uc, addr, loop_test_code, sizeof(loop_test_code));
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
    
    
    // start background thread
    printf("---- Thread Starting ----\n");
    starter_params.uc = uc;
    starter_params.startAddr = addr;
    starter_params.endAddr = addr + sizeof(loop_test_code);

#ifdef _WIN32
    // create thread
    th = (HANDLE)_beginthreadex(NULL, 0, win32_emu_starter, &starter_params, CREATE_SUSPENDED, NULL);
    if(th == (HANDLE)-1)
    {
        printf("Failed on _beginthreadex() with error returned: %p\n", _errno());
        return -1;
    }
    // start thread
    ret = ResumeThread(th);
    if( ret == -1 )
    {
        printf("Failed on ResumeThread() with error returned: %p\n", _errno());
        return -2;
    }
    // wait 3 seconds
    Sleep(3 * 1000);
#else
    // add posix code to start the emu_starter() thread
    ret = pthread_create(&th, NULL, posix_emu_starter, &starter_params);
    if( ret )
    {
        printf("Failed on pthread_create() with error returned: %u\n", err);
        return -2;
    }
    // wait 3 seconds
    sleep(3);
#endif


    // Stop the thread after it has been let to run in the background for a while
    printf("---- Thread Stopping ----\n");
    printf("uc_emu_stop()\n");
    err = uc_emu_stop(uc);
    if( err )
    {
        printf("Failed on uc_emu_stop() with error returned: %u\n", err);
        return err;
    }
    test_passed_ok = true;
    

    // done executing, print some reg values as a test
    uc_reg_read(uc, UC_MIPS_REG_PC, &val);	printf("pc is %X\n", val);
    uc_reg_read(uc, UC_MIPS_REG_A0, &val);	printf("a0 is %X\n", val);
    
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

