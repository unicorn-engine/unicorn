/* Unicorn Emulator Engine */
/* By Nguyen Anh Quynh <aquynh@gmail.com>, 2015 */

#ifndef UNICORN_ENGINE_H
#define UNICORN_ENGINE_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include <stdarg.h>
#if defined(UNICORN_HAS_OSXKERNEL)
#include <libkern/libkern.h>
#else
#include <stdlib.h>
#include <stdio.h>
#endif

#include "platform.h"

// Handle to use with all APIs
typedef size_t uch;

#include "m68k.h"
#include "x86.h"
#include "arm.h"
#include "arm64.h"
#include "mips.h"
#include "sparc.h"

#ifdef _MSC_VER
#pragma warning(disable:4201)
#pragma warning(disable:4100)
#ifdef UNICORN_SHARED
#define UNICORN_EXPORT __declspec(dllexport)
#else    // defined(UNICORN_STATIC)
#define UNICORN_EXPORT
#endif
#else
#ifdef __GNUC__
#define UNICORN_EXPORT __attribute__((visibility("default")))
#else
#define UNICORN_EXPORT
#endif
#endif

#ifdef __GNUC__
#define UNICORN_DEPRECATED __attribute__((deprecated))
#elif defined(_MSC_VER)
#define UNICORN_DEPRECATED __declspec(deprecated)
#else
#pragma message("WARNING: You need to implement UNICORN_DEPRECATED for this compiler")
#define UNICORN_DEPRECATED
#endif

// Unicorn API version
#define UC_API_MAJOR 0
#define UC_API_MINOR 9

// Macro to create combined version which can be compared to
// result of uc_version() API.
#define UC_MAKE_VERSION(major, minor) ((major << 8) + minor)

// Scales to calculate timeout on microsecond unit
// 1 second = 1000,000 microseconds
#define UC_SECOND_SCALE 1000000
// 1 milisecond = 1000 nanoseconds
#define UC_MILISECOND_SCALE 1000

// Architecture type
typedef enum uc_arch {
    UC_ARCH_ARM = 1,    // ARM architecture (including Thumb, Thumb-2)
    UC_ARCH_ARM64,      // ARM-64, also called AArch64
    UC_ARCH_MIPS,       // Mips architecture
    UC_ARCH_X86,        // X86 architecture (including x86 & x86-64)
    UC_ARCH_PPC,        // PowerPC architecture
    UC_ARCH_SPARC,      // Sparc architecture
    UC_ARCH_M68K,       // M68K architecture
    UC_ARCH_MAX,
} uc_arch;

// Mode type
typedef enum uc_mode {
    UC_MODE_LITTLE_ENDIAN = 0,  // little-endian mode (default mode)
    UC_MODE_ARM = 0,    // 32-bit ARM
    UC_MODE_16 = 1 << 1,    // 16-bit mode (X86)
    UC_MODE_32 = 1 << 2,    // 32-bit mode (X86)
    UC_MODE_64 = 1 << 3,    // 64-bit mode (X86, PPC)
    UC_MODE_THUMB = 1 << 4, // ARM's Thumb mode, including Thumb-2
    UC_MODE_MCLASS = 1 << 5,    // ARM's Cortex-M series
    UC_MODE_V8 = 1 << 6,    // ARMv8 A32 encodings for ARM
    UC_MODE_MICRO = 1 << 4, // MicroMips mode (MIPS)
    UC_MODE_MIPS3 = 1 << 5, // Mips III ISA
    UC_MODE_MIPS32R6 = 1 << 6, // Mips32r6 ISA
    UC_MODE_V9 = 1 << 4, // SparcV9 mode (Sparc)
    UC_MODE_QPX = 1 << 4, // Quad Processing eXtensions mode (PPC)
    UC_MODE_BIG_ENDIAN = 1 << 31,   // big-endian mode
    UC_MODE_MIPS32 = UC_MODE_32,    // Mips32 ISA (Mips)
    UC_MODE_MIPS64 = UC_MODE_64,    // Mips64 ISA (Mips)
} uc_mode;

// All type of errors encountered by Unicorn API.
// These are values returned by uc_errno()
typedef enum uc_err {
    UC_ERR_OK = 0,   // No error: everything was fine
    UC_ERR_OOM,      // Out-Of-Memory error: uc_open(), uc_emulate()
    UC_ERR_ARCH,     // Unsupported architecture: uc_open()
    UC_ERR_HANDLE,   // Invalid handle
    UC_ERR_UCH,      // Invalid handle (uch)
    UC_ERR_MODE,     // Invalid/unsupported mode: uc_open()
    UC_ERR_VERSION,  // Unsupported version (bindings)
    UC_ERR_MEM_READ, // Quit emulation due to invalid memory READ: uc_emu_start()
    UC_ERR_MEM_WRITE, // Quit emulation due to invalid memory WRITE: uc_emu_start()
    UC_ERR_CODE_INVALID, // Quit emulation due to invalid code address: uc_emu_start()
    UC_ERR_HOOK,    // Invalid hook type: uc_hook_add()
    UC_ERR_INSN_INVALID, // Quit emulation due to invalid instruction: uc_emu_start()
    UC_ERR_MAP, // Invalid memory mapping: uc_mem_map()
} uc_err;


// Callback function for tracing code (UC_HOOK_CODE & UC_HOOK_BLOCK)
// @address: address where the code is being executed
// @size: size of machine instruction(s) being executed, or 0 when size is unknown
// @user_data: user data passed to tracing APIs.
typedef void (*uc_cb_hookcode_t)(uch handle, uint64_t address, uint32_t size, void *user_data);

// Callback function for tracing interrupts (for uc_hook_intr())
// @intno: interrupt number
// @user_data: user data passed to tracing APIs.
typedef void (*uc_cb_hookintr_t)(uch handle, uint32_t intno, void *user_data);

// Callback function for tracing IN instruction of X86
// @port: port number
// @size: data size (1/2/4) to be read from this port
// @user_data: user data passed to tracing APIs.
typedef uint32_t (*uc_cb_insn_in_t)(uch handle, uint32_t port, int size, void *user_data);

// x86's handler for OUT
// @port: port number
// @size: data size (1/2/4) to be written to this port
// @value: data value to be written to this port
typedef void (*uc_cb_insn_out_t)(uch handle, uint32_t port, int size, uint32_t value, void *user_data);

// All type of memory accesses for UC_HOOK_MEM_*
typedef enum uc_mem_type {
    UC_MEM_READ = 16,   // Memory is read from
    UC_MEM_WRITE,       // Memory is written to
    UC_MEM_READ_WRITE,  // Memory is accessed (either READ or WRITE)
} uc_mem_type;

// All type of hooks for uc_hook_add() API.
typedef enum uc_hook_t {
    UC_HOOK_INTR = 32,      // Hook all interrupt events
    UC_HOOK_INSN,           // Hook a particular instruction
    UC_HOOK_CODE,           // Hook a range of code
    UC_HOOK_BLOCK,          // Hook basic blocks
    UC_HOOK_MEM_INVALID,    // Hook for all invalid memory access events
    UC_HOOK_MEM_READ,       // Hook all memory read events.
    UC_HOOK_MEM_WRITE,      // Hook all memory write events.
    UC_HOOK_MEM_READ_WRITE, // Hook all memory accesses (either READ or WRITE).
} uc_hook_t;

// Callback function for hooking memory (UC_HOOK_MEM_*)
// @type: this memory is being READ, or WRITE
// @address: address where the code is being executed
// @size: size of data being read or written
// @value: value of data being written to memory, or irrelevant if type = READ.
// @user_data: user data passed to tracing APIs
typedef void (*uc_cb_hookmem_t)(uch handle, uc_mem_type type,
        uint64_t address, int size, int64_t value, void *user_data);

// Callback function for handling memory events (for UC_HOOK_MEM_INVALID)
// @type: this memory is being READ, or WRITE
// @address: address where the code is being executed
// @size: size of data being read or written
// @value: value of data being written to memory, or irrelevant if type = READ.
// @user_data: user data passed to tracing APIs
// @return: return true to continue, or false to stop program (due to invalid memory).
typedef bool (*uc_cb_eventmem_t)(uch handle, uc_mem_type type,
        uint64_t address, int size, int64_t value, void *user_data);


/*
 Return combined API version & major and minor version numbers.

 @major: major number of API version
 @minor: minor number of API version

 @return hexical number as (major << 8 | minor), which encodes both
     major & minor versions.
     NOTE: This returned value can be compared with version number made
     with macro UC_MAKE_VERSION

 For example, second API version would return 1 in @major, and 1 in @minor
 The return value would be 0x0101

 NOTE: if you only care about returned value, but not major and minor values,
 set both @major & @minor arguments to NULL.
*/
UNICORN_EXPORT
unsigned int uc_version(unsigned int *major, unsigned int *minor);


/*
 Determine if the given architecture is supported by this library.

 @arch: architecture type (UC_ARCH_*)

 @return True if this library supports the given arch.
*/
UNICORN_EXPORT
bool uc_arch_supported(uc_arch arch);


/*
 Initialize UC handle: this must be done before any usage of UC.

 @arch: architecture type (UC_ARCH_*)
 @mode: hardware mode. This is combined of UC_MODE_*
 @handle: pointer to handle, which will be updated at return time

 @return UC_ERR_OK on success, or other value on failure (refer to uc_err enum
 for detailed error).
*/
UNICORN_EXPORT
uc_err uc_open(uc_arch arch, uc_mode mode, uch *handle);

/*
 Close UC handle: MUST do to release the handle when it is not used anymore.
 NOTE: this must be called only when there is no longer usage of Unicorn.
 The reason is the this API releases some cached memory, thus access to any
 Unicorn API after uc_close() might crash your application.
 After this, @handle is invalid, and nolonger usable.

 @handle: pointer to a handle returned by uc_open()

 @return UC_ERR_OK on success, or other value on failure (refer to uc_err enum
 for detailed error).
*/
UNICORN_EXPORT
uc_err uc_close(uch *handle);

/*
 Report the last error number when some API function fail.
 Like glibc's errno, uc_errno might not retain its old value once accessed.

 @handle: handle returned by uc_open()

 @return: error code of uc_err enum type (UC_ERR_*, see above)
*/
UNICORN_EXPORT
uc_err uc_errno(uch handle);

/*
 Return a string describing given error code.

 @code: error code (see UC_ERR_* above)

 @return: returns a pointer to a string that describes the error code
 passed in the argument @code
 */
UNICORN_EXPORT
const char *uc_strerror(uc_err code);

/*
 Write to register.

 @handle: handle returned by uc_open()
 @regid:  register ID that is to be modified.
 @value:  pointer to the value that will set to register @regid

 @return UC_ERR_OK on success, or other value on failure (refer to uc_err enum
 for detailed error).
*/
UNICORN_EXPORT
uc_err uc_reg_write(uch handle, int regid, const void *value);

/*
 Read register value.

 @handle: handle returned by uc_open()
 @regid:  register ID that is to be retrieved.
 @value:  pointer to a variable storing the register value.

 @return UC_ERR_OK on success, or other value on failure (refer to uc_err enum
 for detailed error).
*/
UNICORN_EXPORT
uc_err uc_reg_read(uch handle, int regid, void *value);

/*
 Write to a range of bytes in memory.

 @handle: handle returned by uc_open()
 @address: starting memory address of bytes to set.
 @bytes:   pointer to a variable containing data to be written to memory.
 @size:   size of memory to write to.

 NOTE: @bytes must be big enough to contain @size bytes.

 @return UC_ERR_OK on success, or other value on failure (refer to uc_err enum
 for detailed error).
*/
UNICORN_EXPORT
uc_err uc_mem_write(uch handle, uint64_t address, const uint8_t *bytes, size_t size);

/*
 Read a range of bytes in memory.

 @handle: handle returned by uc_open()
 @address: starting memory address of bytes to get.
 @bytes:   pointer to a variable containing data copied from memory.
 @size:   size of memory to read.

 NOTE: @bytes must be big enough to contain @size bytes.

 @return UC_ERR_OK on success, or other value on failure (refer to uc_err enum
 for detailed error).
*/
UNICORN_EXPORT
uc_err uc_mem_read(uch handle, uint64_t address, uint8_t *bytes, size_t size);

/*
 Emulate machine code in a specific duration of time.

 @handle: handle returned by uc_open()
 @begin: address where emulation starts
 @until: address where emulation stops (i.e when this address is hit)
 @timeout: duration to emulate the code (in microseconds). When this value is 0,
        we will emulate the code in infinite time, until the code is finished.
 @count: the number of instructions to be emulated. When this value is 0,
        we will emulate all the code available, until the code is finished.

 @return UC_ERR_OK on success, or other value on failure (refer to uc_err enum
 for detailed error).
*/
UNICORN_EXPORT
uc_err uc_emu_start(uch handle, uint64_t begin, uint64_t until, uint64_t timeout, size_t count);

/*
 Stop emulation (which was started by uc_emu_start() API.
 This is typically called from callback functions registered via tracing APIs.
 NOTE: for now, this will stop the execution only after the current block.

 @handle: handle returned by uc_open()

 @return UC_ERR_OK on success, or other value on failure (refer to uc_err enum
 for detailed error).
*/
UNICORN_EXPORT
uc_err uc_emu_stop(uch handle);

/*
 Register callback for a hook event.
 The callback will be run when the hook event is hit.

 @handle: handle returned by uc_open()
 @h2: hook handle returned from this registration. To be used in uc_hook_del() API
 @type: hook type
 @callback: callback to be run when instruction is hit
 @user_data: user-defined data. This will be passed to callback function in its
      last argument @user_data
 @...: variable arguments (depending on @type)

 @return UC_ERR_OK on success, or other value on failure (refer to uc_err enum
 for detailed error).
*/
UNICORN_EXPORT
uc_err uc_hook_add(uch handle, uch *h2, uc_hook_t type, void *callback, void *user_data, ...);

/*
 Unregister (remove) a hook callback.
 This API removes the hook callback registered by uc_hook_add().
 NOTE: this should be called only when you no longer want to trace.
 After this, @hhandle is invalid, and nolonger usable.

 @handle: handle returned by uc_open()
 @h2: handle returned by uc_hook_add()

 @return UC_ERR_OK on success, or other value on failure (refer to uc_err enum
 for detailed error).
*/
UNICORN_EXPORT
uc_err uc_hook_del(uch handle, uch *h2);

/*
 Map memory in for emulation.
 This API adds a memory region that can be used by emulation.

 @handle: handle returned by uc_open()
 @address: starting address of the new memory region to be mapped in.
    This address must be aligned to 4KB, or this will return with UC_ERR_MAP error.
 @size: size of the new memory region to be mapped in.
    This size must be multiple of 4KB, or this will return with UC_ERR_MAP error.

 @return UC_ERR_OK on success, or other value on failure (refer to uc_err enum
 for detailed error).
*/
UNICORN_EXPORT
uc_err uc_mem_map(uch handle, uint64_t address, size_t size);

#ifdef __cplusplus
}
#endif

#endif
