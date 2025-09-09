/* Unicorn Emulator Engine */
/* By Nguyen Anh Quynh <aquynh@gmail.com>, 2015-2017 */
/* This file is released under LGPL2.
   See COPYING.LGPL2 in root directory for more details
*/

#ifndef UNICORN_ENGINE_H
#define UNICORN_ENGINE_H

#ifdef __cplusplus
extern "C" {
#endif

#include "platform.h"
#include <stdarg.h>

#if defined(UNICORN_HAS_OSXKERNEL)
#include <libkern/libkern.h>
#else
#include <stdlib.h>
#include <stdio.h>
#endif

struct uc_struct;
typedef struct uc_struct uc_engine;

typedef size_t uc_hook;

#include "m68k.h"
#include "x86.h"
#include "arm.h"
#include "arm64.h"
#include "mips.h"
#include "sparc.h"
#include "ppc.h"
#include "riscv.h"
#include "s390x.h"
#include "tricore.h"

#ifdef __GNUC__
#define DEFAULT_VISIBILITY __attribute__((visibility("default")))
#else
#define DEFAULT_VISIBILITY
#endif

#ifdef _MSC_VER
#pragma warning(disable : 4201)
#pragma warning(disable : 4100)
#ifdef UNICORN_SHARED
#define UNICORN_EXPORT __declspec(dllexport)
#else // defined(UNICORN_STATIC)
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
#pragma message(                                                               \
    "WARNING: You need to implement UNICORN_DEPRECATED for this compiler")
#define UNICORN_DEPRECATED
#endif

// Unicorn API version
#define UC_API_MAJOR 2
#define UC_API_MINOR 1
#define UC_API_PATCH 4
// Release candidate version, 255 means the official release.
#define UC_API_EXTRA 255

// Unicorn package version
#define UC_VERSION_MAJOR UC_API_MAJOR
#define UC_VERSION_MINOR UC_API_MINOR
#define UC_VERSION_PATCH UC_API_PATCH
#define UC_VERSION_EXTRA UC_API_EXTRA

/*
  Macro to create combined version which can be compared to
  result of uc_version() API.
*/
#define UC_MAKE_VERSION(major, minor) (((major) << 24) + ((minor) << 16))

// Scales to calculate timeout on microsecond unit
// 1 second = 1000,000 microseconds
#define UC_SECOND_SCALE 1000000
// 1 milisecond = 1000 nanoseconds
#define UC_MILISECOND_SCALE 1000

// Architecture type
typedef enum uc_arch {
    UC_ARCH_ARM = 1, // ARM architecture (including Thumb, Thumb-2)
    UC_ARCH_ARM64,   // ARM-64, also called AArch64
    UC_ARCH_MIPS,    // Mips architecture
    UC_ARCH_X86,     // X86 architecture (including x86 & x86-64)
    UC_ARCH_PPC,     // PowerPC architecture
    UC_ARCH_SPARC,   // Sparc architecture
    UC_ARCH_M68K,    // M68K architecture
    UC_ARCH_RISCV,   // RISCV architecture
    UC_ARCH_S390X,   // S390X architecture
    UC_ARCH_TRICORE, // TriCore architecture
    UC_ARCH_MAX,
} uc_arch;

// Mode type
typedef enum uc_mode {
    UC_MODE_LITTLE_ENDIAN = 0,    // little-endian mode (default mode)
    UC_MODE_BIG_ENDIAN = 1 << 30, // big-endian mode

    // arm / arm64
    UC_MODE_ARM = 0,        // ARM mode
    UC_MODE_THUMB = 1 << 4, // THUMB mode (including Thumb-2)
    // Depreciated, use UC_ARM_CPU_* with uc_ctl instead.
    UC_MODE_MCLASS = 1 << 5,  // ARM's Cortex-M series.
    UC_MODE_V8 = 1 << 6,      // ARMv8 A32 encodings for ARM
    UC_MODE_ARMBE8 = 1 << 10, // Big-endian data and Little-endian code.
                              // Legacy support for UC1 only.

    // arm (32bit) cpu types
    // Depreciated, use UC_ARM_CPU_* with uc_ctl instead.
    UC_MODE_ARM926 = 1 << 7,  // ARM926 CPU type
    UC_MODE_ARM946 = 1 << 8,  // ARM946 CPU type
    UC_MODE_ARM1176 = 1 << 9, // ARM1176 CPU type

    // mips
    UC_MODE_MICRO = 1 << 4,    // MicroMips mode (currently unsupported)
    UC_MODE_MIPS3 = 1 << 5,    // Mips III ISA (currently unsupported)
    UC_MODE_MIPS32R6 = 1 << 6, // Mips32r6 ISA (currently unsupported)
    UC_MODE_MIPS32 = 1 << 2,   // Mips32 ISA
    UC_MODE_MIPS64 = 1 << 3,   // Mips64 ISA

    // x86 / x64
    UC_MODE_16 = 1 << 1, // 16-bit mode
    UC_MODE_32 = 1 << 2, // 32-bit mode
    UC_MODE_64 = 1 << 3, // 64-bit mode

    // ppc
    UC_MODE_PPC32 = 1 << 2, // 32-bit mode
    UC_MODE_PPC64 = 1 << 3, // 64-bit mode (currently unsupported)
    UC_MODE_QPX =
        1 << 4, // Quad Processing eXtensions mode (currently unsupported)

    // sparc
    UC_MODE_SPARC32 = 1 << 2, // 32-bit mode
    UC_MODE_SPARC64 = 1 << 3, // 64-bit mode
    UC_MODE_V9 = 1 << 4,      // SparcV9 mode (currently unsupported)

    // riscv
    UC_MODE_RISCV32 = 1 << 2, // 32-bit mode
    UC_MODE_RISCV64 = 1 << 3, // 64-bit mode

    // m68k
} uc_mode;

// All type of errors encountered by Unicorn API.
// These are values returned by uc_errno()
typedef enum uc_err {
    UC_ERR_OK = 0,         // No error: everything was fine
    UC_ERR_NOMEM,          // Out-Of-Memory error: uc_open(), uc_emulate()
    UC_ERR_ARCH,           // Unsupported architecture: uc_open()
    UC_ERR_HANDLE,         // Invalid handle
    UC_ERR_MODE,           // Invalid/unsupported mode: uc_open()
    UC_ERR_VERSION,        // Unsupported version (bindings)
    UC_ERR_READ_UNMAPPED,  // Quit emulation due to READ on unmapped memory:
                           // uc_emu_start()
    UC_ERR_WRITE_UNMAPPED, // Quit emulation due to WRITE on unmapped memory:
                           // uc_emu_start()
    UC_ERR_FETCH_UNMAPPED, // Quit emulation due to FETCH on unmapped memory:
                           // uc_emu_start()
    UC_ERR_HOOK,           // Invalid hook type: uc_hook_add()
    UC_ERR_INSN_INVALID,   // Quit emulation due to invalid instruction:
                           // uc_emu_start()
    UC_ERR_MAP,            // Invalid memory mapping: uc_mem_map()
    UC_ERR_WRITE_PROT,     // Quit emulation due to UC_MEM_WRITE_PROT violation:
                           // uc_emu_start()
    UC_ERR_READ_PROT,      // Quit emulation due to UC_MEM_READ_PROT violation:
                           // uc_emu_start()
    UC_ERR_FETCH_PROT,     // Quit emulation due to UC_MEM_FETCH_PROT violation:
                           // uc_emu_start()
    UC_ERR_ARG, // Inavalid argument provided to uc_xxx function (See specific
                // function API)
    UC_ERR_READ_UNALIGNED,  // Unaligned read
    UC_ERR_WRITE_UNALIGNED, // Unaligned write
    UC_ERR_FETCH_UNALIGNED, // Unaligned fetch
    UC_ERR_HOOK_EXIST,      // hook for this event already existed
    UC_ERR_RESOURCE,        // Insufficient resource: uc_emu_start()
    UC_ERR_EXCEPTION,       // Unhandled CPU exception
    UC_ERR_OVERFLOW,        // Provided buffer is not large enough: uc_reg_*2()
} uc_err;

/*
  Callback function for tracing code (UC_HOOK_CODE & UC_HOOK_BLOCK)

  @address: address where the code is being executed
  @size: size of machine instruction(s) being executed, or 0 when size is
  unknown
  @user_data: user data passed to tracing APIs.
*/
typedef void (*uc_cb_hookcode_t)(uc_engine *uc, uint64_t address, uint32_t size,
                                 void *user_data);

/*
  Callback function for tracing interrupts (for uc_hook_intr())

  @intno: interrupt number
  @user_data: user data passed to tracing APIs.
*/
typedef void (*uc_cb_hookintr_t)(uc_engine *uc, uint32_t intno,
                                 void *user_data);

/*
  Callback function for tracing invalid instructions

  @user_data: user data passed to tracing APIs.

  @return: return true to continue, or false to stop program (due to invalid
  instruction).
*/
typedef bool (*uc_cb_hookinsn_invalid_t)(uc_engine *uc, void *user_data);

/*
  Callback function for tracing IN instruction of X86

  @port: port number
  @size: data size (1/2/4) to be read from this port
  @user_data: user data passed to tracing APIs.
*/
typedef uint32_t (*uc_cb_insn_in_t)(uc_engine *uc, uint32_t port, int size,
                                    void *user_data);

/*
  Callback function for OUT instruction of X86

  @port: port number
  @size: data size (1/2/4) to be written to this port
  @value: data value to be written to this port
*/
typedef void (*uc_cb_insn_out_t)(uc_engine *uc, uint32_t port, int size,
                                 uint32_t value, void *user_data);

// The definitions for `uc_cb_tlbevent_t` callback
typedef enum uc_prot {
    UC_PROT_NONE = 0,
    UC_PROT_READ = 1,
    UC_PROT_WRITE = 2,
    UC_PROT_EXEC = 4,
    UC_PROT_ALL = 7,
} uc_prot;

struct uc_tlb_entry {
    uint64_t paddr;
    uc_prot perms;
};

typedef struct uc_tlb_entry uc_tlb_entry;

// All type of memory accesses for UC_HOOK_MEM_*
typedef enum uc_mem_type {
    UC_MEM_READ = 16,      // Memory is read from
    UC_MEM_WRITE,          // Memory is written to
    UC_MEM_FETCH,          // Memory is fetched
    UC_MEM_READ_UNMAPPED,  // Unmapped memory is read from
    UC_MEM_WRITE_UNMAPPED, // Unmapped memory is written to
    UC_MEM_FETCH_UNMAPPED, // Unmapped memory is fetched
    UC_MEM_WRITE_PROT,     // Write to write protected, but mapped, memory
    UC_MEM_READ_PROT,      // Read from read protected, but mapped, memory
    UC_MEM_FETCH_PROT,     // Fetch from non-executable, but mapped, memory
    UC_MEM_READ_AFTER,     // Memory is read from (successful access)
} uc_mem_type;

/*
  Callback function for tlb lookups

  @vaddr: virtuall address for lookup
  @rw: the access mode
  @result: result entry, contains physical address (paddr) and permitted access
  type (perms) for the entry

  @return: return true if the entry was found. If a callback is present but
  no one returns true a pagefault is generated.
*/
typedef bool (*uc_cb_tlbevent_t)(uc_engine *uc, uint64_t vaddr,
                                 uc_mem_type type, uc_tlb_entry *result,
                                 void *user_data);

// Represent a TranslationBlock.
typedef struct uc_tb {
    uint64_t pc;
    uint16_t icount;
    uint16_t size;
} uc_tb;

/*
  Callback function for new edges between translation blocks.

  @cur_tb: Current TB which is to be generated.
  @prev_tb: The previous TB.
*/
typedef void (*uc_hook_edge_gen_t)(uc_engine *uc, uc_tb *cur_tb, uc_tb *prev_tb,
                                   void *user_data);

/*
  Callback function for tcg opcodes that fits in two arguments.

  @address: Current pc.
  @arg1: The first argument.
  @arg2: The second argument.
*/
typedef void (*uc_hook_tcg_op_2)(uc_engine *uc, uint64_t address, uint64_t arg1,
                                 uint64_t arg2, uint32_t size, void *user_data);

typedef uc_hook_tcg_op_2 uc_hook_tcg_sub_t;

/*
  Callback function for MMIO read

  @offset: offset to the base address of the IO memory.
  @size: data size to read
  @user_data: user data passed to uc_mmio_map()
*/
typedef uint64_t (*uc_cb_mmio_read_t)(uc_engine *uc, uint64_t offset,
                                      unsigned size, void *user_data);

/*
  Callback function for MMIO write

  @offset: offset to the base address of the IO memory.
  @size: data size to write
  @value: data value to be written
  @user_data: user data passed to uc_mmio_map()
*/
typedef void (*uc_cb_mmio_write_t)(uc_engine *uc, uint64_t offset,
                                   unsigned size, uint64_t value,
                                   void *user_data);

// These are all op codes we support to hook for UC_HOOK_TCG_OP_CODE.
// Be cautious since it may bring much more overhead than UC_HOOK_CODE without
// proper flags.
// TODO: Tracing UC_TCG_OP_CALL should be interesting.
typedef enum uc_tcg_op_code {
    UC_TCG_OP_SUB = 0, // Both sub_i32 and sub_i64
} uc_tcg_op_code;

// These are extra flags to be paired with uc_tcg_op_code which is helpful to
// instrument in some certain cases.
typedef enum uc_tcg_op_flag {
    // Only instrument opcode if it would set cc_dst, i.e. cmp instruction.
    UC_TCG_OP_FLAG_CMP = 1 << 0,
    // Only instrument opcode which is directly translated.
    // i.e. x86 sub/subc -> tcg sub_i32/64
    UC_TCG_OP_FLAG_DIRECT = 1 << 1
} uc_tcg_op_flag;

// All type of hooks for uc_hook_add() API.
typedef enum uc_hook_type {
    // Hook all interrupt/syscall events
    UC_HOOK_INTR = 1 << 0,
    // Hook a particular instruction - only a very small subset of instructions
    // supported here
    UC_HOOK_INSN = 1 << 1,
    // Hook a range of code
    UC_HOOK_CODE = 1 << 2,
    // Hook basic blocks
    UC_HOOK_BLOCK = 1 << 3,
    // Hook for memory read on unmapped memory
    UC_HOOK_MEM_READ_UNMAPPED = 1 << 4,
    // Hook for invalid memory write events
    UC_HOOK_MEM_WRITE_UNMAPPED = 1 << 5,
    // Hook for invalid memory fetch for execution events
    UC_HOOK_MEM_FETCH_UNMAPPED = 1 << 6,
    // Hook for memory read on read-protected memory
    UC_HOOK_MEM_READ_PROT = 1 << 7,
    // Hook for memory write on write-protected memory
    UC_HOOK_MEM_WRITE_PROT = 1 << 8,
    // Hook for memory fetch on non-executable memory
    UC_HOOK_MEM_FETCH_PROT = 1 << 9,
    // Hook memory read events.
    UC_HOOK_MEM_READ = 1 << 10,
    // Hook memory write events.
    UC_HOOK_MEM_WRITE = 1 << 11,
    // Hook memory fetch for execution events
    UC_HOOK_MEM_FETCH = 1 << 12,
    // Hook memory read events, but only successful access.
    // The callback will be triggered after successful read.
    UC_HOOK_MEM_READ_AFTER = 1 << 13,
    // Hook invalid instructions exceptions.
    UC_HOOK_INSN_INVALID = 1 << 14,
    // Hook on new edge generation. Could be useful in program analysis.
    //
    // NOTE: This is different from UC_HOOK_BLOCK in 2 ways:
    //       1. The hook is called before executing code.
    //       2. The hook is only called when generation is triggered.
    UC_HOOK_EDGE_GENERATED = 1 << 15,
    // Hook on specific tcg op code. The usage of this hook is similar to
    // UC_HOOK_INSN.
    UC_HOOK_TCG_OPCODE = 1 << 16,
    // Hook on tlb fill requests.
    // Register tlb fill request hook on the virtuall addresses.
    // The callback will be triggert if the tlb cache don't contain an address.
    UC_HOOK_TLB_FILL = 1 << 17,
} uc_hook_type;

// Hook type for all events of unmapped memory access
#define UC_HOOK_MEM_UNMAPPED                                                   \
    (UC_HOOK_MEM_READ_UNMAPPED + UC_HOOK_MEM_WRITE_UNMAPPED +                  \
     UC_HOOK_MEM_FETCH_UNMAPPED)
// Hook type for all events of illegal protected memory access
#define UC_HOOK_MEM_PROT                                                       \
    (UC_HOOK_MEM_READ_PROT + UC_HOOK_MEM_WRITE_PROT + UC_HOOK_MEM_FETCH_PROT)
// Hook type for all events of illegal read memory access
#define UC_HOOK_MEM_READ_INVALID                                               \
    (UC_HOOK_MEM_READ_PROT + UC_HOOK_MEM_READ_UNMAPPED)
// Hook type for all events of illegal write memory access
#define UC_HOOK_MEM_WRITE_INVALID                                              \
    (UC_HOOK_MEM_WRITE_PROT + UC_HOOK_MEM_WRITE_UNMAPPED)
// Hook type for all events of illegal fetch memory access
#define UC_HOOK_MEM_FETCH_INVALID                                              \
    (UC_HOOK_MEM_FETCH_PROT + UC_HOOK_MEM_FETCH_UNMAPPED)
// Hook type for all events of illegal memory access
#define UC_HOOK_MEM_INVALID (UC_HOOK_MEM_UNMAPPED + UC_HOOK_MEM_PROT)
// Hook type for all events of valid memory access
// NOTE: UC_HOOK_MEM_READ is triggered before UC_HOOK_MEM_READ_PROT and
// UC_HOOK_MEM_READ_UNMAPPED, so
//       this hook may technically trigger on some invalid reads.
#define UC_HOOK_MEM_VALID                                                      \
    (UC_HOOK_MEM_READ + UC_HOOK_MEM_WRITE + UC_HOOK_MEM_FETCH)

/*
  Callback function for hooking memory (READ, WRITE & FETCH).

  NOTE: The access might be splitted depending on the MMU implementation.
  UC_TLB_VIRTUAL provides more fine-grained control about memory accessing.

  @type: this memory is being READ, or WRITE
  @address: address where memory is being written or read to
  @size: size of data being read or written
  @value: value of data being written to memory, or irrelevant if type = READ.
  @user_data: user data passed to tracing APIs
*/
typedef void (*uc_cb_hookmem_t)(uc_engine *uc, uc_mem_type type,
                                uint64_t address, int size, int64_t value,
                                void *user_data);

/*
  Callback function for handling invalid memory access events (UNMAPPED and
    PROT events)

  NOTE: The access might be splitted depending on the MMU implementation.
  UC_TLB_VIRTUAL provides more fine-grained control about memory accessing.

  @type: this memory is being READ, or WRITE
  @address: address where memory is being written or read to
  @size: size of data being read or written
  @value: value of data being written to memory, or irrelevant if type = READ.
  @user_data: user data passed to tracing APIs

  @return: return true to continue, or false to stop program (due to invalid
  memory). NOTE: returning true to continue execution will only work if the
  accessed memory is made accessible with the correct permissions during the
  hook.

           In the event of a UC_MEM_READ_UNMAPPED or UC_MEM_WRITE_UNMAPPED
  callback, the memory should be uc_mem_map()-ed with the correct permissions,
  and the instruction will then read or write to the address as it was supposed
  to.

           In the event of a UC_MEM_FETCH_UNMAPPED callback, the memory can be
  mapped in as executable, in which case execution will resume from the fetched
  address. The instruction pointer may be written to in order to change where
  execution resumes, but the fetch must succeed if execution is to resume.
*/
typedef bool (*uc_cb_eventmem_t)(uc_engine *uc, uc_mem_type type,
                                 uint64_t address, int size, int64_t value,
                                 void *user_data);

/*
  Memory region mapped by uc_mem_map() and uc_mem_map_ptr()
  Retrieve the list of memory regions with uc_mem_regions()
*/
typedef struct uc_mem_region {
    uint64_t begin; // begin address of the region (inclusive)
    uint64_t end;   // end address of the region (inclusive)
    uint32_t perms; // memory permissions of the region
} uc_mem_region;

// All type of queries for uc_query() API.
typedef enum uc_query_type {
    // Dynamically query current hardware mode.
    UC_QUERY_MODE = 1,
    UC_QUERY_PAGE_SIZE, // query pagesize of engine
    UC_QUERY_ARCH, // query architecture of engine (for ARM to query Thumb mode)
    UC_QUERY_TIMEOUT, // query if emulation stops due to timeout (indicated if
                      // result = True)
} uc_query_type;

// The implementation of uc_ctl is like what Linux ioctl does but slightly
// different.
//
// A uc_control_type passed to uc_ctl is constructed as:
//
//    R/W       NR       Reserved     Type
//  [      ] [      ]  [         ] [       ]
//  31    30 29     26 25       16 15      0
//
//  @R/W: Whether the operation is a read or write access.
//  @NR: Number of arguments.
//  @Reserved: Should be zero, reserved for future extension.
//  @Type: Taken from uc_control_type enum.
//
// See the helper macros below.

// No input and output arguments.
#define UC_CTL_IO_NONE (0)
// Only input arguments for a write operation.
#define UC_CTL_IO_WRITE (1)
// Only output arguments for a read operation.
#define UC_CTL_IO_READ (2)
// The arguments include both input and output arugments.
#define UC_CTL_IO_READ_WRITE (UC_CTL_IO_WRITE | UC_CTL_IO_READ)

#define UC_CTL(type, nr, rw)                                                   \
    (uc_control_type)((type) | ((nr) << 26) | ((rw) << 30))
#define UC_CTL_NONE(type, nr) UC_CTL(type, nr, UC_CTL_IO_NONE)
#define UC_CTL_READ(type, nr) UC_CTL(type, nr, UC_CTL_IO_READ)
#define UC_CTL_WRITE(type, nr) UC_CTL(type, nr, UC_CTL_IO_WRITE)
#define UC_CTL_READ_WRITE(type, nr) UC_CTL(type, nr, UC_CTL_IO_READ_WRITE)

// unicorn tlb type selection
typedef enum uc_tlb_type {
    // The default unicorn virtuall TLB implementation.
    // The tlb implementation of the CPU, best to use for full system emulation.
    UC_TLB_CPU = 0,
    // This tlb defaults to virtuall address == physical address
    // Also a hook is availible to override the tlb entries (see
    // uc_cb_tlbevent_t).
    UC_TLB_VIRTUAL
} uc_tlb_type;

// All type of controls for uc_ctl API.
// The controls are organized in a tree level.
// If a control don't have `Set` or `Get` for @args, it means it's r/o or w/o.
typedef enum uc_control_type {
    // Current mode.
    // Read: @args = (int*)
    UC_CTL_UC_MODE = 0,
    // Curent page size.
    // Write: @args = (uint32_t)
    // Read: @args = (uint32_t*)
    UC_CTL_UC_PAGE_SIZE,
    // Current arch.
    // Read: @args = (int*)
    UC_CTL_UC_ARCH,
    // Current timeout.
    // Read: @args = (uint64_t*)
    UC_CTL_UC_TIMEOUT,
    // Enable multiple exits.
    // Without this control, reading/setting exits won't work.
    // This is for API backward compatibility.
    // Write: @args = (int)
    UC_CTL_UC_USE_EXITS,
    // The number of current exits.
    // Read: @args = (size_t*)
    UC_CTL_UC_EXITS_CNT,
    // Current exits.
    // Write: @args = (uint64_t* exits, size_t len)
    //        @len = UC_CTL_UC_EXITS_CNT
    // Read: @args = (uint64_t* exits, size_t len)
    //       @len = UC_CTL_UC_EXITS_CNT
    UC_CTL_UC_EXITS,

    // Set the cpu model of uc.
    // Note this option can only be set before any Unicorn
    // API is called except for uc_open.
    // Write: @args = (int)
    // Read:  @args = (int*)
    UC_CTL_CPU_MODEL,
    // Request a tb cache at a specific address
    // Read: @args = (uint64_t, uc_tb*)
    UC_CTL_TB_REQUEST_CACHE,
    // Invalidate a tb cache at a specific address
    // Write: @args = (uint64_t, uint64_t)
    UC_CTL_TB_REMOVE_CACHE,
    // Invalidate all translation blocks.
    // No arguments.
    UC_CTL_TB_FLUSH,
    // Invalidate all TLB cache entries and translation blocks.
    // No arguments
    UC_CTL_TLB_FLUSH,
    // Change the tlb implementation
    // see uc_tlb_type for current implemented types
    // Write: @args = (int)
    UC_CTL_TLB_TYPE,
    // Change the tcg translation buffer size, note that
    // unicorn may adjust this value.
    // Write: @args = (uint32_t)
    // Read: @args = (uint32_t*)
    UC_CTL_TCG_BUFFER_SIZE,
    // controle if context_save/restore should work with snapshots
    // Write: @args = (int)
    UC_CTL_CONTEXT_MODE,
} uc_control_type;

/*

Exits Mechanism

In some cases, users may have multiple exits and the @until parameter of
uc_emu_start is not sufficient to control the emulation. The exits mechanism is
designed to solve this problem. Note that using hooks is aslo feasible, but the
exits could be slightly more efficient and easy to implement.

By default, the exits mechanism is disabled to keep backward compatibility. That
is to say, calling uc_ctl_set/get_exits would return an error. Thus, to enable
the exits firstly, call:

  uc_ctl_exits_enable(uc)

After this call, the @until parameter of uc_emu_start would have no effect on
the emulation, so:

  uc_emu_start(uc, 0x1000, 0 ...)
  uc_emu_start(uc, 0x1000, 0x1000 ...)
  uc_emu_start(uc, 0x1000, -1 ...)

The three calls are totally equavelent since the @until is ignored.

To setup the exits, users may call:

  uc_ctl_set/get_exits(uc, exits, len)

For example, with an exits array [0x1000, 0x2000], uc_emu_start would stop at
either 0x1000 and 0x2000. With an exits array [], uc_emu_start won't stop unless
some hooks request a stop.

If users would like to restore the default behavior of @until parameter, users
may call:

  uc_ctl_exits_disable(uc)

After that, all exits setup previously would be cleared and @until parameter
would take effect again.

See sample_ctl.c for a detailed example.

*/
#define uc_ctl_get_mode(uc, mode)                                              \
    uc_ctl(uc, UC_CTL_READ(UC_CTL_UC_MODE, 1), (mode))
#define uc_ctl_get_page_size(uc, ptr)                                          \
    uc_ctl(uc, UC_CTL_READ(UC_CTL_UC_PAGE_SIZE, 1), (ptr))
#define uc_ctl_set_page_size(uc, page_size)                                    \
    uc_ctl(uc, UC_CTL_WRITE(UC_CTL_UC_PAGE_SIZE, 1), (page_size))
#define uc_ctl_get_arch(uc, arch)                                              \
    uc_ctl(uc, UC_CTL_READ(UC_CTL_UC_ARCH, 1), (arch))
#define uc_ctl_get_timeout(uc, ptr)                                            \
    uc_ctl(uc, UC_CTL_READ(UC_CTL_UC_TIMEOUT, 1), (ptr))
#define uc_ctl_exits_enable(uc)                                                \
    uc_ctl(uc, UC_CTL_WRITE(UC_CTL_UC_USE_EXITS, 1), 1)
#define uc_ctl_exits_disable(uc)                                               \
    uc_ctl(uc, UC_CTL_WRITE(UC_CTL_UC_USE_EXITS, 1), 0)
#define uc_ctl_get_exits_cnt(uc, ptr)                                          \
    uc_ctl(uc, UC_CTL_READ(UC_CTL_UC_EXITS_CNT, 1), (ptr))
#define uc_ctl_get_exits(uc, buffer, len)                                      \
    uc_ctl(uc, UC_CTL_READ(UC_CTL_UC_EXITS, 2), (buffer), (len))
#define uc_ctl_set_exits(uc, buffer, len)                                      \
    uc_ctl(uc, UC_CTL_WRITE(UC_CTL_UC_EXITS, 2), (buffer), (len))
#define uc_ctl_get_cpu_model(uc, model)                                        \
    uc_ctl(uc, UC_CTL_READ(UC_CTL_CPU_MODEL, 1), (model))
#define uc_ctl_set_cpu_model(uc, model)                                        \
    uc_ctl(uc, UC_CTL_WRITE(UC_CTL_CPU_MODEL, 1), (model))
#define uc_ctl_remove_cache(uc, address, end)                                  \
    uc_ctl(uc, UC_CTL_WRITE(UC_CTL_TB_REMOVE_CACHE, 2), (address), (end))
#define uc_ctl_request_cache(uc, address, tb)                                  \
    uc_ctl(uc, UC_CTL_READ_WRITE(UC_CTL_TB_REQUEST_CACHE, 2), (address), (tb))
#define uc_ctl_flush_tb(uc) uc_ctl(uc, UC_CTL_WRITE(UC_CTL_TB_FLUSH, 0))
#define uc_ctl_flush_tlb(uc) uc_ctl(uc, UC_CTL_WRITE(UC_CTL_TLB_FLUSH, 0))
#define uc_ctl_tlb_mode(uc, mode)                                              \
    uc_ctl(uc, UC_CTL_WRITE(UC_CTL_TLB_TYPE, 1), (mode))
#define uc_ctl_get_tcg_buffer_size(uc, size)                                   \
    uc_ctl(uc, UC_CTL_READ(UC_CTL_TCG_BUFFER_SIZE, 1), (size))
#define uc_ctl_set_tcg_buffer_size(uc, size)                                   \
    uc_ctl(uc, UC_CTL_WRITE(UC_CTL_TCG_BUFFER_SIZE, 1), (size))
#define uc_ctl_context_mode(uc, mode)                                          \
    uc_ctl(uc, UC_CTL_WRITE(UC_CTL_CONTEXT_MODE, 1), (mode))

// Opaque storage for CPU context, used with uc_context_*()
struct uc_context;
typedef struct uc_context uc_context;

/*
 Return combined API version & major and minor version numbers.

 @major: major number of API version
 @minor: minor number of API version

 @return hexadecimal number as (major << 24 | minor << 16 | patch << 8 | extra).
     NOTE: This returned value can be compared with version number made
     with macro UC_MAKE_VERSION

 For example, Unicorn version 2.0.1 final would be 0x020001ff.

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
 Create new instance of unicorn engine.

 @arch: architecture type (UC_ARCH_*)
 @mode: hardware mode. This is combined of UC_MODE_*
 @uc: pointer to uc_engine, which will be updated at return time

 @return UC_ERR_OK on success, or other value on failure (refer to uc_err enum
   for detailed error).
*/
UNICORN_EXPORT
uc_err uc_open(uc_arch arch, uc_mode mode, uc_engine **uc);

/*
 Close a Unicorn engine instance.
 NOTE: this must be called only when there is no longer any
 usage of @uc. This API releases some of @uc's cached memory, thus
 any use of the Unicorn API with @uc after it has been closed may
 crash your application. After this, @uc is invalid, and is no
 longer usable.

 @uc: pointer to a handle returned by uc_open()

 @return UC_ERR_OK on success, or other value on failure (refer to uc_err enum
   for detailed error).
*/
UNICORN_EXPORT
uc_err uc_close(uc_engine *uc);

/*
 Query internal status of engine.

 @uc: handle returned by uc_open()
 @type: query type. See uc_query_type

 @result: save the internal status queried

 @return: error code of uc_err enum type (UC_ERR_*, see above)
*/
UNICORN_EXPORT
uc_err uc_query(uc_engine *uc, uc_query_type type, size_t *result);

/*
 Control internal states of engine.

 Also see uc_ctl_* macro helpers for easy use.

 @uc: handle returned by uc_open()
 @control: the control type.
 @args: See uc_control_type for details about variadic arguments.

 @return: error code of uc_err enum type (UC_ERR_*, see above)
*/
UNICORN_EXPORT
uc_err uc_ctl(uc_engine *uc, uc_control_type control, ...);

/*
 Report the last error number when some API function fails.
 Like glibc's errno, uc_errno might not retain its old value once accessed.

 @uc: handle returned by uc_open()

 @return: error code of uc_err enum type (UC_ERR_*, see above)
*/
UNICORN_EXPORT
uc_err uc_errno(uc_engine *uc);

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

 @uc: handle returned by uc_open()
 @regid:  register ID that is to be modified.
 @value:  pointer to the value that will be written to register @regid

 @return UC_ERR_OK on success; UC_ERR_ARG if register number or value is invalid
*/
UNICORN_EXPORT
uc_err uc_reg_write(uc_engine *uc, int regid, const void *value);

/*
 Read register value.

 @uc: handle returned by uc_open()
 @regid:  register ID that is to be retrieved.
 @value:  pointer to a variable storing the register value.

 @return UC_ERR_OK on success; UC_ERR_ARG if register number or value is invalid
*/
UNICORN_EXPORT
uc_err uc_reg_read(uc_engine *uc, int regid, void *value);

/*
 Write to register.

 @uc: handle returned by uc_open()
 @regid:  register ID that is to be modified.
 @value:  pointer to the value that will be written to register @regid
 @size:   size of value being written; on return, size of value written

 @return UC_ERR_OK on success; UC_ERR_ARG if register number or value is
 invalid; UC_ERR_OVERFLOW if value is not large enough for the register.
*/
UNICORN_EXPORT
uc_err uc_reg_write2(uc_engine *uc, int regid, const void *value, size_t *size);

/*
 Read register value.

 @uc: handle returned by uc_open()
 @regid:  register ID that is to be retrieved.
 @value:  pointer to a variable storing the register value.
 @size:   size of value buffer; on return, size of value read

 @return UC_ERR_OK on success; UC_ERR_ARG if register number or value is
 invalid; UC_ERR_OVERFLOW if value is not large enough to hold the register.
*/
UNICORN_EXPORT
uc_err uc_reg_read2(uc_engine *uc, int regid, void *value, size_t *size);

/*
 Write multiple register values.

 @uc: handle returned by uc_open()
 @regs:  array of register IDs to store
 @vals:  array of pointers to register values
 @count: length of both *regs and *vals

 @return UC_ERR_OK on success; UC_ERR_ARG if some register number or value is
 invalid
*/
UNICORN_EXPORT
uc_err uc_reg_write_batch(uc_engine *uc, int const *regs, void *const *vals,
                          int count);

/*
 Read multiple register values.

 @uc: handle returned by uc_open()
 @regs:  array of register IDs to retrieve
 @vals:  array of pointers to register values
 @count: length of both *regs and *vals

 @return UC_ERR_OK on success; UC_ERR_ARG if some register number or value is
 invalid
*/
UNICORN_EXPORT
uc_err uc_reg_read_batch(uc_engine *uc, int const *regs, void **vals,
                         int count);

/*
 Write multiple register values.

 @uc: handle returned by uc_open()
 @regs:  array of register IDs to store
 @value: array of pointers to register values
 @sizes: array of sizes of each value; on return, sizes of each stored register
 @count: length of *regs, *vals and *sizes

 @return UC_ERR_OK on success; UC_ERR_ARG if some register number or value is
 invalid; UC_ERR_OVERFLOW if some value is not large enough for the
 corresponding register.
*/
UNICORN_EXPORT
uc_err uc_reg_write_batch2(uc_engine *uc, int const *regs,
                           const void *const *vals, size_t *sizes, int count);

/*
 Read multiple register values.

 @uc: handle returned by uc_open()
 @regs:  array of register IDs to retrieve
 @value: pointer to array of values to hold registers
 @sizes: array of sizes of each value; on return, sizes of each retrieved
 register
 @count: length of *regs, *vals and *sizes

 @return UC_ERR_OK on success; UC_ERR_ARG if some register number or value is
 invalid; UC_ERR_OVERFLOW if some value is not large enough to hold the
 corresponding register.
*/
UNICORN_EXPORT
uc_err uc_reg_read_batch2(uc_engine *uc, int const *regs, void *const *vals,
                          size_t *sizes, int count);

/*
 Write to a range of bytes in memory.

 @uc: handle returned by uc_open()
 @address: starting memory address of bytes to set.
 @bytes:   pointer to a variable containing data to be written to memory.
 @size:   size of memory to write to.

 NOTE: @bytes must be big enough to contain @size bytes.

 @return UC_ERR_OK on success, or other value on failure (refer to uc_err enum
   for detailed error).
*/
UNICORN_EXPORT
uc_err uc_mem_write(uc_engine *uc, uint64_t address, const void *bytes,
                    uint64_t size);

/*
 Read a range of bytes in memory.

 @uc: handle returned by uc_open()
 @address: starting memory address of bytes to get.
 @bytes:   pointer to a variable containing data copied from memory.
 @size:   size of memory to read.

 NOTE: @bytes must be big enough to contain @size bytes.

 @return UC_ERR_OK on success, or other value on failure (refer to uc_err enum
   for detailed error).
*/
UNICORN_EXPORT
uc_err uc_mem_read(uc_engine *uc, uint64_t address, void *bytes, uint64_t size);

/*
 Read a range of bytes in memory after mmu translation.

 @uc:      handle returned by uc_open()
 @address: starting virtual memory address of bytes to get.
 @prot:    The access type for the tlb lookup
 @bytes:   pointer to a variable containing data copied from memory.
 @size:    size of memory to read.

 NOTE: @bytes must be big enough to contain @size bytes.

 This function will translate the address with the MMU. Therefore all
 pages needs to be memory mapped with the proper access rights. The MMU
 will not translate the virtual address when the pages are not mapped
 with the given access rights.

 Note the `prot` is different from the underlying protections of the physicall
 memory regions. For instance, if a region of phyiscal memory is mapped with
 write-only permissions, only a call with prot == UC_PROT_WRITE will be able to
 read the contents.

 @return UC_ERR_OK on success, or other value on failure (refer to uc_err enum
   for detailed error).
*/
UNICORN_EXPORT
uc_err uc_vmem_read(uc_engine *uc, uint64_t address, uc_prot prot,
                           void *bytes, size_t size);

/*
 Write to a range of bytes in memory after mmu translation.

 @uc: handle returned by uc_open()
 @address: starting memory address of bytes to set.
 @prot:    The access type for the tlb lookup
 @bytes:   pointer to a variable containing data to be written to memory.
 @size:   size of memory to write to.

 This function will translate the address with the MMU. Therefore all
 pages needs to be memory mapped with the proper access rights. The MMU
 will not translate the virtual address when the pages are not mapped
 with the given access rights.

 When the pages are mapped with the given access rights the write will
 happen indipenden from the access rights of the mapping. So when you
 have a page read only mapped, a call with prot == UC_PROT_READ will
 be able to write the data.

 NOTE: @bytes must be big enough to contain @size bytes.

 @return UC_ERR_OK on success, or other value on failure (refer to uc_err enum
   for detailed error).
*/
UNICORN_EXPORT
uc_err uc_vmem_write(uc_engine *uc, uint64_t address, uc_prot prot,
                           void *bytes, size_t size);

/*
 Translate a virtuall address to a physical address

 @uc:
 @address:  virtual address to translate
 @prot:     The access type for the tlb lookup
 @paddress: A pointer to store the result

 This function will translate the address with the MMU. Therefore all
 pages needs to be memory mapped with the proper access rights. The MMU
 will not translate the virtual address when the pages are not mapped
 with the given access rights.

 @return UC_ERR_OK on success, or other value on failure (refer to uc_err enum
   for detailed error).
*/
UNICORN_EXPORT
uc_err uc_vmem_translate(uc_engine *uc, uint64_t address, uc_prot prot,
                              uint64_t *paddress);

/*
 Emulate machine code in a specific duration of time.

 @uc: handle returned by uc_open()
 @begin: address where emulation starts
 @until: address where emulation stops (i.e. when this address is hit)
 @timeout: duration to emulate the code (in microseconds). When this value is 0,
        we will emulate the code in infinite time, until the code is finished.
 @count: the number of instructions to be emulated. When this value is 0,
        we will emulate all the code available, until the code is finished.

 NOTE: The internal states of the engine is guranteed to be correct if and only
       if uc_emu_start returns without any errors or errors have been handled in
       the callbacks.

 @return UC_ERR_OK on success, or other value on failure (refer to uc_err enum
   for detailed error).
*/
UNICORN_EXPORT
uc_err uc_emu_start(uc_engine *uc, uint64_t begin, uint64_t until,
                    uint64_t timeout, size_t count);

/*
 Stop emulation (which was started by uc_emu_start() API.
 This is typically called from callback functions registered via tracing APIs.

 @uc: handle returned by uc_open()

 @return UC_ERR_OK on success, or other value on failure (refer to uc_err enum
   for detailed error).
*/
UNICORN_EXPORT
uc_err uc_emu_stop(uc_engine *uc);

/*
 Register callback for a hook event.
 The callback will be run when the hook event is hit.

 @uc: handle returned by uc_open()
 @hh: hook handle returned from this registration. To be used in uc_hook_del()
 API
 @type: hook type, refer to uc_hook_type enum
 @callback: callback to be run when instruction is hit
 @user_data: user-defined data. This will be passed to callback function in its
      last argument @user_data
 @begin: start address of the area where the callback is in effect (inclusive)
 @end: end address of the area where the callback is in effect (inclusive)
   NOTE 1: the callback is called only if related address is in range [@begin,
 @end] NOTE 2: if @begin > @end, callback is called whenever this hook type is
 triggered
 @...: variable arguments (depending on @type)
   NOTE: if @type = UC_HOOK_INSN, this is the instruction ID.
         currently, only x86 in, out, syscall, sysenter, cpuid are supported.
   NOTE: if @type = UC_HOOK_TCG_OPCODE, arguments are @opcode and @flags. See
 @uc_tcg_op_code and @uc_tcg_op_flag for details.

 @return UC_ERR_OK on success, or other value on failure (refer to uc_err enum
   for detailed error).
*/
UNICORN_EXPORT
uc_err uc_hook_add(uc_engine *uc, uc_hook *hh, int type, void *callback,
                   void *user_data, uint64_t begin, uint64_t end, ...);

/*
 Unregister (remove) a hook callback.
 This API removes the hook callback registered by uc_hook_add().
 NOTE: this should be called only when you no longer want to trace.
 After this, @hh is invalid, and no longer usable.

 @uc: handle returned by uc_open()
 @hh: handle returned by uc_hook_add()

 @return UC_ERR_OK on success, or other value on failure (refer to uc_err enum
   for detailed error).
*/
UNICORN_EXPORT
uc_err uc_hook_del(uc_engine *uc, uc_hook hh);

/*
 Variables to control which state should be stored in the context.
 Defaults to UC_CTL_CONTEXT_CPU. The options are used in a bitfield
 so to enable more then one content the binary or of the required
 contents can be use.
 The UC_CTL_CONTEXT_MEMORY stores some pointers to internal allocated
 memory. Therefor it's not possible to use this context with another
 unicorn object.
*/

typedef enum uc_context_content {
    UC_CTL_CONTEXT_CPU = 1,
    UC_CTL_CONTEXT_MEMORY = 2,
} uc_context_content;

/*
 Map memory in for emulation.
 This API adds a memory region that can be used by emulation.

 @uc: handle returned by uc_open()
 @address: starting address of the new memory region to be mapped in.
    This address must be aligned to 4KB, or this will return with UC_ERR_ARG
 error.
 @size: size of the new memory region to be mapped in.
    This size must be a multiple of 4KB, or this will return with UC_ERR_ARG
 error.
 @perms: Permissions for the newly mapped region.
    This must be some combination of UC_PROT_READ | UC_PROT_WRITE |
 UC_PROT_EXEC, or this will return with UC_ERR_ARG error.

 @return UC_ERR_OK on success, or other value on failure (refer to uc_err enum
   for detailed error).
*/
UNICORN_EXPORT
uc_err uc_mem_map(uc_engine *uc, uint64_t address, uint64_t size,
                  uint32_t perms);

/*
 Map existing host memory in for emulation.
 This API adds a memory region that can be used by emulation.

 @uc: handle returned by uc_open()
 @address: starting address of the new memory region to be mapped in.
    This address must be aligned to 4KB, or this will return with UC_ERR_ARG
 error.
 @size: size of the new memory region to be mapped in.
    This size must be a multiple of 4KB, or this will return with UC_ERR_ARG
 error.
 @perms: Permissions for the newly mapped region.
    This must be some combination of UC_PROT_READ | UC_PROT_WRITE |
 UC_PROT_EXEC, or this will return with UC_ERR_ARG error.
 @ptr: pointer to host memory backing the newly mapped memory. This host memory
 is expected to be an equal or larger size than provided, and be mapped with at
    least PROT_READ | PROT_WRITE. If it is not, the resulting behavior is
 undefined.

 @return UC_ERR_OK on success, or other value on failure (refer to uc_err enum
   for detailed error).
*/
UNICORN_EXPORT
uc_err uc_mem_map_ptr(uc_engine *uc, uint64_t address, uint64_t size,
                      uint32_t perms, void *ptr);

/*
 Map MMIO in for emulation.
 This API adds a MMIO region that can be used by emulation.

 @uc: handle returned by uc_open()
 @address: starting address of the new MMIO region to be mapped in.
   This address must be aligned to 4KB, or this will return with UC_ERR_ARG
 error.
 @size: size of the new MMIO region to be mapped in.
   This size must be multiple of 4KB, or this will return with UC_ERR_ARG error.
 @read_cb: function for handling reads from this MMIO region.
 @user_data_read: user-defined data. This will be passed to @read_cb function in
 its last argument @user_data
 @write_cb: function for handling writes to this MMIO region.
 @user_data_write: user-defined data. This will be passed to @write_cb function
 in its last argument @user_data
 @return UC_ERR_OK on success, or other value on failure (refer to uc_err enum
   for detailed error).
 */
UNICORN_EXPORT
uc_err uc_mmio_map(uc_engine *uc, uint64_t address, uint64_t size,
                   uc_cb_mmio_read_t read_cb, void *user_data_read,
                   uc_cb_mmio_write_t write_cb, void *user_data_write);

/*
 Unmap a region of emulation memory.
 This API deletes a memory mapping from the emulation memory space.

 @uc: handle returned by uc_open()
 @address: starting address of the memory region to be unmapped.
    This address must be aligned to 4KB, or this will return with UC_ERR_ARG
 error.
 @size: size of the memory region to be modified.
    This size must be a multiple of 4KB, or this will return with UC_ERR_ARG
 error.

 @return UC_ERR_OK on success, or other value on failure (refer to uc_err enum
   for detailed error).
*/
UNICORN_EXPORT
uc_err uc_mem_unmap(uc_engine *uc, uint64_t address, uint64_t size);

/*
 Set memory permissions for emulation memory.
 This API changes permissions on an existing memory region.

 @uc: handle returned by uc_open()
 @address: starting address of the memory region to be modified.
    This address must be aligned to 4KB, or this will return with UC_ERR_ARG
 error.
 @size: size of the memory region to be modified.
    This size must be a multiple of 4KB, or this will return with UC_ERR_ARG
 error.
 @perms: New permissions for the mapped region.
    This must be some combination of UC_PROT_READ | UC_PROT_WRITE |
 UC_PROT_EXEC, or this will return with UC_ERR_ARG error.

 @return UC_ERR_OK on success, or other value on failure (refer to uc_err enum
   for detailed error).
*/
UNICORN_EXPORT
uc_err uc_mem_protect(uc_engine *uc, uint64_t address, uint64_t size,
                      uint32_t perms);

/*
 Retrieve all memory regions mapped by uc_mem_map() and uc_mem_map_ptr()
 This API allocates memory for @regions, and user must free this memory later
 by uc_free() to avoid leaking memory.
 NOTE: memory regions may be split by uc_mem_unmap()

 @uc: handle returned by uc_open()
 @regions: pointer to an array of uc_mem_region struct. This is allocated by
   Unicorn, and must be freed by user later with uc_free()
 @count: pointer to number of struct uc_mem_region contained in @regions

 @return UC_ERR_OK on success, or other value on failure (refer to uc_err enum
   for detailed error).
*/
UNICORN_EXPORT
uc_err uc_mem_regions(uc_engine *uc, uc_mem_region **regions, uint32_t *count);

/*
 Allocate a region that can be used with uc_context_{save,restore} to perform
 quick save/rollback of the CPU context, which includes registers and some
 internal metadata. Contexts may not be shared across engine instances with
 differing arches or modes.

 @uc: handle returned by uc_open()
 @context: pointer to a uc_context*. This will be updated with the pointer to
   the new context on successful return of this function.
   Later, this allocated memory must be freed with uc_context_free().

 @return UC_ERR_OK on success, or other value on failure (refer to uc_err enum
   for detailed error).
*/
UNICORN_EXPORT
uc_err uc_context_alloc(uc_engine *uc, uc_context **context);

/*
 Free the memory allocated by uc_mem_regions.
 WARNING: After Unicorn 1.0.1rc5, the memory allocated by uc_context_alloc
 should be freed by uc_context_free(). Calling uc_free() may still work, but
 the result is **undefined**.

 @mem: memory allocated by uc_mem_regions (returned in *regions).

 @return UC_ERR_OK on success, or other value on failure (refer to uc_err enum
   for detailed error).
*/
UNICORN_EXPORT
uc_err uc_free(void *mem);

/*
 Save a copy of the internal CPU context.
 This API should be used to efficiently make or update a saved copy of the
 internal CPU state.

 @uc: handle returned by uc_open()
 @context: handle returned by uc_context_alloc()

 @return UC_ERR_OK on success, or other value on failure (refer to uc_err enum
   for detailed error).
*/
UNICORN_EXPORT
uc_err uc_context_save(uc_engine *uc, uc_context *context);

/*
 Write value to a register of a context.

 @ctx: handle returned by uc_context_alloc()
 @regid:  register ID that is to be modified.
 @value:  pointer to the value that will be written to register @regid

 @return UC_ERR_OK on success; UC_ERR_ARG if register number or value is invalid
*/
UNICORN_EXPORT
uc_err uc_context_reg_write(uc_context *ctx, int regid, const void *value);

/*
 Read register value from a context.

 @ctx: handle returned by uc_context_alloc()
 @regid:  register ID that is to be retrieved.
 @value:  pointer to a variable storing the register value.

 @return UC_ERR_OK on success; UC_ERR_ARG if register number or value is invalid
*/
UNICORN_EXPORT
uc_err uc_context_reg_read(uc_context *ctx, int regid, void *value);

/*
 Write value to a register of a context.

 @ctx: handle returned by uc_context_alloc()
 @regid:  register ID that is to be modified.
 @value:  pointer to the value that will be written to register @regid
 @size:   size of value being written; on return, size of value written

 @return UC_ERR_OK on success; UC_ERR_ARG if register number or value is
 invalid; UC_ERR_OVERFLOW if value is not large enough for the register.
*/
UNICORN_EXPORT
uc_err uc_context_reg_write2(uc_context *ctx, int regid, const void *value,
                             size_t *size);

/*
 Read register value from a context.

 @ctx: handle returned by uc_context_alloc()
 @regid:  register ID that is to be retrieved.
 @value:  pointer to a variable storing the register value.
 @size:   size of value buffer; on return, size of value read

 @return UC_ERR_OK on success; UC_ERR_ARG if register number or value is
 invalid; UC_ERR_OVERFLOW if value is not large enough to hold the register.
*/
UNICORN_EXPORT
uc_err uc_context_reg_read2(uc_context *ctx, int regid, void *value,
                            size_t *size);

/*
 Write multiple register values to registers of a context.

 @ctx: handle returned by uc_context_alloc()
 @regs:  array of register IDs to store
 @value: pointer to array of register values
 @count: length of both *regs and *vals

 @return UC_ERR_OK on success, or other value on failure (refer to uc_err enum
   for detailed error).
*/
UNICORN_EXPORT
uc_err uc_context_reg_write_batch(uc_context *ctx, int const *regs,
                                  void *const *vals, int count);

/*
 Read multiple register values from a context.

 @ctx: handle returned by uc_context_alloc()
 @regs:  array of register IDs to retrieve
 @value: pointer to array of values to hold registers
 @count: length of both *regs and *vals

 @return UC_ERR_OK on success, or other value on failure (refer to uc_err enum
   for detailed error).
*/
UNICORN_EXPORT
uc_err uc_context_reg_read_batch(uc_context *ctx, int const *regs, void **vals,
                                 int count);

/*
 Write multiple register values to registers of a context.

 @ctx: handle returned by uc_context_alloc()
 @regs:  array of register IDs to store
 @value: array of pointers to register values
 @sizes: array of sizes of each value; on return, sizes of each stored register
 @count: length of *regs, *vals and *sizes

 @return UC_ERR_OK on success; UC_ERR_ARG if some register number or value is
 invalid; UC_ERR_OVERFLOW if some value is not large enough for the
 corresponding register.
*/
UNICORN_EXPORT
uc_err uc_context_reg_write_batch2(uc_context *ctx, int const *regs,
                                   const void *const *vals, size_t *sizes,
                                   int count);

/*
 Read multiple register values from a context.

 @ctx: handle returned by uc_context_alloc()
 @regs:  array of register IDs to retrieve
 @value: pointer to array of values to hold registers
 @sizes: array of sizes of each value; on return, sizes of each retrieved
 register
 @count: length of *regs, *vals and *sizes

 @return UC_ERR_OK on success; UC_ERR_ARG if some register number or value is
 invalid; UC_ERR_OVERFLOW if some value is not large enough to hold the
 corresponding register.
*/
UNICORN_EXPORT
uc_err uc_context_reg_read_batch2(uc_context *ctx, int const *regs,
                                  void *const *vals, size_t *sizes, int count);

/*
 Restore the current CPU context from a saved copy.
 This API should be used to roll the CPU context back to a previous
 state saved by uc_context_save().

 @uc: handle returned by uc_open()
 @context: handle returned by uc_context_alloc that has been used with
 uc_context_save

 @return UC_ERR_OK on success, or other value on failure (refer to uc_err enum
   for detailed error).
*/
UNICORN_EXPORT
uc_err uc_context_restore(uc_engine *uc, uc_context *context);

/*
  Return the size needed to store the cpu context. Can be used to allocate a
  buffer to contain the cpu context and directly call uc_context_save.

  @uc: handle returned by uc_open()

  @return the size for needed to store the cpu context as as size_t.
*/
UNICORN_EXPORT
size_t uc_context_size(uc_engine *uc);

/*
  Free the context allocated by uc_context_alloc().

  @context: handle returned by uc_context_alloc()

  @return UC_ERR_OK on success, or other value on failure (refer to uc_err enum
   for detailed error).
*/
UNICORN_EXPORT
uc_err uc_context_free(uc_context *context);

#ifdef __cplusplus
}
#endif

#endif
