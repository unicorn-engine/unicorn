// 
// Dynamic loader for unicorn shared library in windows and linux.
// This was made for v1.0 of unicorn.
// Newer versions of unicorn may require changes to these files.
// 
// Windows Notes:
// If an absolute path to unicorn.dll is passed into uc_dyn_load() it will
// still try to load the rest of the dependent dlls (ie libglib-2.0-0.dll etc)
// from standard dll paths. This is usually the directory that the main
// exe file, that loaded unicorn.dll, is in. This is standard behaviour for
// Windows dll files, and not specific to unicorn dlls.
// 
// So putting all dlls in their own directory and then attempting to load
// unicorn.dll from that directory via an absolute path will cause
// uc_dyn_load() to fail.
// 
// The easiest way around this is to place all dlls in the same directory
// as your main exe file. Other ways around this are using various flags
// for LoadLibraryEx() or by calling SetDllDirectory().
// 
// LoadLibraryEx info:
// https://msdn.microsoft.com/en-us/library/windows/desktop/ms684179(v=vs.85).aspx
// SetDllDirectory() info:
// https://msdn.microsoft.com/en-us/library/windows/desktop/ms686203(v=vs.85).aspx
// 
// Zak Escano  -  November 2015
// 

// Only use this if DYNLOAD is set in preprocessor definitions
#ifdef DYNLOAD

// This is to detect whether we are loading a dll in windows or a so in linux.
#ifdef _MSC_VER
#define WINDOWS_DLL	1
#endif

#include "unicorn_dynload.h"

#ifdef WINDOWS_DLL
#include <Windows.h>
#define DYNLOAD_DEFPATH			"unicorn.dll"
#define DYNLOAD_HANDLE			HMODULE
#define DYNLOAD_LOADLIB(path, f)LoadLibraryEx(path, NULL, f)
#define DYNLOAD_FREELIB(handle)	FreeLibrary(handle)
#define DYNLOAD_GETFUNC(h, n)	GetProcAddress(h, n)
#define DYNLOAD_GETERROR()		GetLastError()
#else
#include <dlfcn.h>
#define DYNLOAD_DEFPATH			"unicorn.so"
#define DYNLOAD_HANDLE			void*
#define DYNLOAD_LOADLIB(path, f)dlopen(path, f)
#define DYNLOAD_FREELIB(handle)	dlclose(handle)
#define DYNLOAD_GETFUNC(h, n)	dlsym(h, n)
#define DYNLOAD_GETERROR()		dlerror()
#endif


static DYNLOAD_HANDLE g_dyn_handle = NULL;


typedef unsigned int (*uc_version_t)(unsigned int *major, unsigned int *minor);
typedef bool   (*uc_arch_supported_t)(uc_arch arch);
typedef uc_err (*uc_open_t)(uc_arch arch, uc_mode mode, uc_engine **uc);
typedef uc_err (*uc_close_t)(uc_engine *uc);
typedef uc_err (*uc_query_t)(uc_engine *uc, uc_query_type type, size_t *result);
typedef uc_err (*uc_errno_t)(uc_engine *uc);
typedef const char* (*uc_strerror_t)(uc_err code);
typedef uc_err (*uc_reg_write_t)(uc_engine *uc, int regid, const void *value);
typedef uc_err (*uc_reg_read_t)(uc_engine *uc, int regid, void *value);
typedef uc_err (*uc_reg_write_batch_t)(uc_engine *uc, int *regs, void *const *vals, int count);
typedef uc_err (*uc_reg_read_batch_t)(uc_engine *uc, int *regs, void **vals, int count);
typedef uc_err (*uc_mem_write_t)(uc_engine *uc, uint64_t address, const void *bytes, size_t size);
typedef uc_err (*uc_mem_read_t)(uc_engine *uc, uint64_t address, void *bytes, size_t size);
typedef uc_err (*uc_emu_start_t)(uc_engine *uc, uint64_t begin, uint64_t until, uint64_t timeout, size_t count);
typedef uc_err (*uc_emu_stop_t)(uc_engine *uc);
typedef uc_err (*uc_hook_add_t)(uc_engine *uc, uc_hook *hh, int type, void *callback, void *user_data, uint64_t begin, uint64_t end, ...);
typedef uc_err (*uc_hook_del_t)(uc_engine *uc, uc_hook hh);
typedef uc_err (*uc_mem_map_t)(uc_engine *uc, uint64_t address, size_t size, uint32_t perms);
typedef uc_err (*uc_mem_map_ptr_t)(uc_engine *uc, uint64_t address, size_t size, uint32_t perms, void *ptr);
typedef uc_err (*uc_mem_unmap_t)(uc_engine *uc, uint64_t address, size_t size);
typedef uc_err (*uc_mem_protect_t)(uc_engine *uc, uint64_t address, size_t size, uint32_t perms);
typedef uc_err (*uc_mem_regions_t)(uc_engine *uc, uc_mem_region **regions, uint32_t *count);


static uc_version_t gp_uc_version = NULL;
static uc_arch_supported_t gp_uc_arch_supported = NULL;
static uc_open_t gp_uc_open = NULL;
static uc_close_t gp_uc_close = NULL;
static uc_query_t gp_uc_query = NULL;
static uc_errno_t gp_uc_errno = NULL;
static uc_strerror_t gp_uc_strerror = NULL;
static uc_reg_write_t gp_uc_reg_write = NULL;
static uc_reg_read_t gp_uc_reg_read = NULL;
static uc_reg_write_batch_t gp_uc_reg_write_batch = NULL;
static uc_reg_read_batch_t gp_uc_reg_read_batch = NULL;
static uc_mem_write_t gp_uc_mem_write = NULL;
static uc_mem_read_t gp_uc_mem_read = NULL;
static uc_emu_start_t gp_uc_emu_start = NULL;
static uc_emu_stop_t gp_uc_emu_stop = NULL;
static uc_hook_add_t gp_uc_hook_add = NULL;
static uc_hook_del_t gp_uc_hook_del = NULL;
static uc_mem_map_t gp_uc_mem_map = NULL;
static uc_mem_map_ptr_t gp_uc_mem_map_ptr = NULL;
static uc_mem_unmap_t gp_uc_mem_unmap = NULL;
static uc_mem_protect_t gp_uc_mem_protect = NULL;
static uc_mem_regions_t gp_uc_mem_regions = NULL;


bool uc_dyn_load(const char* path, int flags)
{
    if (path == NULL) {
        path = DYNLOAD_DEFPATH;
    }

    if (g_dyn_handle) {
        if (!uc_dyn_free())
            return false;
    }

    g_dyn_handle = DYNLOAD_LOADLIB(path, flags);
    if (g_dyn_handle == NULL) {
        //int err = DYNLOAD_GETERROR();
        //printf("Error loading %s: Last error is %X\n", path, err);
        return false;
    }

    gp_uc_version = (uc_version_t)DYNLOAD_GETFUNC(g_dyn_handle, "uc_version");
    gp_uc_arch_supported = (uc_arch_supported_t)DYNLOAD_GETFUNC(g_dyn_handle, "uc_arch_supported");
    gp_uc_open = (uc_open_t)DYNLOAD_GETFUNC(g_dyn_handle, "uc_open");
    gp_uc_close = (uc_close_t)DYNLOAD_GETFUNC(g_dyn_handle, "uc_close");
    gp_uc_query = (uc_query_t)DYNLOAD_GETFUNC(g_dyn_handle, "uc_query");
    gp_uc_errno = (uc_errno_t)DYNLOAD_GETFUNC(g_dyn_handle, "uc_errno");
    gp_uc_strerror = (uc_strerror_t)DYNLOAD_GETFUNC(g_dyn_handle, "uc_strerror");
    gp_uc_reg_write = (uc_reg_write_t)DYNLOAD_GETFUNC(g_dyn_handle, "uc_reg_write");
    gp_uc_reg_read = (uc_reg_read_t)DYNLOAD_GETFUNC(g_dyn_handle, "uc_reg_read");
    gp_uc_reg_write_batch = (uc_reg_write_batch_t)DYNLOAD_GETFUNC(g_dyn_handle, "uc_reg_write_batch");
    gp_uc_reg_read_batch = (uc_reg_read_batch_t)DYNLOAD_GETFUNC(g_dyn_handle, "uc_reg_read_batch");
    gp_uc_mem_write = (uc_mem_write_t)DYNLOAD_GETFUNC(g_dyn_handle, "uc_mem_write");
    gp_uc_mem_read = (uc_mem_read_t)DYNLOAD_GETFUNC(g_dyn_handle, "uc_mem_read");
    gp_uc_emu_start = (uc_emu_start_t)DYNLOAD_GETFUNC(g_dyn_handle, "uc_emu_start");
    gp_uc_emu_stop = (uc_emu_stop_t)DYNLOAD_GETFUNC(g_dyn_handle, "uc_emu_stop");
    gp_uc_hook_add = (uc_hook_add_t)DYNLOAD_GETFUNC(g_dyn_handle, "uc_hook_add");
    gp_uc_hook_del = (uc_hook_del_t)DYNLOAD_GETFUNC(g_dyn_handle, "uc_hook_del");
    gp_uc_mem_map = (uc_mem_map_t)DYNLOAD_GETFUNC(g_dyn_handle, "uc_mem_map");
    gp_uc_mem_map_ptr = (uc_mem_map_ptr_t)DYNLOAD_GETFUNC(g_dyn_handle, "uc_mem_map_ptr");
    gp_uc_mem_unmap = (uc_mem_unmap_t)DYNLOAD_GETFUNC(g_dyn_handle, "uc_mem_unmap");
    gp_uc_mem_protect = (uc_mem_protect_t)DYNLOAD_GETFUNC(g_dyn_handle, "uc_mem_protect");
    gp_uc_mem_regions = (uc_mem_regions_t)DYNLOAD_GETFUNC(g_dyn_handle, "uc_mem_regions");
    return true;
}

bool uc_dyn_free(void)
{
    if (g_dyn_handle==NULL)
        return true;

    DYNLOAD_FREELIB(g_dyn_handle);
    g_dyn_handle = NULL;

    gp_uc_version = NULL;
    gp_uc_arch_supported = NULL;
    gp_uc_open = NULL;
    gp_uc_close = NULL;
    gp_uc_query = NULL;
    gp_uc_errno = NULL;
    gp_uc_strerror = NULL;
    gp_uc_reg_write = NULL;
    gp_uc_reg_read = NULL;
    gp_uc_reg_write_batch = NULL;
    gp_uc_reg_read_batch = NULL;
    gp_uc_mem_write = NULL;
    gp_uc_mem_read = NULL;
    gp_uc_emu_start = NULL;
    gp_uc_emu_stop = NULL;
    gp_uc_hook_add = NULL;
    gp_uc_hook_del = NULL;
    gp_uc_mem_map = NULL;
    gp_uc_mem_map_ptr = NULL;
    gp_uc_mem_unmap = NULL;
    gp_uc_mem_protect = NULL;
    gp_uc_mem_regions = NULL;
    return true;
}


unsigned int uc_version(unsigned int *major, unsigned int *minor)
{
    return gp_uc_version(major, minor);
}

bool uc_arch_supported(uc_arch arch)
{
    return gp_uc_arch_supported(arch);
}

uc_err uc_open(uc_arch arch, uc_mode mode, uc_engine **uc)
{
    return gp_uc_open(arch, mode, uc);
}

uc_err uc_close(uc_engine *uc)
{
    return gp_uc_close(uc);
}

uc_err uc_query(uc_engine *uc, uc_query_type type, size_t *result)
{
    return gp_uc_query(uc, type, result);
}

uc_err uc_errno(uc_engine *uc)
{
    return gp_uc_errno(uc);
}

const char *uc_strerror(uc_err code)
{
    return gp_uc_strerror(code);
}

uc_err uc_reg_write(uc_engine *uc, int regid, const void *value)
{
    return gp_uc_reg_write(uc, regid, value);
}

uc_err uc_reg_read(uc_engine *uc, int regid, void *value)
{
    return gp_uc_reg_read(uc, regid, value);
}

uc_err uc_reg_write_batch(uc_engine *uc, int *regs, void *const *vals, int count)
{
    return gp_uc_reg_write_batch(uc, regs, vals, count);
}

uc_err uc_reg_read_batch(uc_engine *uc, int *regs, void **vals, int count)
{
    return gp_uc_reg_read_batch(uc, regs, vals, count);
}

uc_err uc_mem_write(uc_engine *uc, uint64_t address, const void *bytes, size_t size)
{
    return gp_uc_mem_write(uc, address, bytes, size);
}

uc_err uc_mem_read(uc_engine *uc, uint64_t address, void *bytes, size_t size)
{
    return gp_uc_mem_read(uc, address, bytes, size);
}

uc_err uc_emu_start(uc_engine *uc, uint64_t begin, uint64_t until, uint64_t timeout, size_t count)
{
    return gp_uc_emu_start(uc, begin, until, timeout, count);
}

uc_err uc_emu_stop(uc_engine *uc)
{
    return gp_uc_emu_stop(uc);
}

uc_err uc_hook_add(uc_engine *uc, uc_hook *hh, int type, void *callback, void *user_data, uint64_t begin, uint64_t end, ...)
{
    va_list valist;
    uc_err ret = UC_ERR_OK;
    int id;
    va_start(valist, end);

    switch(type) {
        // note this default case will capture any combinations of
        // UC_HOOK_MEM_*_PROT and UC_HOOK_MEM_*_UNMAPPED
        // as well as any combination of
        // UC_HOOK_MEM_READ, UC_HOOK_MEM_WRITE and UC_HOOK_MEM_FETCH
        default:
        case UC_HOOK_INTR:
        case UC_HOOK_CODE:
        case UC_HOOK_BLOCK:
        // all combinations of UC_HOOK_MEM_*_PROT and UC_HOOK_MEM_*_UNMAPPED are caught by 'default'
        case UC_HOOK_MEM_READ_UNMAPPED:
        case UC_HOOK_MEM_WRITE_UNMAPPED:
        case UC_HOOK_MEM_FETCH_UNMAPPED:
        case UC_HOOK_MEM_READ_PROT:
        case UC_HOOK_MEM_WRITE_PROT:
        case UC_HOOK_MEM_FETCH_PROT:
        // all combinations of read/write/fetch are caught by 'default'
        case UC_HOOK_MEM_READ:
        case UC_HOOK_MEM_WRITE:
        case UC_HOOK_MEM_FETCH:
            // 0 extra args
            ret = gp_uc_hook_add(uc, hh, type, callback, user_data, begin, end);
            break;
        case UC_HOOK_INSN:
            // 1 extra arg
            id = va_arg(valist, int);
            ret = gp_uc_hook_add(uc, hh, type, callback, user_data, begin, end, id);
            break;
    }

    va_end(valist);
    return ret;
}

uc_err uc_hook_del(uc_engine *uc, uc_hook hh)
{
    return gp_uc_hook_del(uc, hh);
}

uc_err uc_mem_map(uc_engine *uc, uint64_t address, size_t size, uint32_t perms)
{
    return gp_uc_mem_map(uc, address, size, perms);
}

uc_err uc_mem_map_ptr(uc_engine *uc, uint64_t address, size_t size, uint32_t perms, void *ptr)
{
    return gp_uc_mem_map_ptr(uc, address, size, perms, ptr);
}

uc_err uc_mem_unmap(uc_engine *uc, uint64_t address, size_t size)
{
    return gp_uc_mem_unmap(uc, address, size);
}

uc_err uc_mem_protect(uc_engine *uc, uint64_t address, size_t size, uint32_t perms)
{
    return gp_uc_mem_protect(uc, address, size, perms);
}

uc_err uc_mem_regions(uc_engine *uc, uc_mem_region **regions, uint32_t *count)
{
    return gp_uc_mem_regions(uc, regions, count);
}

#endif // DYNLOAD
