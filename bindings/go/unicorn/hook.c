#include <unicorn/unicorn.h>
#include "_cgo_export.h"

uc_err uc_hook_add(uc_engine *uc, uc_hook *hh, int type, void *callback,
                void *user_data, uint64_t begin, uint64_t end, ...);


uc_err uc_hook_add_wrap(uc_engine *handle, uc_hook *h2, uc_hook_type type, void *callback, uintptr_t user, uint64_t begin, uint64_t end) {
    return uc_hook_add(handle, h2, type, callback, (void *)user, begin, end);
}

uc_err uc_hook_add_insn(uc_engine *handle, uc_hook *h2, uc_hook_type type, void *callback, uintptr_t user, uint64_t begin, uint64_t end, int insn) {
    return uc_hook_add(handle, h2, type, callback, (void *)user, begin, end, insn);
}

void hookCode_cgo(uc_engine *handle, uint64_t addr, uint32_t size, uintptr_t user) {
    hookCode(handle, addr, size, (void *)user);
}

bool hookMemInvalid_cgo(uc_engine *handle, uc_mem_type type, uint64_t addr, int size, int64_t value, uintptr_t user) {
    return hookMemInvalid(handle, type, addr, size, value, (void *)user);
}

void hookMemAccess_cgo(uc_engine *handle, uc_mem_type type, uint64_t addr, int size, int64_t value, uintptr_t user) {
    hookMemAccess(handle, type, addr, size, value, (void *)user);
}

void hookInterrupt_cgo(uc_engine *handle, uint32_t intno, uintptr_t user) {
    hookInterrupt(handle, intno, (void *)user);
}

uint32_t hookX86In_cgo(uc_engine *handle, uint32_t port, uint32_t size, uintptr_t user) {
    return hookX86In(handle, port, size, (void *)user);
}

void hookX86Out_cgo(uc_engine *handle, uint32_t port, uint32_t size, uint32_t value, uintptr_t user) {
    hookX86Out(handle, port, size, value, (void *)user);
}

void hookX86Syscall_cgo(uc_engine *handle, uintptr_t user) {
    hookX86Syscall(handle, (void *)user);
}
