#include <unicorn/unicorn.h>
#include "_cgo_export.h"

uc_err uc_hook_add2(uch handle, uch *h2, uc_hook_t type, void *callback, void *user_data, int extra) {
    return uc_hook_add(handle, h2, type, callback, user_data, extra);
}

void hookCode_cgo(uch handle, uint64_t addr, uint32_t size, void *user) {
    hookCode(handle, addr, size, user);
}

bool hookMemInvalid_cgo(uch handle, uc_mem_type type, uint64_t addr, int size, int64_t value, void *user) {
    return hookMemInvalid(handle, type, addr, size, value, user);
}

void hookMemAccess_cgo(uch handle, uc_mem_type type, uint64_t addr, int size, int64_t value, void *user) {
    hookMemAccess(handle, type, addr, size, value, user);
}

void hookInterrupt_cgo(uch handle, uint32_t intno, void *user) {
    hookInterrupt(handle, intno, user);
}

uint32_t hookX86In_cgo(uch handle, uint32_t port, uint32_t size, void *user) {
    return hookX86In(handle, port, size, user);
}

void hookX86Out_cgo(uch handle, uint32_t port, uint32_t size, uint32_t value, void *user) {
    hookX86Out(handle, port, size, value, user);
}

void hookX86Syscall_cgo(uch handle, void *user) {
    hookX86Syscall(handle, user);
}
