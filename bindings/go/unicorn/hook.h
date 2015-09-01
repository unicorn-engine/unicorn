uc_err uc_hook_add2(uch handle, uch *h2, uc_hook_t type, void *callback, void *user_data, int extra);
void hookCode_cgo(uch handle, uint64_t addr, uint32_t size, void *user);
bool hookMemInvalid_cgo(uch handle, uc_mem_type type, uint64_t addr, int size, int64_t value, void *user);
void hookMemAccess_cgo(uch handle, uc_mem_type type, uint64_t addr, int size, int64_t value, void *user);
void hookInterrupt_cgo(uch handle, uint32_t intno, void *user);
uint32_t hookX86In_cgo(uch handle, uint32_t port, uint32_t size, void *user);
void hookX86Out_cgo(uch handle, uint32_t port, uint32_t size, uint32_t value, void *user);
void hookX86Syscall_cgo(uch handle, void *user);
