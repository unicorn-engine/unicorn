uc_err uc_hook_add_i1(uc_engine *handle, uc_hook *h2, uc_hook_type type, void *callback, void *user_data, int arg1);
uc_err uc_hook_add_u2(uc_engine *handle, uc_hook *h2, uc_hook_type type, void *callback, void *user_data, uint64_t arg1, uint64_t arg2);
void hookCode_cgo(uc_engine *handle, uint64_t addr, uint32_t size, void *user);
bool hookMemInvalid_cgo(uc_engine *handle, uc_mem_type type, uint64_t addr, int size, int64_t value, void *user);
void hookMemAccess_cgo(uc_engine *handle, uc_mem_type type, uint64_t addr, int size, int64_t value, void *user);
void hookInterrupt_cgo(uc_engine *handle, uint32_t intno, void *user);
uint32_t hookX86In_cgo(uc_engine *handle, uint32_t port, uint32_t size, void *user);
void hookX86Out_cgo(uc_engine *handle, uint32_t port, uint32_t size, uint32_t value, void *user);
void hookX86Syscall_cgo(uc_engine *handle, void *user);
