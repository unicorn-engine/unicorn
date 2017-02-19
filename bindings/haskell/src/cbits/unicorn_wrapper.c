#include "unicorn_wrapper.h"

void uc_close_wrapper(uc_engine *uc) {
    uc_close(uc);
}

void uc_close_dummy(uc_engine *uc) {
}

uc_err uc_reg_write_wrapper(uc_engine *uc, int regid, const int64_t *value) {
    return uc_reg_write(uc, regid, (const void*) value);
}

uc_err uc_reg_read_wrapper(uc_engine *uc, int regid, int64_t *value) {
    return uc_reg_read(uc, regid, (void*) value);
}

void uc_free_wrapper(void *mem) {
    uc_free(mem);
}
