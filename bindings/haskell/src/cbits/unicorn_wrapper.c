#include <stdlib.h>

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

uc_err uc_reg_write_batch_wrapper(uc_engine *uc, int *regs, int64_t *vals, int count) {
    void **valsPtr = malloc(sizeof(void*) * count);
    int i;

    for (i = 0; i < count; ++i) {
        valsPtr[i] = (void*) &vals[i];
    }

    uc_err ret = uc_reg_write_batch(uc, regs, (void *const*) valsPtr, count);
    free(valsPtr);

    return ret;
}

uc_err uc_reg_read_batch_wrapper(uc_engine *uc, int *regs, int64_t *vals, int count) {
    void **valsPtr = malloc(sizeof(void*) * count);
    int i;

    for (i = 0; i < count; ++i) {
        valsPtr[i] = (void*) &vals[i];
    }

    uc_err ret = uc_reg_read_batch(uc, regs, valsPtr, count);
    free(valsPtr);

    return ret;
}

void uc_free_wrapper(void *mem) {
    uc_free(mem);
}
