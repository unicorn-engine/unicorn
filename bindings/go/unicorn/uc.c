#include <stdlib.h>
#include <unicorn/unicorn.h>
#include "_cgo_export.h"

uc_err uc_reg_read_batch_helper(uc_engine *handle, int *regs, uint64_t *val_out, int count) {
    void **val_ref = malloc(sizeof(void *) * count);
    int i;
    for (i = 0; i < count; i++) {
        val_ref[i] = (void *)&val_out[i];
    }
    uc_err ret = uc_reg_read_batch(handle, regs, val_ref, count);
    free(val_ref);
    return ret;
}

uc_err uc_reg_write_batch_helper(uc_engine *handle, int *regs, uint64_t *val_in, int count) {
    void **val_ref = malloc(sizeof(void *) * count);
    int i;
    for (i = 0; i < count; i++) {
        val_ref[i] = (void *)&val_in[i];
    }
    uc_err ret = uc_reg_write_batch(handle, regs, (void *const *)val_ref, count);
    free(val_ref);
    return ret;
}
