#ifndef UNICORN_WRAPPER_H
#define UNICORN_WRAPPER_H

#include <stdint.h>
#include <unicorn/unicorn.h>

/*
 * Wrap Unicorn's uc_close function and ignore the returned error code.
 */
void uc_close_wrapper(uc_engine *uc);

/*
 * Doesn't actually do anything.
 */
void uc_close_dummy(uc_engine *uc);

/*
 * Wrappers for register read/write functions that accept int64_t pointers.
 */
uc_err uc_reg_write_wrapper(uc_engine *uc, int regid, const int64_t *value);
uc_err uc_reg_read_wrapper(uc_engine *uc, int regid, int64_t *value);
uc_err uc_reg_write_batch_wrapper(uc_engine *uc, int *regs, int64_t *vals, int count);
uc_err uc_reg_read_batch_wrapper(uc_engine *uc, int *regs, int64_t *vals, int count);

/*
 * Wrap Unicorn's uc_free function and ignore the returned error code.
 */
void uc_free_wrapper(void *context);

#endif
