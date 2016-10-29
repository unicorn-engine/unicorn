#ifndef UNICORN_WRAPPER_H
#define UNICORN_WRAPPER_H

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
 * Wrap Unicorn's uc_context_free function and ignore the returned error code.
 */
void uc_context_free_wrapper(uc_context *context);

#endif
