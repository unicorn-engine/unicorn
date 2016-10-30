#include "unicorn_wrapper.h"

void uc_close_wrapper(uc_engine *uc) {
    uc_close(uc);
}

void uc_close_dummy(uc_engine *uc) {
}

void uc_context_free_wrapper(uc_context *context) {
    uc_context_free(context);
}
