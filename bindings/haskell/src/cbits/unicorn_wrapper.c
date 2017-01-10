#include "unicorn_wrapper.h"

void uc_close_wrapper(uc_engine *uc) {
    uc_close(uc);
}

void uc_close_dummy(uc_engine *uc) {
}

void uc_free_wrapper(void *mem) {
    uc_free(mem);
}
