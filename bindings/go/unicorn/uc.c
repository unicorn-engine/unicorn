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

uc_err uc_ctl_get_mode_helper(uc_engine *handle, int *mode) {
  return uc_ctl(handle, UC_CTL_READ(UC_CTL_UC_MODE, 1), (mode));
}

uc_err uc_ctl_get_page_size_helper(uc_engine *handle, uint32_t *ptr) {
  return uc_ctl(handle, UC_CTL_READ(UC_CTL_UC_PAGE_SIZE, 1), (ptr));
}

uc_err uc_ctl_set_page_size_helper(uc_engine *handle, uint32_t page_size) {
  return uc_ctl(handle, UC_CTL_WRITE(UC_CTL_UC_PAGE_SIZE, 1), (page_size));
}

uc_err uc_ctl_get_arch_helper(uc_engine *handle, int *arch) {
  return uc_ctl(handle, UC_CTL_READ(UC_CTL_UC_ARCH, 1), (arch));
}

uc_err uc_ctl_get_timeout_helper(uc_engine *handle, uint64_t *ptr) {
  return uc_ctl(handle, UC_CTL_READ(UC_CTL_UC_TIMEOUT, 1), (ptr));
}

uc_err uc_ctl_exits_enable_helper(uc_engine *handle) {
  return uc_ctl(handle, UC_CTL_WRITE(UC_CTL_UC_USE_EXITS, 1), 1);
}

uc_err uc_ctl_exits_disable_helper(uc_engine *handle) {
  return uc_ctl(handle, UC_CTL_WRITE(UC_CTL_UC_USE_EXITS, 1), 0);
}

uc_err uc_ctl_get_exits_cnt_helper(uc_engine *handle, size_t *ptr) {
  return uc_ctl(handle, UC_CTL_READ(UC_CTL_UC_EXITS_CNT, 1), (ptr));
}

uc_err uc_ctl_get_exits_helper(uc_engine *handle, uint64_t *exits, size_t len) {
  return uc_ctl(handle, UC_CTL_READ(UC_CTL_UC_EXITS, 2), (exits), (len));
}

uc_err uc_ctl_set_exits_helper(uc_engine *handle, uint64_t *exits, size_t len) {
  return uc_ctl(handle, UC_CTL_WRITE(UC_CTL_UC_EXITS, 2), (exits), (len));
}

uc_err uc_ctl_get_cpu_model_helper(uc_engine *handle, int *model) {
  return uc_ctl(handle, UC_CTL_READ(UC_CTL_CPU_MODEL, 1), (model));
}

uc_err uc_ctl_set_cpu_model_helper(uc_engine *handle, int model) {
  return uc_ctl(handle, UC_CTL_WRITE(UC_CTL_CPU_MODEL, 1), (model));
}

uc_err uc_ctl_remove_cache_helper(uc_engine *handle, uint64_t address, uint64_t end) {
  return uc_ctl(handle, UC_CTL_WRITE(UC_CTL_TB_REMOVE_CACHE, 2), (address), (end));
}

uc_err uc_ctl_request_cache_helper(uc_engine *handle, uint64_t address, uc_tb *tb) {
  return uc_ctl(handle, UC_CTL_READ_WRITE(UC_CTL_TB_REQUEST_CACHE, 2), (address), (tb));
}

uc_err uc_ctl_flush_tb_helper(uc_engine *handle) {
  return uc_ctl(handle, UC_CTL_WRITE(UC_CTL_TB_FLUSH, 0));
}

uc_err uc_ctl_flush_tlb_helper(uc_engine *handle) { 
  return uc_ctl(handle, UC_CTL_WRITE(UC_CTL_TLB_FLUSH, 0));
}

uc_err uc_ctl_tlb_mode_helper(uc_engine *handle, int mode) {
  return uc_ctl(handle, UC_CTL_WRITE(UC_CTL_TLB_TYPE, 1), (mode));
}

uc_err uc_ctl_get_tcg_buffer_size_helper(uc_engine *handle, uint32_t *size) {
  return uc_ctl(handle, UC_CTL_READ(UC_CTL_TCG_BUFFER_SIZE, 1), (size));
}

uc_err uc_ctl_set_tcg_buffer_size_helper(uc_engine *handle, uint32_t size) {
  return uc_ctl(handle, UC_CTL_WRITE(UC_CTL_TCG_BUFFER_SIZE, 1), (size));
}

uc_err uc_ctl_context_mode_helper(uc_engine *handle, int mode) {
  return uc_ctl(handle, UC_CTL_WRITE(UC_CTL_CONTEXT_MODE, 1), (mode));
}
