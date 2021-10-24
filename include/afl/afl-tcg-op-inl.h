/*
   american fuzzy lop++ - unicorn instrumentation
   ----------------------------------------------

   Originally written by Andrew Griffiths <agriffiths@google.com> and
                         Michal Zalewski

   Adapted for afl-unicorn by Dominik Maier <mail@dmnk.co>

   CompareCoverage and NeverZero counters by Andrea Fioraldi
                                  <andreafioraldi@gmail.com>

   Copyright 2015, 2016, 2017 Google Inc. All rights reserved.
   Copyright 2019 AFLplusplus Project. All rights reserved.

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at:

     http://www.apache.org/licenses/LICENSE-2.0

   This code is a shim patched into the separately-distributed source
   code of Unicorn 1.0.1. It leverages the built-in QEMU tracing functionality
   to implement AFL-style instrumentation and to take care of the remaining
   parts of the AFL fork server logic.

   The resulting libunicorn binary is essentially a standalone instrumentation
   tool; for an example of how to leverage it for other purposes, you can
   have a look at afl-showmap.c.

 */

static inline void gen_afl_maybe_log(TCGContext *tcg_ctx, uint64_t cur_loc) {

  TCGv_ptr tuc = tcg_const_ptr(tcg_ctx, tcg_ctx->uc);
  TCGv_i64 tcur_loc = tcg_const_i64(tcg_ctx, cur_loc);
  gen_helper_afl_maybe_log(tcg_ctx, tuc, tcur_loc);

}

static inline void gen_afl_compcov_log_16(TCGContext *tcg_ctx, uint64_t cur_loc,
                                          TCGv_i32 arg1, TCGv_i32 arg2) {
#if defined(AFL_DEBUG)
  printf("[d] Emitting 16 bit COMPCOV instrumentation for loc 0x%lx\n", cur_loc);
#endif

  TCGv_ptr tuc = tcg_const_ptr(tcg_ctx, tcg_ctx->uc);
  TCGv_i64 tcur_loc = tcg_const_i64(tcg_ctx, cur_loc);
  gen_helper_afl_compcov_log_16(tcg_ctx, tuc, tcur_loc, arg1, arg2);

}

static inline void gen_afl_compcov_log_32(TCGContext *tcg_ctx, uint64_t cur_loc,
                                          TCGv_i32 arg1, TCGv_i32 arg2) {
#if defined(AFL_DEBUG)
  printf("[d] Emitting 32 bit COMPCOV instrumentation for loc 0x%lux\n", cur_loc);
#endif

  TCGv_ptr tuc = tcg_const_ptr(tcg_ctx, tcg_ctx->uc);
  TCGv_i64 tcur_loc = tcg_const_i64(tcg_ctx, cur_loc);
  gen_helper_afl_compcov_log_32(tcg_ctx, tuc, tcur_loc, arg1, arg2);

}

static inline void gen_afl_compcov_log_64(TCGContext *tcg_ctx, uint64_t cur_loc,
                                          TCGv_i64 arg1, TCGv_i64 arg2) {
#if defined(AFL_DEBUG)
  printf("[d] Emitting 64 bit COMPCOV instrumentation for loc 0x%lux\n", cur_loc);
#endif

  TCGv_ptr tuc = tcg_const_ptr(tcg_ctx, tcg_ctx->uc);
  TCGv_i64 tcur_loc = tcg_const_i64(tcg_ctx, cur_loc);
  gen_helper_afl_compcov_log_64(tcg_ctx, tuc, tcur_loc, arg1, arg2);

}

