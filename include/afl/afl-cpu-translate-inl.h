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

#include "config.h"
#include "types.h"

/* These are executed on code generation. Execution is in afl-unicorn-tcg-runtime-inl.h */
/* Roughly afl_gen_maybe_log -> gen_afl_maybe_log -> emit HELPER(afl_maybe_log) -> call afl_maybe_log */

static void afl_gen_maybe_log(TCGContext *s, uint64_t cur_loc) {

  if (!s->uc->afl_area_ptr) return;

  /* "Hash" */

  cur_loc = (cur_loc >> 4) ^ (cur_loc << 8);
  cur_loc &= MAP_SIZE - 7;

  /* Implement probabilistic instrumentation by looking at scrambled block
     address. This keeps the instrumented locations stable across runs. */

  if (cur_loc >= s->uc->afl_inst_rms) return;

    gen_afl_maybe_log(s, cur_loc);

}

// Currently only arm32 and x86. We undefine it for others to silence unused func compiler warnings.
#if defined(ARCH_HAS_COMPCOV)
static void afl_gen_compcov(TCGContext *s, uint64_t cur_loc, TCGv arg1,
                            TCGv arg2, TCGMemOp ot, int is_imm) {

  if (!s->uc->afl_compcov_level || !s->uc->afl_area_ptr) return;

  if (!is_imm && s->uc->afl_compcov_level < 2) return;

  cur_loc = (cur_loc >> 4) ^ (cur_loc << 8);
  cur_loc &= MAP_SIZE - 7;

  if (cur_loc >= s->uc->afl_inst_rms) return;

  switch (ot) {

    case MO_64: gen_afl_compcov_log_64(s, cur_loc, (TCGv_i64)arg1, (TCGv_i64)arg2); break;
    case MO_32: gen_afl_compcov_log_32(s, cur_loc, (TCGv_i32)arg1, (TCGv_i32)arg2); break;
    case MO_16: gen_afl_compcov_log_16(s, cur_loc, (TCGv_i32)arg1, (TCGv_i32)arg2); break;
    default: return;

  }

}
#endif