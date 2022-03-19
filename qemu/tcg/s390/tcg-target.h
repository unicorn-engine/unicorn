/*
 * Tiny Code Generator for QEMU
 *
 * Copyright (c) 2009 Ulrich Hecht <uli@suse.de>
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
 * THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */

#ifndef S390_TCG_TARGET_H
#define S390_TCG_TARGET_H

#define TCG_TARGET_INSN_UNIT_SIZE 2
#define TCG_TARGET_TLB_DISPLACEMENT_BITS 19

typedef enum TCGReg {
    TCG_REG_R0 = 0,
    TCG_REG_R1,
    TCG_REG_R2,
    TCG_REG_R3,
    TCG_REG_R4,
    TCG_REG_R5,
    TCG_REG_R6,
    TCG_REG_R7,
    TCG_REG_R8,
    TCG_REG_R9,
    TCG_REG_R10,
    TCG_REG_R11,
    TCG_REG_R12,
    TCG_REG_R13,
    TCG_REG_R14,
    TCG_REG_R15
} TCGReg;

#define TCG_TARGET_NB_REGS 16

/* A list of relevant facilities used by this translator.  Some of these
   are required for proper operation, and these are checked at startup.  */

#define FACILITY_ZARCH_ACTIVE         (1ULL << (63 - 2))
#define FACILITY_LONG_DISP            (1ULL << (63 - 18))
#define FACILITY_EXT_IMM              (1ULL << (63 - 21))
#define FACILITY_GEN_INST_EXT         (1ULL << (63 - 34))
#define FACILITY_LOAD_ON_COND         (1ULL << (63 - 45))
#define FACILITY_FAST_BCR_SER         FACILITY_LOAD_ON_COND
#define FACILITY_DISTINCT_OPS         FACILITY_LOAD_ON_COND
#define FACILITY_LOAD_ON_COND2        (1ULL << (63 - 53))

extern uint64_t s390_facilities;

/* optional instructions */
#define TCG_TARGET_HAS_div2_i32       1
#define TCG_TARGET_HAS_rot_i32        1
#define TCG_TARGET_HAS_ext8s_i32      1
#define TCG_TARGET_HAS_ext16s_i32     1
#define TCG_TARGET_HAS_ext8u_i32      1
#define TCG_TARGET_HAS_ext16u_i32     1
#define TCG_TARGET_HAS_bswap16_i32    1
#define TCG_TARGET_HAS_bswap32_i32    1
#define TCG_TARGET_HAS_not_i32        0
#define TCG_TARGET_HAS_neg_i32        1
#define TCG_TARGET_HAS_andc_i32       0
#define TCG_TARGET_HAS_orc_i32        0
#define TCG_TARGET_HAS_eqv_i32        0
#define TCG_TARGET_HAS_nand_i32       0
#define TCG_TARGET_HAS_nor_i32        0
#define TCG_TARGET_HAS_clz_i32        0
#define TCG_TARGET_HAS_ctz_i32        0
#define TCG_TARGET_HAS_ctpop_i32      0
#define TCG_TARGET_HAS_deposit_i32    (s390_facilities & FACILITY_GEN_INST_EXT)
#define TCG_TARGET_HAS_extract_i32    (s390_facilities & FACILITY_GEN_INST_EXT)
#define TCG_TARGET_HAS_sextract_i32   0
#define TCG_TARGET_HAS_extract2_i32   0
#define TCG_TARGET_HAS_movcond_i32    1
#define TCG_TARGET_HAS_add2_i32       1
#define TCG_TARGET_HAS_sub2_i32       1
#define TCG_TARGET_HAS_mulu2_i32      0
#define TCG_TARGET_HAS_muls2_i32      0
#define TCG_TARGET_HAS_muluh_i32      0
#define TCG_TARGET_HAS_mulsh_i32      0
#define TCG_TARGET_HAS_extrl_i64_i32  0
#define TCG_TARGET_HAS_extrh_i64_i32  0
#define TCG_TARGET_HAS_goto_ptr       1
#define TCG_TARGET_HAS_direct_jump    (s390_facilities & FACILITY_GEN_INST_EXT)

#define TCG_TARGET_HAS_div2_i64       1
#define TCG_TARGET_HAS_rot_i64        1
#define TCG_TARGET_HAS_ext8s_i64      1
#define TCG_TARGET_HAS_ext16s_i64     1
#define TCG_TARGET_HAS_ext32s_i64     1
#define TCG_TARGET_HAS_ext8u_i64      1
#define TCG_TARGET_HAS_ext16u_i64     1
#define TCG_TARGET_HAS_ext32u_i64     1
#define TCG_TARGET_HAS_bswap16_i64    1
#define TCG_TARGET_HAS_bswap32_i64    1
#define TCG_TARGET_HAS_bswap64_i64    1
#define TCG_TARGET_HAS_not_i64        0
#define TCG_TARGET_HAS_neg_i64        1
#define TCG_TARGET_HAS_andc_i64       0
#define TCG_TARGET_HAS_orc_i64        0
#define TCG_TARGET_HAS_eqv_i64        0
#define TCG_TARGET_HAS_nand_i64       0
#define TCG_TARGET_HAS_nor_i64        0
#define TCG_TARGET_HAS_clz_i64        (s390_facilities & FACILITY_EXT_IMM)
#define TCG_TARGET_HAS_ctz_i64        0
#define TCG_TARGET_HAS_ctpop_i64      0
#define TCG_TARGET_HAS_deposit_i64    (s390_facilities & FACILITY_GEN_INST_EXT)
#define TCG_TARGET_HAS_extract_i64    (s390_facilities & FACILITY_GEN_INST_EXT)
#define TCG_TARGET_HAS_sextract_i64   0
#define TCG_TARGET_HAS_extract2_i64   0
#define TCG_TARGET_HAS_movcond_i64    1
#define TCG_TARGET_HAS_add2_i64       1
#define TCG_TARGET_HAS_sub2_i64       1
#define TCG_TARGET_HAS_mulu2_i64      1
#define TCG_TARGET_HAS_muls2_i64      0
#define TCG_TARGET_HAS_muluh_i64      0
#define TCG_TARGET_HAS_mulsh_i64      0

/* used for function call generation */
#define TCG_REG_CALL_STACK		TCG_REG_R15
#define TCG_TARGET_STACK_ALIGN		8
#define TCG_TARGET_CALL_STACK_OFFSET	160

#define TCG_TARGET_EXTEND_ARGS 1
#define TCG_TARGET_HAS_MEMORY_BSWAP   1

#define TCG_TARGET_DEFAULT_MO (TCG_MO_ALL & ~TCG_MO_ST_LD)

enum {
    TCG_AREG0 = TCG_REG_R10,
};

static inline void flush_icache_range(uintptr_t start, uintptr_t stop)
{
}

static inline void tb_target_set_jmp_target(uintptr_t tc_ptr,
                                            uintptr_t jmp_addr, uintptr_t addr)
{
    /* patch the branch destination */
    intptr_t disp = addr - (jmp_addr - 2);
    atomic_set((int32_t *)jmp_addr, disp / 2);
    /* no need to flush icache explicitly */
}

#ifdef CONFIG_SOFTMMU
#define TCG_TARGET_NEED_LDST_LABELS
#endif
#define TCG_TARGET_NEED_POOL_LABELS

#endif
