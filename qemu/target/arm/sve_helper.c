/*
 * ARM SVE Operations
 *
 * Copyright (c) 2018 Linaro, Ltd.
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, see <http://www.gnu.org/licenses/>.
 */

#include "qemu/osdep.h"
#include "cpu.h"
#include "internals.h"
#include "exec/exec-all.h"
#include "exec/cpu_ldst.h"
#include "exec/helper-proto.h"
#include "tcg/tcg-gvec-desc.h"
#include "fpu/softfloat.h"
#include "tcg/tcg.h"


/* Note that vector data is stored in host-endian 64-bit chunks,
   so addressing units smaller than that needs a host-endian fixup.  */
#ifdef HOST_WORDS_BIGENDIAN
#define H1(x)   ((x) ^ 7)
#define H1_2(x) ((x) ^ 6)
#define H1_4(x) ((x) ^ 4)
#define H2(x)   ((x) ^ 3)
#define H4(x)   ((x) ^ 1)
#else
#define H1(x)   (x)
#define H1_2(x) (x)
#define H1_4(x) (x)
#define H2(x)   (x)
#define H4(x)   (x)
#endif

/* Return a value for NZCV as per the ARM PredTest pseudofunction.
 *
 * The return value has bit 31 set if N is set, bit 1 set if Z is clear,
 * and bit 0 set if C is set.  Compare the definitions of these variables
 * within CPUARMState.
 */

/* For no G bits set, NZCV = C.  */
#define PREDTEST_INIT  1

/* This is an iterative function, called for each Pd and Pg word
 * moving forward.
 */
static uint32_t iter_predtest_fwd(uint64_t d, uint64_t g, uint32_t flags)
{
    if (likely(g)) {
        /* Compute N from first D & G.
           Use bit 2 to signal first G bit seen.  */
        if (!(flags & 4)) {
#ifdef _MSC_VER
            flags |= ((d & (g & (0 - g))) != 0) << 31;
#else
            flags |= ((d & (g & -g)) != 0) << 31;
#endif
            flags |= 4;
        }

        /* Accumulate Z from each D & G.  */
        flags |= ((d & g) != 0) << 1;

        /* Compute C from last !(D & G).  Replace previous.  */
        flags = deposit32(flags, 0, 1, (d & pow2floor(g)) == 0);
    }
    return flags;
}

/* This is an iterative function, called for each Pd and Pg word
 * moving backward.
 */
static uint32_t iter_predtest_bwd(uint64_t d, uint64_t g, uint32_t flags)
{
    if (likely(g)) {
        /* Compute C from first (i.e last) !(D & G).
           Use bit 2 to signal first G bit seen.  */
        if (!(flags & 4)) {
            flags += 4 - 1; /* add bit 2, subtract C from PREDTEST_INIT */
            flags |= (d & pow2floor(g)) == 0;
        }

        /* Accumulate Z from each D & G.  */
        flags |= ((d & g) != 0) << 1;

        /* Compute N from last (i.e first) D & G.  Replace previous.  */
#ifdef _MSC_VER
        flags = deposit32(flags, 31, 1, (d & (g & (0 - g))) != 0);
#else
        flags = deposit32(flags, 31, 1, (d & (g & -g)) != 0);
#endif
    }
    return flags;
}

/* The same for a single word predicate.  */
uint32_t HELPER(sve_predtest1)(uint64_t d, uint64_t g)
{
    return iter_predtest_fwd(d, g, PREDTEST_INIT);
}

/* The same for a multi-word predicate.  */
uint32_t HELPER(sve_predtest)(void *vd, void *vg, uint32_t words)
{
    uint32_t flags = PREDTEST_INIT;
    uint64_t *d = vd, *g = vg;
    uintptr_t i = 0;

    do {
        flags = iter_predtest_fwd(d[i], g[i], flags);
    } while (++i < words);

    return flags;
}

/* Expand active predicate bits to bytes, for byte elements.
 *  for (i = 0; i < 256; ++i) {
 *      unsigned long m = 0;
 *      for (j = 0; j < 8; j++) {
 *          if ((i >> j) & 1) {
 *              m |= 0xfful << (j << 3);
 *          }
 *      }
 *      printf("0x%016lx,\n", m);
 *  }
 */
static inline uint64_t expand_pred_b(uint8_t byte)
{
    static const uint64_t word[256] = {
        0x0000000000000000, 0x00000000000000ff, 0x000000000000ff00,
        0x000000000000ffff, 0x0000000000ff0000, 0x0000000000ff00ff,
        0x0000000000ffff00, 0x0000000000ffffff, 0x00000000ff000000,
        0x00000000ff0000ff, 0x00000000ff00ff00, 0x00000000ff00ffff,
        0x00000000ffff0000, 0x00000000ffff00ff, 0x00000000ffffff00,
        0x00000000ffffffff, 0x000000ff00000000, 0x000000ff000000ff,
        0x000000ff0000ff00, 0x000000ff0000ffff, 0x000000ff00ff0000,
        0x000000ff00ff00ff, 0x000000ff00ffff00, 0x000000ff00ffffff,
        0x000000ffff000000, 0x000000ffff0000ff, 0x000000ffff00ff00,
        0x000000ffff00ffff, 0x000000ffffff0000, 0x000000ffffff00ff,
        0x000000ffffffff00, 0x000000ffffffffff, 0x0000ff0000000000,
        0x0000ff00000000ff, 0x0000ff000000ff00, 0x0000ff000000ffff,
        0x0000ff0000ff0000, 0x0000ff0000ff00ff, 0x0000ff0000ffff00,
        0x0000ff0000ffffff, 0x0000ff00ff000000, 0x0000ff00ff0000ff,
        0x0000ff00ff00ff00, 0x0000ff00ff00ffff, 0x0000ff00ffff0000,
        0x0000ff00ffff00ff, 0x0000ff00ffffff00, 0x0000ff00ffffffff,
        0x0000ffff00000000, 0x0000ffff000000ff, 0x0000ffff0000ff00,
        0x0000ffff0000ffff, 0x0000ffff00ff0000, 0x0000ffff00ff00ff,
        0x0000ffff00ffff00, 0x0000ffff00ffffff, 0x0000ffffff000000,
        0x0000ffffff0000ff, 0x0000ffffff00ff00, 0x0000ffffff00ffff,
        0x0000ffffffff0000, 0x0000ffffffff00ff, 0x0000ffffffffff00,
        0x0000ffffffffffff, 0x00ff000000000000, 0x00ff0000000000ff,
        0x00ff00000000ff00, 0x00ff00000000ffff, 0x00ff000000ff0000,
        0x00ff000000ff00ff, 0x00ff000000ffff00, 0x00ff000000ffffff,
        0x00ff0000ff000000, 0x00ff0000ff0000ff, 0x00ff0000ff00ff00,
        0x00ff0000ff00ffff, 0x00ff0000ffff0000, 0x00ff0000ffff00ff,
        0x00ff0000ffffff00, 0x00ff0000ffffffff, 0x00ff00ff00000000,
        0x00ff00ff000000ff, 0x00ff00ff0000ff00, 0x00ff00ff0000ffff,
        0x00ff00ff00ff0000, 0x00ff00ff00ff00ff, 0x00ff00ff00ffff00,
        0x00ff00ff00ffffff, 0x00ff00ffff000000, 0x00ff00ffff0000ff,
        0x00ff00ffff00ff00, 0x00ff00ffff00ffff, 0x00ff00ffffff0000,
        0x00ff00ffffff00ff, 0x00ff00ffffffff00, 0x00ff00ffffffffff,
        0x00ffff0000000000, 0x00ffff00000000ff, 0x00ffff000000ff00,
        0x00ffff000000ffff, 0x00ffff0000ff0000, 0x00ffff0000ff00ff,
        0x00ffff0000ffff00, 0x00ffff0000ffffff, 0x00ffff00ff000000,
        0x00ffff00ff0000ff, 0x00ffff00ff00ff00, 0x00ffff00ff00ffff,
        0x00ffff00ffff0000, 0x00ffff00ffff00ff, 0x00ffff00ffffff00,
        0x00ffff00ffffffff, 0x00ffffff00000000, 0x00ffffff000000ff,
        0x00ffffff0000ff00, 0x00ffffff0000ffff, 0x00ffffff00ff0000,
        0x00ffffff00ff00ff, 0x00ffffff00ffff00, 0x00ffffff00ffffff,
        0x00ffffffff000000, 0x00ffffffff0000ff, 0x00ffffffff00ff00,
        0x00ffffffff00ffff, 0x00ffffffffff0000, 0x00ffffffffff00ff,
        0x00ffffffffffff00, 0x00ffffffffffffff, 0xff00000000000000,
        0xff000000000000ff, 0xff0000000000ff00, 0xff0000000000ffff,
        0xff00000000ff0000, 0xff00000000ff00ff, 0xff00000000ffff00,
        0xff00000000ffffff, 0xff000000ff000000, 0xff000000ff0000ff,
        0xff000000ff00ff00, 0xff000000ff00ffff, 0xff000000ffff0000,
        0xff000000ffff00ff, 0xff000000ffffff00, 0xff000000ffffffff,
        0xff0000ff00000000, 0xff0000ff000000ff, 0xff0000ff0000ff00,
        0xff0000ff0000ffff, 0xff0000ff00ff0000, 0xff0000ff00ff00ff,
        0xff0000ff00ffff00, 0xff0000ff00ffffff, 0xff0000ffff000000,
        0xff0000ffff0000ff, 0xff0000ffff00ff00, 0xff0000ffff00ffff,
        0xff0000ffffff0000, 0xff0000ffffff00ff, 0xff0000ffffffff00,
        0xff0000ffffffffff, 0xff00ff0000000000, 0xff00ff00000000ff,
        0xff00ff000000ff00, 0xff00ff000000ffff, 0xff00ff0000ff0000,
        0xff00ff0000ff00ff, 0xff00ff0000ffff00, 0xff00ff0000ffffff,
        0xff00ff00ff000000, 0xff00ff00ff0000ff, 0xff00ff00ff00ff00,
        0xff00ff00ff00ffff, 0xff00ff00ffff0000, 0xff00ff00ffff00ff,
        0xff00ff00ffffff00, 0xff00ff00ffffffff, 0xff00ffff00000000,
        0xff00ffff000000ff, 0xff00ffff0000ff00, 0xff00ffff0000ffff,
        0xff00ffff00ff0000, 0xff00ffff00ff00ff, 0xff00ffff00ffff00,
        0xff00ffff00ffffff, 0xff00ffffff000000, 0xff00ffffff0000ff,
        0xff00ffffff00ff00, 0xff00ffffff00ffff, 0xff00ffffffff0000,
        0xff00ffffffff00ff, 0xff00ffffffffff00, 0xff00ffffffffffff,
        0xffff000000000000, 0xffff0000000000ff, 0xffff00000000ff00,
        0xffff00000000ffff, 0xffff000000ff0000, 0xffff000000ff00ff,
        0xffff000000ffff00, 0xffff000000ffffff, 0xffff0000ff000000,
        0xffff0000ff0000ff, 0xffff0000ff00ff00, 0xffff0000ff00ffff,
        0xffff0000ffff0000, 0xffff0000ffff00ff, 0xffff0000ffffff00,
        0xffff0000ffffffff, 0xffff00ff00000000, 0xffff00ff000000ff,
        0xffff00ff0000ff00, 0xffff00ff0000ffff, 0xffff00ff00ff0000,
        0xffff00ff00ff00ff, 0xffff00ff00ffff00, 0xffff00ff00ffffff,
        0xffff00ffff000000, 0xffff00ffff0000ff, 0xffff00ffff00ff00,
        0xffff00ffff00ffff, 0xffff00ffffff0000, 0xffff00ffffff00ff,
        0xffff00ffffffff00, 0xffff00ffffffffff, 0xffffff0000000000,
        0xffffff00000000ff, 0xffffff000000ff00, 0xffffff000000ffff,
        0xffffff0000ff0000, 0xffffff0000ff00ff, 0xffffff0000ffff00,
        0xffffff0000ffffff, 0xffffff00ff000000, 0xffffff00ff0000ff,
        0xffffff00ff00ff00, 0xffffff00ff00ffff, 0xffffff00ffff0000,
        0xffffff00ffff00ff, 0xffffff00ffffff00, 0xffffff00ffffffff,
        0xffffffff00000000, 0xffffffff000000ff, 0xffffffff0000ff00,
        0xffffffff0000ffff, 0xffffffff00ff0000, 0xffffffff00ff00ff,
        0xffffffff00ffff00, 0xffffffff00ffffff, 0xffffffffff000000,
        0xffffffffff0000ff, 0xffffffffff00ff00, 0xffffffffff00ffff,
        0xffffffffffff0000, 0xffffffffffff00ff, 0xffffffffffffff00,
        0xffffffffffffffff,
    };
    return word[byte];
}

/* Similarly for half-word elements.
 *  for (i = 0; i < 256; ++i) {
 *      unsigned long m = 0;
 *      if (i & 0xaa) {
 *          continue;
 *      }
 *      for (j = 0; j < 8; j += 2) {
 *          if ((i >> j) & 1) {
 *              m |= 0xfffful << (j << 3);
 *          }
 *      }
 *      printf("[0x%x] = 0x%016lx,\n", i, m);
 *  }
 */
static inline uint64_t expand_pred_h(uint8_t byte)
{
    static const uint64_t word[] = {
        [0x01] = 0x000000000000ffff, [0x04] = 0x00000000ffff0000,
        [0x05] = 0x00000000ffffffff, [0x10] = 0x0000ffff00000000,
        [0x11] = 0x0000ffff0000ffff, [0x14] = 0x0000ffffffff0000,
        [0x15] = 0x0000ffffffffffff, [0x40] = 0xffff000000000000,
        [0x41] = 0xffff00000000ffff, [0x44] = 0xffff0000ffff0000,
        [0x45] = 0xffff0000ffffffff, [0x50] = 0xffffffff00000000,
        [0x51] = 0xffffffff0000ffff, [0x54] = 0xffffffffffff0000,
        [0x55] = 0xffffffffffffffff,
    };
    return word[byte & 0x55];
}

/* Similarly for single word elements.  */
static inline uint64_t expand_pred_s(uint8_t byte)
{
    static const uint64_t word[] = {
        [0x01] = 0x00000000ffffffffull,
        [0x10] = 0xffffffff00000000ull,
        [0x11] = 0xffffffffffffffffull,
    };
    return word[byte & 0x11];
}

/* Swap 16-bit words within a 32-bit word.  */
static inline uint32_t hswap32(uint32_t h)
{
    return rol32(h, 16);
}

/* Swap 16-bit words within a 64-bit word.  */
static inline uint64_t hswap64(uint64_t h)
{
    uint64_t m = 0x0000ffff0000ffffull;
    h = rol64(h, 32);
    return ((h & m) << 16) | ((h >> 16) & m);
}

/* Swap 32-bit words within a 64-bit word.  */
static inline uint64_t wswap64(uint64_t h)
{
    return rol64(h, 32);
}

#define LOGICAL_PPPP(NAME, FUNC) \
void HELPER(NAME)(void *vd, void *vn, void *vm, void *vg, uint32_t desc)  \
{                                                                         \
    uintptr_t opr_sz = simd_oprsz(desc);                                  \
    uint64_t *d = vd, *n = vn, *m = vm, *g = vg;                          \
    uintptr_t i;                                                          \
    for (i = 0; i < opr_sz / 8; ++i) {                                    \
        d[i] = FUNC(n[i], m[i], g[i]);                                    \
    }                                                                     \
}

#define DO_AND(N, M, G)  (((N) & (M)) & (G))
#define DO_BIC(N, M, G)  (((N) & ~(M)) & (G))
#define DO_EOR(N, M, G)  (((N) ^ (M)) & (G))
#define DO_ORR(N, M, G)  (((N) | (M)) & (G))
#define DO_ORN(N, M, G)  (((N) | ~(M)) & (G))
#define DO_NOR(N, M, G)  (~((N) | (M)) & (G))
#define DO_NAND(N, M, G) (~((N) & (M)) & (G))
#define DO_SEL(N, M, G)  (((N) & (G)) | ((M) & ~(G)))

LOGICAL_PPPP(sve_and_pppp, DO_AND)
LOGICAL_PPPP(sve_bic_pppp, DO_BIC)
LOGICAL_PPPP(sve_eor_pppp, DO_EOR)
LOGICAL_PPPP(sve_sel_pppp, DO_SEL)
LOGICAL_PPPP(sve_orr_pppp, DO_ORR)
LOGICAL_PPPP(sve_orn_pppp, DO_ORN)
LOGICAL_PPPP(sve_nor_pppp, DO_NOR)
LOGICAL_PPPP(sve_nand_pppp, DO_NAND)

#undef DO_AND
#undef DO_BIC
#undef DO_EOR
#undef DO_ORR
#undef DO_ORN
#undef DO_NOR
#undef DO_NAND
#undef DO_SEL
#undef LOGICAL_PPPP

/* Fully general three-operand expander, controlled by a predicate.
 * This is complicated by the host-endian storage of the register file.
 */
/* ??? I don't expect the compiler could ever vectorize this itself.
 * With some tables we can convert bit masks to byte masks, and with
 * extra care wrt byte/word ordering we could use gcc generic vectors
 * and do 16 bytes at a time.
 */
#define DO_ZPZZ(NAME, TYPE, H, OP)                                       \
void HELPER(NAME)(void *vd, void *vn, void *vm, void *vg, uint32_t desc) \
{                                                                       \
    intptr_t i, opr_sz = simd_oprsz(desc);                              \
    for (i = 0; i < opr_sz; ) {                                         \
        uint16_t pg = *(uint16_t *)((char *)vg + H1_2(i >> 3));                 \
        do {                                                            \
            if (pg & 1) {                                               \
                TYPE nn = *(TYPE *)((char *)vn + H(i));                         \
                TYPE mm = *(TYPE *)((char *)vm + H(i));                         \
                *(TYPE *)((char *)vd + H(i)) = OP(nn, mm);                      \
            }                                                           \
            i += sizeof(TYPE), pg >>= sizeof(TYPE);                     \
        } while (i & 15);                                               \
    }                                                                   \
}

/* Similarly, specialized for 64-bit operands.  */
#define DO_ZPZZ_D(NAME, TYPE, OP)                                \
void HELPER(NAME)(void *vd, void *vn, void *vm, void *vg, uint32_t desc) \
{                                                               \
    intptr_t i, opr_sz = simd_oprsz(desc) / 8;                  \
    TYPE *d = vd, *n = vn, *m = vm;                             \
    uint8_t *pg = vg;                                           \
    for (i = 0; i < opr_sz; i += 1) {                           \
        if (pg[H1(i)] & 1) {                                    \
            TYPE nn = n[i], mm = m[i];                          \
            d[i] = OP(nn, mm);                                  \
        }                                                       \
    }                                                           \
}

#define DO_AND(N, M)  (N & M)
#define DO_EOR(N, M)  (N ^ M)
#define DO_ORR(N, M)  (N | M)
#define DO_BIC(N, M)  (N & ~M)
#define DO_ADD(N, M)  (N + M)
#define DO_SUB(N, M)  (N - M)
#define DO_MAX(N, M)  ((N) >= (M) ? (N) : (M))
#define DO_MIN(N, M)  ((N) >= (M) ? (M) : (N))
#define DO_ABD(N, M)  ((N) >= (M) ? (N) - (M) : (M) - (N))
#define DO_MUL(N, M)  (N * M)


/*
 * We must avoid the C undefined behaviour cases: division by
 * zero and signed division of INT_MIN by -1. Both of these
 * have architecturally defined required results for Arm.
 * We special case all signed divisions by -1 to avoid having
 * to deduce the minimum integer for the type involved.
 */
#define DO_SDIV(N, M) (unlikely(M == 0) ? 0 : unlikely(M == -1) ? -N : N / M)
#define DO_UDIV(N, M) (unlikely(M == 0) ? 0 : N / M)

DO_ZPZZ(sve_and_zpzz_b, uint8_t, H1, DO_AND)
DO_ZPZZ(sve_and_zpzz_h, uint16_t, H1_2, DO_AND)
DO_ZPZZ(sve_and_zpzz_s, uint32_t, H1_4, DO_AND)
DO_ZPZZ_D(sve_and_zpzz_d, uint64_t, DO_AND)

DO_ZPZZ(sve_orr_zpzz_b, uint8_t, H1, DO_ORR)
DO_ZPZZ(sve_orr_zpzz_h, uint16_t, H1_2, DO_ORR)
DO_ZPZZ(sve_orr_zpzz_s, uint32_t, H1_4, DO_ORR)
DO_ZPZZ_D(sve_orr_zpzz_d, uint64_t, DO_ORR)

DO_ZPZZ(sve_eor_zpzz_b, uint8_t, H1, DO_EOR)
DO_ZPZZ(sve_eor_zpzz_h, uint16_t, H1_2, DO_EOR)
DO_ZPZZ(sve_eor_zpzz_s, uint32_t, H1_4, DO_EOR)
DO_ZPZZ_D(sve_eor_zpzz_d, uint64_t, DO_EOR)

DO_ZPZZ(sve_bic_zpzz_b, uint8_t, H1, DO_BIC)
DO_ZPZZ(sve_bic_zpzz_h, uint16_t, H1_2, DO_BIC)
DO_ZPZZ(sve_bic_zpzz_s, uint32_t, H1_4, DO_BIC)
DO_ZPZZ_D(sve_bic_zpzz_d, uint64_t, DO_BIC)

DO_ZPZZ(sve_add_zpzz_b, uint8_t, H1, DO_ADD)
DO_ZPZZ(sve_add_zpzz_h, uint16_t, H1_2, DO_ADD)
DO_ZPZZ(sve_add_zpzz_s, uint32_t, H1_4, DO_ADD)
DO_ZPZZ_D(sve_add_zpzz_d, uint64_t, DO_ADD)

DO_ZPZZ(sve_sub_zpzz_b, uint8_t, H1, DO_SUB)
DO_ZPZZ(sve_sub_zpzz_h, uint16_t, H1_2, DO_SUB)
DO_ZPZZ(sve_sub_zpzz_s, uint32_t, H1_4, DO_SUB)
DO_ZPZZ_D(sve_sub_zpzz_d, uint64_t, DO_SUB)

DO_ZPZZ(sve_smax_zpzz_b, int8_t, H1, DO_MAX)
DO_ZPZZ(sve_smax_zpzz_h, int16_t, H1_2, DO_MAX)
DO_ZPZZ(sve_smax_zpzz_s, int32_t, H1_4, DO_MAX)
DO_ZPZZ_D(sve_smax_zpzz_d, int64_t, DO_MAX)

DO_ZPZZ(sve_umax_zpzz_b, uint8_t, H1, DO_MAX)
DO_ZPZZ(sve_umax_zpzz_h, uint16_t, H1_2, DO_MAX)
DO_ZPZZ(sve_umax_zpzz_s, uint32_t, H1_4, DO_MAX)
DO_ZPZZ_D(sve_umax_zpzz_d, uint64_t, DO_MAX)

DO_ZPZZ(sve_smin_zpzz_b, int8_t,  H1, DO_MIN)
DO_ZPZZ(sve_smin_zpzz_h, int16_t,  H1_2, DO_MIN)
DO_ZPZZ(sve_smin_zpzz_s, int32_t,  H1_4, DO_MIN)
DO_ZPZZ_D(sve_smin_zpzz_d, int64_t,  DO_MIN)

DO_ZPZZ(sve_umin_zpzz_b, uint8_t, H1, DO_MIN)
DO_ZPZZ(sve_umin_zpzz_h, uint16_t, H1_2, DO_MIN)
DO_ZPZZ(sve_umin_zpzz_s, uint32_t, H1_4, DO_MIN)
DO_ZPZZ_D(sve_umin_zpzz_d, uint64_t, DO_MIN)

DO_ZPZZ(sve_sabd_zpzz_b, int8_t,  H1, DO_ABD)
DO_ZPZZ(sve_sabd_zpzz_h, int16_t,  H1_2, DO_ABD)
DO_ZPZZ(sve_sabd_zpzz_s, int32_t,  H1_4, DO_ABD)
DO_ZPZZ_D(sve_sabd_zpzz_d, int64_t,  DO_ABD)

DO_ZPZZ(sve_uabd_zpzz_b, uint8_t, H1, DO_ABD)
DO_ZPZZ(sve_uabd_zpzz_h, uint16_t, H1_2, DO_ABD)
DO_ZPZZ(sve_uabd_zpzz_s, uint32_t, H1_4, DO_ABD)
DO_ZPZZ_D(sve_uabd_zpzz_d, uint64_t, DO_ABD)

/* Because the computation type is at least twice as large as required,
   these work for both signed and unsigned source types.  */
static inline uint8_t do_mulh_b(int32_t n, int32_t m)
{
    return (n * m) >> 8;
}

static inline uint16_t do_mulh_h(int32_t n, int32_t m)
{
    return (n * m) >> 16;
}

static inline uint32_t do_mulh_s(int64_t n, int64_t m)
{
    return (n * m) >> 32;
}

static inline uint64_t do_smulh_d(uint64_t n, uint64_t m)
{
    uint64_t lo, hi;
    muls64(&lo, &hi, n, m);
    return hi;
}

static inline uint64_t do_umulh_d(uint64_t n, uint64_t m)
{
    uint64_t lo, hi;
    mulu64(&lo, &hi, n, m);
    return hi;
}

DO_ZPZZ(sve_mul_zpzz_b, uint8_t, H1, DO_MUL)
DO_ZPZZ(sve_mul_zpzz_h, uint16_t, H1_2, DO_MUL)
DO_ZPZZ(sve_mul_zpzz_s, uint32_t, H1_4, DO_MUL)
DO_ZPZZ_D(sve_mul_zpzz_d, uint64_t, DO_MUL)

DO_ZPZZ(sve_smulh_zpzz_b, int8_t, H1, do_mulh_b)
DO_ZPZZ(sve_smulh_zpzz_h, int16_t, H1_2, do_mulh_h)
DO_ZPZZ(sve_smulh_zpzz_s, int32_t, H1_4, do_mulh_s)
DO_ZPZZ_D(sve_smulh_zpzz_d, uint64_t, do_smulh_d)

DO_ZPZZ(sve_umulh_zpzz_b, uint8_t, H1, do_mulh_b)
DO_ZPZZ(sve_umulh_zpzz_h, uint16_t, H1_2, do_mulh_h)
DO_ZPZZ(sve_umulh_zpzz_s, uint32_t, H1_4, do_mulh_s)
DO_ZPZZ_D(sve_umulh_zpzz_d, uint64_t, do_umulh_d)

DO_ZPZZ(sve_sdiv_zpzz_s, int32_t, H1_4, DO_SDIV)
DO_ZPZZ_D(sve_sdiv_zpzz_d, int64_t, DO_SDIV)

DO_ZPZZ(sve_udiv_zpzz_s, uint32_t, H1_4, DO_UDIV)
DO_ZPZZ_D(sve_udiv_zpzz_d, uint64_t, DO_UDIV)

/* Note that all bits of the shift are significant
   and not modulo the element size.  */
#define DO_ASR(N, M)  (N >> MIN(M, sizeof(N) * 8 - 1))
#define DO_LSR(N, M)  (M < sizeof(N) * 8 ? N >> M : 0)
#define DO_LSL(N, M)  (M < sizeof(N) * 8 ? N << M : 0)

DO_ZPZZ(sve_asr_zpzz_b, int8_t, H1, DO_ASR)
DO_ZPZZ(sve_lsr_zpzz_b, uint8_t, H1_2, DO_LSR)
DO_ZPZZ(sve_lsl_zpzz_b, uint8_t, H1_4, DO_LSL)

DO_ZPZZ(sve_asr_zpzz_h, int16_t, H1, DO_ASR)
DO_ZPZZ(sve_lsr_zpzz_h, uint16_t, H1_2, DO_LSR)
DO_ZPZZ(sve_lsl_zpzz_h, uint16_t, H1_4, DO_LSL)

DO_ZPZZ(sve_asr_zpzz_s, int32_t, H1, DO_ASR)
DO_ZPZZ(sve_lsr_zpzz_s, uint32_t, H1_2, DO_LSR)
DO_ZPZZ(sve_lsl_zpzz_s, uint32_t, H1_4, DO_LSL)

DO_ZPZZ_D(sve_asr_zpzz_d, int64_t, DO_ASR)
DO_ZPZZ_D(sve_lsr_zpzz_d, uint64_t, DO_LSR)
DO_ZPZZ_D(sve_lsl_zpzz_d, uint64_t, DO_LSL)

#undef DO_ZPZZ
#undef DO_ZPZZ_D

/* Three-operand expander, controlled by a predicate, in which the
 * third operand is "wide".  That is, for D = N op M, the same 64-bit
 * value of M is used with all of the narrower values of N.
 */
#define DO_ZPZW(NAME, TYPE, TYPEW, H, OP)                               \
void HELPER(NAME)(void *vd, void *vn, void *vm, void *vg, uint32_t desc) \
{                                                                       \
    intptr_t i, opr_sz = simd_oprsz(desc);                              \
    for (i = 0; i < opr_sz; ) {                                         \
        uint8_t pg = *(uint8_t *)((char *)vg + H1(i >> 3));                     \
        TYPEW mm = *(TYPEW *)((char *)vm + i);                                  \
        do {                                                            \
            if (pg & 1) {                                               \
                TYPE nn = *(TYPE *)((char *)vn + H(i));                         \
                *(TYPE *)((char *)vd + H(i)) = OP(nn, mm);                      \
            }                                                           \
            i += sizeof(TYPE), pg >>= sizeof(TYPE);                     \
        } while (i & 7);                                                \
    }                                                                   \
}

DO_ZPZW(sve_asr_zpzw_b, int8_t, uint64_t, H1, DO_ASR)
DO_ZPZW(sve_lsr_zpzw_b, uint8_t, uint64_t, H1, DO_LSR)
DO_ZPZW(sve_lsl_zpzw_b, uint8_t, uint64_t, H1, DO_LSL)

DO_ZPZW(sve_asr_zpzw_h, int16_t, uint64_t, H1_2, DO_ASR)
DO_ZPZW(sve_lsr_zpzw_h, uint16_t, uint64_t, H1_2, DO_LSR)
DO_ZPZW(sve_lsl_zpzw_h, uint16_t, uint64_t, H1_2, DO_LSL)

DO_ZPZW(sve_asr_zpzw_s, int32_t, uint64_t, H1_4, DO_ASR)
DO_ZPZW(sve_lsr_zpzw_s, uint32_t, uint64_t, H1_4, DO_LSR)
DO_ZPZW(sve_lsl_zpzw_s, uint32_t, uint64_t, H1_4, DO_LSL)

#undef DO_ZPZW

/* Fully general two-operand expander, controlled by a predicate.
 */
#define DO_ZPZ(NAME, TYPE, H, OP)                               \
void HELPER(NAME)(void *vd, void *vn, void *vg, uint32_t desc)  \
{                                                               \
    intptr_t i, opr_sz = simd_oprsz(desc);                      \
    for (i = 0; i < opr_sz; ) {                                 \
        uint16_t pg = *(uint16_t *)((char *)vg + H1_2(i >> 3));         \
        do {                                                    \
            if (pg & 1) {                                       \
                TYPE nn = *(TYPE *)((char *)vn + H(i));                 \
                *(TYPE *)((char *)vd + H(i)) = OP(nn);                  \
            }                                                   \
            i += sizeof(TYPE), pg >>= sizeof(TYPE);             \
        } while (i & 15);                                       \
    }                                                           \
}

/* Similarly, specialized for 64-bit operands.  */
#define DO_ZPZ_D(NAME, TYPE, OP)                                \
void HELPER(NAME)(void *vd, void *vn, void *vg, uint32_t desc)  \
{                                                               \
    intptr_t i, opr_sz = simd_oprsz(desc) / 8;                  \
    TYPE *d = vd, *n = vn;                                      \
    uint8_t *pg = vg;                                           \
    for (i = 0; i < opr_sz; i += 1) {                           \
        if (pg[H1(i)] & 1) {                                    \
            TYPE nn = n[i];                                     \
            d[i] = OP(nn);                                      \
        }                                                       \
    }                                                           \
}

#define DO_CLS_B(N)   (clrsb32(N) - 24)
#define DO_CLS_H(N)   (clrsb32(N) - 16)

DO_ZPZ(sve_cls_b, int8_t, H1, DO_CLS_B)
DO_ZPZ(sve_cls_h, int16_t, H1_2, DO_CLS_H)
DO_ZPZ(sve_cls_s, int32_t, H1_4, clrsb32)
DO_ZPZ_D(sve_cls_d, int64_t, clrsb64)

#define DO_CLZ_B(N)   (clz32(N) - 24)
#define DO_CLZ_H(N)   (clz32(N) - 16)

DO_ZPZ(sve_clz_b, uint8_t, H1, DO_CLZ_B)
DO_ZPZ(sve_clz_h, uint16_t, H1_2, DO_CLZ_H)
DO_ZPZ(sve_clz_s, uint32_t, H1_4, clz32)
DO_ZPZ_D(sve_clz_d, uint64_t, clz64)

DO_ZPZ(sve_cnt_zpz_b, uint8_t, H1, ctpop8)
DO_ZPZ(sve_cnt_zpz_h, uint16_t, H1_2, ctpop16)
DO_ZPZ(sve_cnt_zpz_s, uint32_t, H1_4, ctpop32)
DO_ZPZ_D(sve_cnt_zpz_d, uint64_t, ctpop64)

#define DO_CNOT(N)    (N == 0)

DO_ZPZ(sve_cnot_b, uint8_t, H1, DO_CNOT)
DO_ZPZ(sve_cnot_h, uint16_t, H1_2, DO_CNOT)
DO_ZPZ(sve_cnot_s, uint32_t, H1_4, DO_CNOT)
DO_ZPZ_D(sve_cnot_d, uint64_t, DO_CNOT)

#ifdef _MSC_VER
#define DO_FABS16(N)    (N & ((uint16_t)-1 >> 1))
#define DO_FABS32(N)    (N & ((uint32_t)-1 >> 1))
#define DO_FABS64(N)    (N & ((uint64_t)-1 >> 1))

DO_ZPZ(sve_fabs_h, uint16_t, H1_2, DO_FABS16)
DO_ZPZ(sve_fabs_s, uint32_t, H1_4, DO_FABS32)
DO_ZPZ_D(sve_fabs_d, uint64_t, DO_FABS64)
#else
#define DO_FABS(N)    (N & ((__typeof(N))-1 >> 1))

DO_ZPZ(sve_fabs_h, uint16_t, H1_2, DO_FABS)
DO_ZPZ(sve_fabs_s, uint32_t, H1_4, DO_FABS)
DO_ZPZ_D(sve_fabs_d, uint64_t, DO_FABS)
#endif

#ifdef _MSC_VER
#define DO_FNEG16(N)    (N ^ ~((uint16_t)-1 >> 1))
#define DO_FNEG32(N)    (N ^ ~((uint32_t)-1 >> 1))
#define DO_FNEG64(N)    (N ^ ~((uint64_t)-1 >> 1))

DO_ZPZ(sve_fneg_h, uint16_t, H1_2, DO_FNEG16)
DO_ZPZ(sve_fneg_s, uint32_t, H1_4, DO_FNEG32)
DO_ZPZ_D(sve_fneg_d, uint64_t, DO_FNEG64)
#else
#define DO_FNEG(N)    (N ^ ~((__typeof(N))-1 >> 1))

DO_ZPZ(sve_fneg_h, uint16_t, H1_2, DO_FNEG)
DO_ZPZ(sve_fneg_s, uint32_t, H1_4, DO_FNEG)
DO_ZPZ_D(sve_fneg_d, uint64_t, DO_FNEG)
#endif

#define DO_NOT(N)    (~N)

DO_ZPZ(sve_not_zpz_b, uint8_t, H1, DO_NOT)
DO_ZPZ(sve_not_zpz_h, uint16_t, H1_2, DO_NOT)
DO_ZPZ(sve_not_zpz_s, uint32_t, H1_4, DO_NOT)
DO_ZPZ_D(sve_not_zpz_d, uint64_t, DO_NOT)

#define DO_SXTB(N)    ((int8_t)N)
#define DO_SXTH(N)    ((int16_t)N)
#define DO_SXTS(N)    ((int32_t)N)
#define DO_UXTB(N)    ((uint8_t)N)
#define DO_UXTH(N)    ((uint16_t)N)
#define DO_UXTS(N)    ((uint32_t)N)

DO_ZPZ(sve_sxtb_h, uint16_t, H1_2, DO_SXTB)
DO_ZPZ(sve_sxtb_s, uint32_t, H1_4, DO_SXTB)
DO_ZPZ(sve_sxth_s, uint32_t, H1_4, DO_SXTH)
DO_ZPZ_D(sve_sxtb_d, uint64_t, DO_SXTB)
DO_ZPZ_D(sve_sxth_d, uint64_t, DO_SXTH)
DO_ZPZ_D(sve_sxtw_d, uint64_t, DO_SXTS)

DO_ZPZ(sve_uxtb_h, uint16_t, H1_2, DO_UXTB)
DO_ZPZ(sve_uxtb_s, uint32_t, H1_4, DO_UXTB)
DO_ZPZ(sve_uxth_s, uint32_t, H1_4, DO_UXTH)
DO_ZPZ_D(sve_uxtb_d, uint64_t, DO_UXTB)
DO_ZPZ_D(sve_uxth_d, uint64_t, DO_UXTH)
DO_ZPZ_D(sve_uxtw_d, uint64_t, DO_UXTS)

#ifdef _MSC_VER
#define DO_ABS(N)    (N < 0 ? (0 - N) : N)
#else
#define DO_ABS(N)    (N < 0 ? -N : N)
#endif

DO_ZPZ(sve_abs_b, int8_t, H1, DO_ABS)
DO_ZPZ(sve_abs_h, int16_t, H1_2, DO_ABS)
DO_ZPZ(sve_abs_s, int32_t, H1_4, DO_ABS)
DO_ZPZ_D(sve_abs_d, int64_t, DO_ABS)

#ifdef _MSC_VER
#define DO_NEG(N)    (0 - N)
#else
#define DO_NEG(N)    (-N)
#endif

DO_ZPZ(sve_neg_b, uint8_t, H1, DO_NEG)
DO_ZPZ(sve_neg_h, uint16_t, H1_2, DO_NEG)
DO_ZPZ(sve_neg_s, uint32_t, H1_4, DO_NEG)
DO_ZPZ_D(sve_neg_d, uint64_t, DO_NEG)

DO_ZPZ(sve_revb_h, uint16_t, H1_2, bswap16)
DO_ZPZ(sve_revb_s, uint32_t, H1_4, bswap32)
DO_ZPZ_D(sve_revb_d, uint64_t, bswap64)

DO_ZPZ(sve_revh_s, uint32_t, H1_4, hswap32)
DO_ZPZ_D(sve_revh_d, uint64_t, hswap64)

DO_ZPZ_D(sve_revw_d, uint64_t, wswap64)

DO_ZPZ(sve_rbit_b, uint8_t, H1, revbit8)
DO_ZPZ(sve_rbit_h, uint16_t, H1_2, revbit16)
DO_ZPZ(sve_rbit_s, uint32_t, H1_4, revbit32)
DO_ZPZ_D(sve_rbit_d, uint64_t, revbit64)

/* Three-operand expander, unpredicated, in which the third operand is "wide".
 */
#define DO_ZZW(NAME, TYPE, TYPEW, H, OP)                       \
void HELPER(NAME)(void *vd, void *vn, void *vm, uint32_t desc) \
{                                                              \
    intptr_t i, opr_sz = simd_oprsz(desc);                     \
    for (i = 0; i < opr_sz; ) {                                \
        TYPEW mm = *(TYPEW *)((char *)vm + i);                         \
        do {                                                   \
            TYPE nn = *(TYPE *)((char *)vn + H(i));                    \
            *(TYPE *)((char *)vd + H(i)) = OP(nn, mm);                 \
            i += sizeof(TYPE);                                 \
        } while (i & 7);                                       \
    }                                                          \
}

DO_ZZW(sve_asr_zzw_b, int8_t, uint64_t, H1, DO_ASR)
DO_ZZW(sve_lsr_zzw_b, uint8_t, uint64_t, H1, DO_LSR)
DO_ZZW(sve_lsl_zzw_b, uint8_t, uint64_t, H1, DO_LSL)

DO_ZZW(sve_asr_zzw_h, int16_t, uint64_t, H1_2, DO_ASR)
DO_ZZW(sve_lsr_zzw_h, uint16_t, uint64_t, H1_2, DO_LSR)
DO_ZZW(sve_lsl_zzw_h, uint16_t, uint64_t, H1_2, DO_LSL)

DO_ZZW(sve_asr_zzw_s, int32_t, uint64_t, H1_4, DO_ASR)
DO_ZZW(sve_lsr_zzw_s, uint32_t, uint64_t, H1_4, DO_LSR)
DO_ZZW(sve_lsl_zzw_s, uint32_t, uint64_t, H1_4, DO_LSL)

#undef DO_ZZW

#undef DO_CLS_B
#undef DO_CLS_H
#undef DO_CLZ_B
#undef DO_CLZ_H
#undef DO_CNOT
#undef DO_FABS
#undef DO_FNEG
#undef DO_ABS
#undef DO_NEG
#undef DO_ZPZ
#undef DO_ZPZ_D

/* Two-operand reduction expander, controlled by a predicate.
 * The difference between TYPERED and TYPERET has to do with
 * sign-extension.  E.g. for SMAX, TYPERED must be signed,
 * but TYPERET must be unsigned so that e.g. a 32-bit value
 * is not sign-extended to the ABI uint64_t return type.
 */
/* ??? If we were to vectorize this by hand the reduction ordering
 * would change.  For integer operands, this is perfectly fine.
 */
#define DO_VPZ(NAME, TYPEELT, TYPERED, TYPERET, H, INIT, OP) \
uint64_t HELPER(NAME)(void *vn, void *vg, uint32_t desc)   \
{                                                          \
    intptr_t i, opr_sz = simd_oprsz(desc);                 \
    TYPERED ret = INIT;                                    \
    for (i = 0; i < opr_sz; ) {                            \
        uint16_t pg = *(uint16_t *)((char *)vg + H1_2(i >> 3));    \
        do {                                               \
            if (pg & 1) {                                  \
                TYPEELT nn = *(TYPEELT *)((char *)vn + H(i));      \
                ret = OP(ret, nn);                         \
            }                                              \
            i += sizeof(TYPEELT), pg >>= sizeof(TYPEELT);  \
        } while (i & 15);                                  \
    }                                                      \
    return (TYPERET)ret;                                   \
}

#define DO_VPZ_D(NAME, TYPEE, TYPER, INIT, OP)             \
uint64_t HELPER(NAME)(void *vn, void *vg, uint32_t desc)   \
{                                                          \
    intptr_t i, opr_sz = simd_oprsz(desc) / 8;             \
    TYPEE *n = vn;                                         \
    uint8_t *pg = vg;                                      \
    TYPER ret = INIT;                                      \
    for (i = 0; i < opr_sz; i += 1) {                      \
        if (pg[H1(i)] & 1) {                               \
            TYPEE nn = n[i];                               \
            ret = OP(ret, nn);                             \
        }                                                  \
    }                                                      \
    return ret;                                            \
}

DO_VPZ(sve_orv_b, uint8_t, uint8_t, uint8_t, H1, 0, DO_ORR)
DO_VPZ(sve_orv_h, uint16_t, uint16_t, uint16_t, H1_2, 0, DO_ORR)
DO_VPZ(sve_orv_s, uint32_t, uint32_t, uint32_t, H1_4, 0, DO_ORR)
DO_VPZ_D(sve_orv_d, uint64_t, uint64_t, 0, DO_ORR)

DO_VPZ(sve_eorv_b, uint8_t, uint8_t, uint8_t, H1, 0, DO_EOR)
DO_VPZ(sve_eorv_h, uint16_t, uint16_t, uint16_t, H1_2, 0, DO_EOR)
DO_VPZ(sve_eorv_s, uint32_t, uint32_t, uint32_t, H1_4, 0, DO_EOR)
DO_VPZ_D(sve_eorv_d, uint64_t, uint64_t, 0, DO_EOR)

DO_VPZ(sve_andv_b, uint8_t, uint8_t, uint8_t, H1, -1, DO_AND)
DO_VPZ(sve_andv_h, uint16_t, uint16_t, uint16_t, H1_2, -1, DO_AND)
DO_VPZ(sve_andv_s, uint32_t, uint32_t, uint32_t, H1_4, -1, DO_AND)
DO_VPZ_D(sve_andv_d, uint64_t, uint64_t, -1, DO_AND)

DO_VPZ(sve_saddv_b, int8_t, uint64_t, uint64_t, H1, 0, DO_ADD)
DO_VPZ(sve_saddv_h, int16_t, uint64_t, uint64_t, H1_2, 0, DO_ADD)
DO_VPZ(sve_saddv_s, int32_t, uint64_t, uint64_t, H1_4, 0, DO_ADD)

DO_VPZ(sve_uaddv_b, uint8_t, uint64_t, uint64_t, H1, 0, DO_ADD)
DO_VPZ(sve_uaddv_h, uint16_t, uint64_t, uint64_t, H1_2, 0, DO_ADD)
DO_VPZ(sve_uaddv_s, uint32_t, uint64_t, uint64_t, H1_4, 0, DO_ADD)
DO_VPZ_D(sve_uaddv_d, uint64_t, uint64_t, 0, DO_ADD)

DO_VPZ(sve_smaxv_b, int8_t, int8_t, uint8_t, H1, INT8_MIN, DO_MAX)
DO_VPZ(sve_smaxv_h, int16_t, int16_t, uint16_t, H1_2, INT16_MIN, DO_MAX)
DO_VPZ(sve_smaxv_s, int32_t, int32_t, uint32_t, H1_4, INT32_MIN, DO_MAX)
DO_VPZ_D(sve_smaxv_d, int64_t, int64_t, INT64_MIN, DO_MAX)

DO_VPZ(sve_umaxv_b, uint8_t, uint8_t, uint8_t, H1, 0, DO_MAX)
DO_VPZ(sve_umaxv_h, uint16_t, uint16_t, uint16_t, H1_2, 0, DO_MAX)
DO_VPZ(sve_umaxv_s, uint32_t, uint32_t, uint32_t, H1_4, 0, DO_MAX)
DO_VPZ_D(sve_umaxv_d, uint64_t, uint64_t, 0, DO_MAX)

DO_VPZ(sve_sminv_b, int8_t, int8_t, uint8_t, H1, INT8_MAX, DO_MIN)
DO_VPZ(sve_sminv_h, int16_t, int16_t, uint16_t, H1_2, INT16_MAX, DO_MIN)
DO_VPZ(sve_sminv_s, int32_t, int32_t, uint32_t, H1_4, INT32_MAX, DO_MIN)
DO_VPZ_D(sve_sminv_d, int64_t, int64_t, INT64_MAX, DO_MIN)

DO_VPZ(sve_uminv_b, uint8_t, uint8_t, uint8_t, H1, -1, DO_MIN)
DO_VPZ(sve_uminv_h, uint16_t, uint16_t, uint16_t, H1_2, -1, DO_MIN)
DO_VPZ(sve_uminv_s, uint32_t, uint32_t, uint32_t, H1_4, -1, DO_MIN)
DO_VPZ_D(sve_uminv_d, uint64_t, uint64_t, -1, DO_MIN)

#undef DO_VPZ
#undef DO_VPZ_D

/* Two vector operand, one scalar operand, unpredicated.  */
#define DO_ZZI(NAME, TYPE, OP)                                       \
void HELPER(NAME)(void *vd, void *vn, uint64_t s64, uint32_t desc)   \
{                                                                    \
    intptr_t i, opr_sz = simd_oprsz(desc) / sizeof(TYPE);            \
    TYPE s = s64, *d = vd, *n = vn;                                  \
    for (i = 0; i < opr_sz; ++i) {                                   \
        d[i] = OP(n[i], s);                                          \
    }                                                                \
}

#define DO_SUBR(X, Y)   (Y - X)

DO_ZZI(sve_subri_b, uint8_t, DO_SUBR)
DO_ZZI(sve_subri_h, uint16_t, DO_SUBR)
DO_ZZI(sve_subri_s, uint32_t, DO_SUBR)
DO_ZZI(sve_subri_d, uint64_t, DO_SUBR)

DO_ZZI(sve_smaxi_b, int8_t, DO_MAX)
DO_ZZI(sve_smaxi_h, int16_t, DO_MAX)
DO_ZZI(sve_smaxi_s, int32_t, DO_MAX)
DO_ZZI(sve_smaxi_d, int64_t, DO_MAX)

DO_ZZI(sve_smini_b, int8_t, DO_MIN)
DO_ZZI(sve_smini_h, int16_t, DO_MIN)
DO_ZZI(sve_smini_s, int32_t, DO_MIN)
DO_ZZI(sve_smini_d, int64_t, DO_MIN)

DO_ZZI(sve_umaxi_b, uint8_t, DO_MAX)
DO_ZZI(sve_umaxi_h, uint16_t, DO_MAX)
DO_ZZI(sve_umaxi_s, uint32_t, DO_MAX)
DO_ZZI(sve_umaxi_d, uint64_t, DO_MAX)

DO_ZZI(sve_umini_b, uint8_t, DO_MIN)
DO_ZZI(sve_umini_h, uint16_t, DO_MIN)
DO_ZZI(sve_umini_s, uint32_t, DO_MIN)
DO_ZZI(sve_umini_d, uint64_t, DO_MIN)

#undef DO_ZZI

#undef DO_AND
#undef DO_ORR
#undef DO_EOR
#undef DO_BIC
#undef DO_ADD
#undef DO_SUB
#undef DO_MAX
#undef DO_MIN
#undef DO_ABD
#undef DO_MUL
#undef DO_DIV
#undef DO_ASR
#undef DO_LSR
#undef DO_LSL
#undef DO_SUBR

/* Similar to the ARM LastActiveElement pseudocode function, except the
   result is multiplied by the element size.  This includes the not found
   indication; e.g. not found for esz=3 is -8.  */
static intptr_t last_active_element(uint64_t *g, intptr_t words, intptr_t esz)
{
    uint64_t mask = pred_esz_masks[esz];
    intptr_t i = words;

    do {
        uint64_t this_g = g[--i] & mask;
        if (this_g) {
            return i * 64 + (63 - clz64(this_g));
        }
    } while (i > 0);
    return (intptr_t)-1 << esz;
}

uint32_t HELPER(sve_pfirst)(void *vd, void *vg, uint32_t words)
{
    uint32_t flags = PREDTEST_INIT;
    uint64_t *d = vd, *g = vg;
    intptr_t i = 0;

    do {
        uint64_t this_d = d[i];
        uint64_t this_g = g[i];

        if (this_g) {
            if (!(flags & 4)) {
                /* Set in D the first bit of G.  */
#ifdef _MSC_VER
                this_d |= this_g & (0 - this_g);
#else
                this_d |= this_g & -this_g;
#endif
                d[i] = this_d;
            }
            flags = iter_predtest_fwd(this_d, this_g, flags);
        }
    } while (++i < words);

    return flags;
}

uint32_t HELPER(sve_pnext)(void *vd, void *vg, uint32_t pred_desc)
{
    intptr_t words = extract32(pred_desc, 0, SIMD_OPRSZ_BITS);
    intptr_t esz = extract32(pred_desc, SIMD_DATA_SHIFT, 2);
    uint32_t flags = PREDTEST_INIT;
    uint64_t *d = vd, *g = vg, esz_mask;
    intptr_t i, next;

    next = last_active_element(vd, words, esz) + (1ULL << esz);
    esz_mask = pred_esz_masks[esz];

    /* Similar to the pseudocode for pnext, but scaled by ESZ
       so that we find the correct bit.  */
    if (next < words * 64) {
        uint64_t mask = -1;

        if (next & 63) {
            mask = ~((1ull << (next & 63)) - 1);
            next &= -64;
        }
        do {
            uint64_t this_g = g[next / 64] & esz_mask & mask;
            if (this_g != 0) {
                next = (next & -64) + ctz64(this_g);
                break;
            }
            next += 64;
            mask = -1;
        } while (next < words * 64);
    }

    i = 0;
    do {
        uint64_t this_d = 0;
        if (i == next / 64) {
            this_d = 1ull << (next & 63);
        }
        d[i] = this_d;
        flags = iter_predtest_fwd(this_d, g[i] & esz_mask, flags);
    } while (++i < words);

    return flags;
}

/* Store zero into every active element of Zd.  We will use this for two
 * and three-operand predicated instructions for which logic dictates a
 * zero result.  In particular, logical shift by element size, which is
 * otherwise undefined on the host.
 *
 * For element sizes smaller than uint64_t, we use tables to expand
 * the N bits of the controlling predicate to a byte mask, and clear
 * those bytes.
 */
void HELPER(sve_clr_b)(void *vd, void *vg, uint32_t desc)
{
    intptr_t i, opr_sz = simd_oprsz(desc) / 8;
    uint64_t *d = vd;
    uint8_t *pg = vg;
    for (i = 0; i < opr_sz; i += 1) {
        d[i] &= ~expand_pred_b(pg[H1(i)]);
    }
}

void HELPER(sve_clr_h)(void *vd, void *vg, uint32_t desc)
{
    intptr_t i, opr_sz = simd_oprsz(desc) / 8;
    uint64_t *d = vd;
    uint8_t *pg = vg;
    for (i = 0; i < opr_sz; i += 1) {
        d[i] &= ~expand_pred_h(pg[H1(i)]);
    }
}

void HELPER(sve_clr_s)(void *vd, void *vg, uint32_t desc)
{
    intptr_t i, opr_sz = simd_oprsz(desc) / 8;
    uint64_t *d = vd;
    uint8_t *pg = vg;
    for (i = 0; i < opr_sz; i += 1) {
        d[i] &= ~expand_pred_s(pg[H1(i)]);
    }
}

void HELPER(sve_clr_d)(void *vd, void *vg, uint32_t desc)
{
    intptr_t i, opr_sz = simd_oprsz(desc) / 8;
    uint64_t *d = vd;
    uint8_t *pg = vg;
    for (i = 0; i < opr_sz; i += 1) {
        if (pg[H1(i)] & 1) {
            d[i] = 0;
        }
    }
}

/* Copy Zn into Zd, and store zero into inactive elements.  */
void HELPER(sve_movz_b)(void *vd, void *vn, void *vg, uint32_t desc)
{
    intptr_t i, opr_sz = simd_oprsz(desc) / 8;
    uint64_t *d = vd, *n = vn;
    uint8_t *pg = vg;
    for (i = 0; i < opr_sz; i += 1) {
        d[i] = n[i] & expand_pred_b(pg[H1(i)]);
    }
}

void HELPER(sve_movz_h)(void *vd, void *vn, void *vg, uint32_t desc)
{
    intptr_t i, opr_sz = simd_oprsz(desc) / 8;
    uint64_t *d = vd, *n = vn;
    uint8_t *pg = vg;
    for (i = 0; i < opr_sz; i += 1) {
        d[i] = n[i] & expand_pred_h(pg[H1(i)]);
    }
}

void HELPER(sve_movz_s)(void *vd, void *vn, void *vg, uint32_t desc)
{
    intptr_t i, opr_sz = simd_oprsz(desc) / 8;
    uint64_t *d = vd, *n = vn;
    uint8_t *pg = vg;
    for (i = 0; i < opr_sz; i += 1) {
        d[i] = n[i] & expand_pred_s(pg[H1(i)]);
    }
}

void HELPER(sve_movz_d)(void *vd, void *vn, void *vg, uint32_t desc)
{
    intptr_t i, opr_sz = simd_oprsz(desc) / 8;
    uint64_t *d = vd, *n = vn;
    uint8_t *pg = vg;
    for (i = 0; i < opr_sz; i += 1) {
#ifdef _MSC_VER
        d[i] = n[i] & ((uint64_t)0 - (uint64_t)(pg[H1(i)] & 1));
#else
        d[i] = n[i] & -(uint64_t)(pg[H1(i)] & 1);
#endif
    }
}

/* Three-operand expander, immediate operand, controlled by a predicate.
 */
#define DO_ZPZI(NAME, TYPE, H, OP)                              \
void HELPER(NAME)(void *vd, void *vn, void *vg, uint32_t desc)  \
{                                                               \
    intptr_t i, opr_sz = simd_oprsz(desc);                      \
    TYPE imm = simd_data(desc);                                 \
    for (i = 0; i < opr_sz; ) {                                 \
        uint16_t pg = *(uint16_t *)((char *)vg + H1_2(i >> 3));         \
        do {                                                    \
            if (pg & 1) {                                       \
                TYPE nn = *(TYPE *)((char *)vn + H(i));                 \
                *(TYPE *)((char *)vd + H(i)) = OP(nn, imm);             \
            }                                                   \
            i += sizeof(TYPE), pg >>= sizeof(TYPE);             \
        } while (i & 15);                                       \
    }                                                           \
}

/* Similarly, specialized for 64-bit operands.  */
#define DO_ZPZI_D(NAME, TYPE, OP)                               \
void HELPER(NAME)(void *vd, void *vn, void *vg, uint32_t desc)  \
{                                                               \
    intptr_t i, opr_sz = simd_oprsz(desc) / 8;                  \
    TYPE *d = vd, *n = vn;                                      \
    TYPE imm = simd_data(desc);                                 \
    uint8_t *pg = vg;                                           \
    for (i = 0; i < opr_sz; i += 1) {                           \
        if (pg[H1(i)] & 1) {                                    \
            TYPE nn = n[i];                                     \
            d[i] = OP(nn, imm);                                 \
        }                                                       \
    }                                                           \
}

#define DO_SHR(N, M)  (N >> M)
#define DO_SHL(N, M)  (N << M)

/* Arithmetic shift right for division.  This rounds negative numbers
   toward zero as per signed division.  Therefore before shifting,
   when N is negative, add 2**M-1.  */
#ifdef _MSC_VER
 #define DO_ASRD(N, M) ((N + (N < 0 ? (1 << M) - 1 : 0)) >> M)
#else
 #define DO_ASRD(N, M) ((N + (N < 0 ? ((__typeof(N))1 << M) - 1 : 0)) >> M)
#endif

DO_ZPZI(sve_asr_zpzi_b, int8_t, H1, DO_SHR)
DO_ZPZI(sve_asr_zpzi_h, int16_t, H1_2, DO_SHR)
DO_ZPZI(sve_asr_zpzi_s, int32_t, H1_4, DO_SHR)
DO_ZPZI_D(sve_asr_zpzi_d, int64_t, DO_SHR)

DO_ZPZI(sve_lsr_zpzi_b, uint8_t, H1, DO_SHR)
DO_ZPZI(sve_lsr_zpzi_h, uint16_t, H1_2, DO_SHR)
DO_ZPZI(sve_lsr_zpzi_s, uint32_t, H1_4, DO_SHR)
DO_ZPZI_D(sve_lsr_zpzi_d, uint64_t, DO_SHR)

DO_ZPZI(sve_lsl_zpzi_b, uint8_t, H1, DO_SHL)
DO_ZPZI(sve_lsl_zpzi_h, uint16_t, H1_2, DO_SHL)
DO_ZPZI(sve_lsl_zpzi_s, uint32_t, H1_4, DO_SHL)
DO_ZPZI_D(sve_lsl_zpzi_d, uint64_t, DO_SHL)

DO_ZPZI(sve_asrd_b, int8_t, H1, DO_ASRD)
DO_ZPZI(sve_asrd_h, int16_t, H1_2, DO_ASRD)
DO_ZPZI(sve_asrd_s, int32_t, H1_4, DO_ASRD)
DO_ZPZI_D(sve_asrd_d, int64_t, DO_ASRD)

#undef DO_SHR
#undef DO_SHL
#undef DO_ASRD
#undef DO_ZPZI
#undef DO_ZPZI_D

/* Fully general four-operand expander, controlled by a predicate.
 */
#define DO_ZPZZZ(NAME, TYPE, H, OP)                           \
void HELPER(NAME)(void *vd, void *va, void *vn, void *vm,     \
                  void *vg, uint32_t desc)                    \
{                                                             \
    intptr_t i, opr_sz = simd_oprsz(desc);                    \
    for (i = 0; i < opr_sz; ) {                               \
        uint16_t pg = *(uint16_t *)((char *)vg + H1_2(i >> 3));       \
        do {                                                  \
            if (pg & 1) {                                     \
                TYPE nn = *(TYPE *)((char *)vn + H(i));               \
                TYPE mm = *(TYPE *)((char *)vm + H(i));               \
                TYPE aa = *(TYPE *)((char *)va + H(i));               \
                *(TYPE *)((char *)vd + H(i)) = OP(aa, nn, mm);        \
            }                                                 \
            i += sizeof(TYPE), pg >>= sizeof(TYPE);           \
        } while (i & 15);                                     \
    }                                                         \
}

/* Similarly, specialized for 64-bit operands.  */
#define DO_ZPZZZ_D(NAME, TYPE, OP)                            \
void HELPER(NAME)(void *vd, void *va, void *vn, void *vm,     \
                  void *vg, uint32_t desc)                    \
{                                                             \
    intptr_t i, opr_sz = simd_oprsz(desc) / 8;                \
    TYPE *d = vd, *a = va, *n = vn, *m = vm;                  \
    uint8_t *pg = vg;                                         \
    for (i = 0; i < opr_sz; i += 1) {                         \
        if (pg[H1(i)] & 1) {                                  \
            TYPE aa = a[i], nn = n[i], mm = m[i];             \
            d[i] = OP(aa, nn, mm);                            \
        }                                                     \
    }                                                         \
}

#define DO_MLA(A, N, M)  (A + N * M)
#define DO_MLS(A, N, M)  (A - N * M)

DO_ZPZZZ(sve_mla_b, uint8_t, H1, DO_MLA)
DO_ZPZZZ(sve_mls_b, uint8_t, H1, DO_MLS)

DO_ZPZZZ(sve_mla_h, uint16_t, H1_2, DO_MLA)
DO_ZPZZZ(sve_mls_h, uint16_t, H1_2, DO_MLS)

DO_ZPZZZ(sve_mla_s, uint32_t, H1_4, DO_MLA)
DO_ZPZZZ(sve_mls_s, uint32_t, H1_4, DO_MLS)

DO_ZPZZZ_D(sve_mla_d, uint64_t, DO_MLA)
DO_ZPZZZ_D(sve_mls_d, uint64_t, DO_MLS)

#undef DO_MLA
#undef DO_MLS
#undef DO_ZPZZZ
#undef DO_ZPZZZ_D

void HELPER(sve_index_b)(void *vd, uint32_t start,
                         uint32_t incr, uint32_t desc)
{
    intptr_t i, opr_sz = simd_oprsz(desc);
    uint8_t *d = vd;
    for (i = 0; i < opr_sz; i += 1) {
        d[H1(i)] = start + i * incr;
    }
}

void HELPER(sve_index_h)(void *vd, uint32_t start,
                         uint32_t incr, uint32_t desc)
{
    intptr_t i, opr_sz = simd_oprsz(desc) / 2;
    uint16_t *d = vd;
    for (i = 0; i < opr_sz; i += 1) {
        d[H2(i)] = start + i * incr;
    }
}

void HELPER(sve_index_s)(void *vd, uint32_t start,
                         uint32_t incr, uint32_t desc)
{
    intptr_t i, opr_sz = simd_oprsz(desc) / 4;
    uint32_t *d = vd;
    for (i = 0; i < opr_sz; i += 1) {
        d[H4(i)] = start + i * incr;
    }
}

void HELPER(sve_index_d)(void *vd, uint64_t start,
                         uint64_t incr, uint32_t desc)
{
    intptr_t i, opr_sz = simd_oprsz(desc) / 8;
    uint64_t *d = vd;
    for (i = 0; i < opr_sz; i += 1) {
        d[i] = start + i * incr;
    }
}

void HELPER(sve_adr_p32)(void *vd, void *vn, void *vm, uint32_t desc)
{
    intptr_t i, opr_sz = simd_oprsz(desc) / 4;
    uint32_t sh = simd_data(desc);
    uint32_t *d = vd, *n = vn, *m = vm;
    for (i = 0; i < opr_sz; i += 1) {
        d[i] = n[i] + (m[i] << sh);
    }
}

void HELPER(sve_adr_p64)(void *vd, void *vn, void *vm, uint32_t desc)
{
    intptr_t i, opr_sz = simd_oprsz(desc) / 8;
    uint64_t sh = simd_data(desc);
    uint64_t *d = vd, *n = vn, *m = vm;
    for (i = 0; i < opr_sz; i += 1) {
        d[i] = n[i] + (m[i] << sh);
    }
}

void HELPER(sve_adr_s32)(void *vd, void *vn, void *vm, uint32_t desc)
{
    intptr_t i, opr_sz = simd_oprsz(desc) / 8;
    uint64_t sh = simd_data(desc);
    uint64_t *d = vd, *n = vn, *m = vm;
    for (i = 0; i < opr_sz; i += 1) {
        d[i] = n[i] + ((uint64_t)(int32_t)m[i] << sh);
    }
}

void HELPER(sve_adr_u32)(void *vd, void *vn, void *vm, uint32_t desc)
{
    intptr_t i, opr_sz = simd_oprsz(desc) / 8;
    uint64_t sh = simd_data(desc);
    uint64_t *d = vd, *n = vn, *m = vm;
    for (i = 0; i < opr_sz; i += 1) {
        d[i] = n[i] + ((uint64_t)(uint32_t)m[i] << sh);
    }
}

void HELPER(sve_fexpa_h)(void *vd, void *vn, uint32_t desc)
{
    /* These constants are cut-and-paste directly from the ARM pseudocode.  */
    static const uint16_t coeff[] = {
        0x0000, 0x0016, 0x002d, 0x0045, 0x005d, 0x0075, 0x008e, 0x00a8,
        0x00c2, 0x00dc, 0x00f8, 0x0114, 0x0130, 0x014d, 0x016b, 0x0189,
        0x01a8, 0x01c8, 0x01e8, 0x0209, 0x022b, 0x024e, 0x0271, 0x0295,
        0x02ba, 0x02e0, 0x0306, 0x032e, 0x0356, 0x037f, 0x03a9, 0x03d4,
    };
    intptr_t i, opr_sz = simd_oprsz(desc) / 2;
    uint16_t *d = vd, *n = vn;

    for (i = 0; i < opr_sz; i++) {
        uint16_t nn = n[i];
        intptr_t idx = extract32(nn, 0, 5);
        uint16_t exp = extract32(nn, 5, 5);
        d[i] = coeff[idx] | (exp << 10);
    }
}

void HELPER(sve_fexpa_s)(void *vd, void *vn, uint32_t desc)
{
    /* These constants are cut-and-paste directly from the ARM pseudocode.  */
    static const uint32_t coeff[] = {
        0x000000, 0x0164d2, 0x02cd87, 0x043a29,
        0x05aac3, 0x071f62, 0x08980f, 0x0a14d5,
        0x0b95c2, 0x0d1adf, 0x0ea43a, 0x1031dc,
        0x11c3d3, 0x135a2b, 0x14f4f0, 0x16942d,
        0x1837f0, 0x19e046, 0x1b8d3a, 0x1d3eda,
        0x1ef532, 0x20b051, 0x227043, 0x243516,
        0x25fed7, 0x27cd94, 0x29a15b, 0x2b7a3a,
        0x2d583f, 0x2f3b79, 0x3123f6, 0x3311c4,
        0x3504f3, 0x36fd92, 0x38fbaf, 0x3aff5b,
        0x3d08a4, 0x3f179a, 0x412c4d, 0x4346cd,
        0x45672a, 0x478d75, 0x49b9be, 0x4bec15,
        0x4e248c, 0x506334, 0x52a81e, 0x54f35b,
        0x5744fd, 0x599d16, 0x5bfbb8, 0x5e60f5,
        0x60ccdf, 0x633f89, 0x65b907, 0x68396a,
        0x6ac0c7, 0x6d4f30, 0x6fe4ba, 0x728177,
        0x75257d, 0x77d0df, 0x7a83b3, 0x7d3e0c,
    };
    intptr_t i, opr_sz = simd_oprsz(desc) / 4;
    uint32_t *d = vd, *n = vn;

    for (i = 0; i < opr_sz; i++) {
        uint32_t nn = n[i];
        intptr_t idx = extract32(nn, 0, 6);
        uint32_t exp = extract32(nn, 6, 8);
        d[i] = coeff[idx] | (exp << 23);
    }
}

void HELPER(sve_fexpa_d)(void *vd, void *vn, uint32_t desc)
{
    /* These constants are cut-and-paste directly from the ARM pseudocode.  */
    static const uint64_t coeff[] = {
        0x0000000000000ull, 0x02C9A3E778061ull, 0x059B0D3158574ull,
        0x0874518759BC8ull, 0x0B5586CF9890Full, 0x0E3EC32D3D1A2ull,
        0x11301D0125B51ull, 0x1429AAEA92DE0ull, 0x172B83C7D517Bull,
        0x1A35BEB6FCB75ull, 0x1D4873168B9AAull, 0x2063B88628CD6ull,
        0x2387A6E756238ull, 0x26B4565E27CDDull, 0x29E9DF51FDEE1ull,
        0x2D285A6E4030Bull, 0x306FE0A31B715ull, 0x33C08B26416FFull,
        0x371A7373AA9CBull, 0x3A7DB34E59FF7ull, 0x3DEA64C123422ull,
        0x4160A21F72E2Aull, 0x44E086061892Dull, 0x486A2B5C13CD0ull,
        0x4BFDAD5362A27ull, 0x4F9B2769D2CA7ull, 0x5342B569D4F82ull,
        0x56F4736B527DAull, 0x5AB07DD485429ull, 0x5E76F15AD2148ull,
        0x6247EB03A5585ull, 0x6623882552225ull, 0x6A09E667F3BCDull,
        0x6DFB23C651A2Full, 0x71F75E8EC5F74ull, 0x75FEB564267C9ull,
        0x7A11473EB0187ull, 0x7E2F336CF4E62ull, 0x82589994CCE13ull,
        0x868D99B4492EDull, 0x8ACE5422AA0DBull, 0x8F1AE99157736ull,
        0x93737B0CDC5E5ull, 0x97D829FDE4E50ull, 0x9C49182A3F090ull,
        0xA0C667B5DE565ull, 0xA5503B23E255Dull, 0xA9E6B5579FDBFull,
        0xAE89F995AD3ADull, 0xB33A2B84F15FBull, 0xB7F76F2FB5E47ull,
        0xBCC1E904BC1D2ull, 0xC199BDD85529Cull, 0xC67F12E57D14Bull,
        0xCB720DCEF9069ull, 0xD072D4A07897Cull, 0xD5818DCFBA487ull,
        0xDA9E603DB3285ull, 0xDFC97337B9B5Full, 0xE502EE78B3FF6ull,
        0xEA4AFA2A490DAull, 0xEFA1BEE615A27ull, 0xF50765B6E4540ull,
        0xFA7C1819E90D8ull,
    };
    intptr_t i, opr_sz = simd_oprsz(desc) / 8;
    uint64_t *d = vd, *n = vn;

    for (i = 0; i < opr_sz; i++) {
        uint64_t nn = n[i];
        intptr_t idx = extract32(nn, 0, 6);
        uint64_t exp = extract32(nn, 6, 11);
        d[i] = coeff[idx] | (exp << 52);
    }
}

void HELPER(sve_ftssel_h)(void *vd, void *vn, void *vm, uint32_t desc)
{
    intptr_t i, opr_sz = simd_oprsz(desc) / 2;
    uint16_t *d = vd, *n = vn, *m = vm;
    for (i = 0; i < opr_sz; i += 1) {
        uint16_t nn = n[i];
        uint16_t mm = m[i];
        if (mm & 1) {
            nn = float16_one;
        }
        d[i] = nn ^ (mm & 2) << 14;
    }
}

void HELPER(sve_ftssel_s)(void *vd, void *vn, void *vm, uint32_t desc)
{
    intptr_t i, opr_sz = simd_oprsz(desc) / 4;
    uint32_t *d = vd, *n = vn, *m = vm;
    for (i = 0; i < opr_sz; i += 1) {
        uint32_t nn = n[i];
        uint32_t mm = m[i];
        if (mm & 1) {
            nn = float32_one;
        }
        d[i] = nn ^ (mm & 2) << 30;
    }
}

void HELPER(sve_ftssel_d)(void *vd, void *vn, void *vm, uint32_t desc)
{
    intptr_t i, opr_sz = simd_oprsz(desc) / 8;
    uint64_t *d = vd, *n = vn, *m = vm;
    for (i = 0; i < opr_sz; i += 1) {
        uint64_t nn = n[i];
        uint64_t mm = m[i];
        if (mm & 1) {
            nn = float64_one;
        }
        d[i] = nn ^ (mm & 2) << 62;
    }
}

/*
 * Signed saturating addition with scalar operand.
 */

void HELPER(sve_sqaddi_b)(void *d, void *a, int32_t b, uint32_t desc)
{
    intptr_t i, oprsz = simd_oprsz(desc);

    for (i = 0; i < oprsz; i += sizeof(int8_t)) {
        int r = *(int8_t *)((char *)a + i) + b;
        if (r > INT8_MAX) {
            r = INT8_MAX;
        } else if (r < INT8_MIN) {
            r = INT8_MIN;
        }
        *(int8_t *)((char *)d + i) = r;
    }
}

void HELPER(sve_sqaddi_h)(void *d, void *a, int32_t b, uint32_t desc)
{
    intptr_t i, oprsz = simd_oprsz(desc);

    for (i = 0; i < oprsz; i += sizeof(int16_t)) {
        int r = *(int16_t *)((char *)a + i) + b;
        if (r > INT16_MAX) {
            r = INT16_MAX;
        } else if (r < INT16_MIN) {
            r = INT16_MIN;
        }
        *(int16_t *)((char *)d + i) = r;
    }
}

void HELPER(sve_sqaddi_s)(void *d, void *a, int64_t b, uint32_t desc)
{
    intptr_t i, oprsz = simd_oprsz(desc);

    for (i = 0; i < oprsz; i += sizeof(int32_t)) {
        int64_t r = *(int32_t *)((char *)a + i) + b;
        if (r > INT32_MAX) {
            r = INT32_MAX;
        } else if (r < INT32_MIN) {
            r = INT32_MIN;
        }
        *(int32_t *)((char *)d + i) = r;
    }
}

void HELPER(sve_sqaddi_d)(void *d, void *a, int64_t b, uint32_t desc)
{
    intptr_t i, oprsz = simd_oprsz(desc);

    for (i = 0; i < oprsz; i += sizeof(int64_t)) {
        int64_t ai = *(int64_t *)((char *)a + i);
        int64_t r = ai + b;
        if (((r ^ ai) & ~(ai ^ b)) < 0) {
            /* Signed overflow.  */
            r = (r < 0 ? INT64_MAX : INT64_MIN);
        }
        *(int64_t *)((char *)d + i) = r;
    }
}

/*
 * Unsigned saturating addition with scalar operand.
 */

void HELPER(sve_uqaddi_b)(void *d, void *a, int32_t b, uint32_t desc)
{
    intptr_t i, oprsz = simd_oprsz(desc);

    for (i = 0; i < oprsz; i += sizeof(uint8_t)) {
        int r = *(uint8_t *)((char *)a + i) + b;
        if (r > UINT8_MAX) {
            r = UINT8_MAX;
        } else if (r < 0) {
            r = 0;
        }
        *(uint8_t *)((char *)d + i) = r;
    }
}

void HELPER(sve_uqaddi_h)(void *d, void *a, int32_t b, uint32_t desc)
{
    intptr_t i, oprsz = simd_oprsz(desc);

    for (i = 0; i < oprsz; i += sizeof(uint16_t)) {
        int r = *(uint16_t *)((char *)a + i) + b;
        if (r > UINT16_MAX) {
            r = UINT16_MAX;
        } else if (r < 0) {
            r = 0;
        }
        *(uint16_t *)((char *)d + i) = r;
    }
}

void HELPER(sve_uqaddi_s)(void *d, void *a, int64_t b, uint32_t desc)
{
    intptr_t i, oprsz = simd_oprsz(desc);

    for (i = 0; i < oprsz; i += sizeof(uint32_t)) {
        int64_t r = *(uint32_t *)((char *)a + i) + b;
        if (r > UINT32_MAX) {
            r = UINT32_MAX;
        } else if (r < 0) {
            r = 0;
        }
        *(uint32_t *)((char *)d + i) = r;
    }
}

void HELPER(sve_uqaddi_d)(void *d, void *a, uint64_t b, uint32_t desc)
{
    intptr_t i, oprsz = simd_oprsz(desc);

    for (i = 0; i < oprsz; i += sizeof(uint64_t)) {
        uint64_t r = *(uint64_t *)((char *)a + i) + b;
        if (r < b) {
            r = UINT64_MAX;
        }
        *(uint64_t *)((char *)d + i) = r;
    }
}

void HELPER(sve_uqsubi_d)(void *d, void *a, uint64_t b, uint32_t desc)
{
    intptr_t i, oprsz = simd_oprsz(desc);

    for (i = 0; i < oprsz; i += sizeof(uint64_t)) {
        uint64_t ai = *(uint64_t *)((char *)a + i);
        *(uint64_t *)((char *)d + i) = (ai < b ? 0 : ai - b);
    }
}

/* Two operand predicated copy immediate with merge.  All valid immediates
 * can fit within 17 signed bits in the simd_data field.
 */
void HELPER(sve_cpy_m_b)(void *vd, void *vn, void *vg,
                         uint64_t mm, uint32_t desc)
{
    intptr_t i, opr_sz = simd_oprsz(desc) / 8;
    uint64_t *d = vd, *n = vn;
    uint8_t *pg = vg;

    mm = dup_const(MO_8, mm);
    for (i = 0; i < opr_sz; i += 1) {
        uint64_t nn = n[i];
        uint64_t pp = expand_pred_b(pg[H1(i)]);
        d[i] = (mm & pp) | (nn & ~pp);
    }
}

void HELPER(sve_cpy_m_h)(void *vd, void *vn, void *vg,
                         uint64_t mm, uint32_t desc)
{
    intptr_t i, opr_sz = simd_oprsz(desc) / 8;
    uint64_t *d = vd, *n = vn;
    uint8_t *pg = vg;

    mm = dup_const(MO_16, mm);
    for (i = 0; i < opr_sz; i += 1) {
        uint64_t nn = n[i];
        uint64_t pp = expand_pred_h(pg[H1(i)]);
        d[i] = (mm & pp) | (nn & ~pp);
    }
}

void HELPER(sve_cpy_m_s)(void *vd, void *vn, void *vg,
                         uint64_t mm, uint32_t desc)
{
    intptr_t i, opr_sz = simd_oprsz(desc) / 8;
    uint64_t *d = vd, *n = vn;
    uint8_t *pg = vg;

    mm = dup_const(MO_32, mm);
    for (i = 0; i < opr_sz; i += 1) {
        uint64_t nn = n[i];
        uint64_t pp = expand_pred_s(pg[H1(i)]);
        d[i] = (mm & pp) | (nn & ~pp);
    }
}

void HELPER(sve_cpy_m_d)(void *vd, void *vn, void *vg,
                         uint64_t mm, uint32_t desc)
{
    intptr_t i, opr_sz = simd_oprsz(desc) / 8;
    uint64_t *d = vd, *n = vn;
    uint8_t *pg = vg;

    for (i = 0; i < opr_sz; i += 1) {
        uint64_t nn = n[i];
        d[i] = (pg[H1(i)] & 1 ? mm : nn);
    }
}

void HELPER(sve_cpy_z_b)(void *vd, void *vg, uint64_t val, uint32_t desc)
{
    intptr_t i, opr_sz = simd_oprsz(desc) / 8;
    uint64_t *d = vd;
    uint8_t *pg = vg;

    val = dup_const(MO_8, val);
    for (i = 0; i < opr_sz; i += 1) {
        d[i] = val & expand_pred_b(pg[H1(i)]);
    }
}

void HELPER(sve_cpy_z_h)(void *vd, void *vg, uint64_t val, uint32_t desc)
{
    intptr_t i, opr_sz = simd_oprsz(desc) / 8;
    uint64_t *d = vd;
    uint8_t *pg = vg;

    val = dup_const(MO_16, val);
    for (i = 0; i < opr_sz; i += 1) {
        d[i] = val & expand_pred_h(pg[H1(i)]);
    }
}

void HELPER(sve_cpy_z_s)(void *vd, void *vg, uint64_t val, uint32_t desc)
{
    intptr_t i, opr_sz = simd_oprsz(desc) / 8;
    uint64_t *d = vd;
    uint8_t *pg = vg;

    val = dup_const(MO_32, val);
    for (i = 0; i < opr_sz; i += 1) {
        d[i] = val & expand_pred_s(pg[H1(i)]);
    }
}

void HELPER(sve_cpy_z_d)(void *vd, void *vg, uint64_t val, uint32_t desc)
{
    intptr_t i, opr_sz = simd_oprsz(desc) / 8;
    uint64_t *d = vd;
    uint8_t *pg = vg;

    for (i = 0; i < opr_sz; i += 1) {
        d[i] = (pg[H1(i)] & 1 ? val : 0);
    }
}

/* Big-endian hosts need to frob the byte indicies.  If the copy
 * happens to be 8-byte aligned, then no frobbing necessary.
 */
static void swap_memmove(void *vd, void *vs, size_t n)
{
    uintptr_t d = (uintptr_t)vd;
    uintptr_t s = (uintptr_t)vs;
    uintptr_t o = (d | s | n) & 7;
    size_t i;

#ifndef HOST_WORDS_BIGENDIAN
    o = 0;
#endif
    switch (o) {
    case 0:
        memmove(vd, vs, n);
        break;

    case 4:
        if (d < s || d >= s + n) {
            for (i = 0; i < n; i += 4) {
                *(uint32_t *)H1_4(d + i) = *(uint32_t *)H1_4(s + i);
            }
        } else {
            for (i = n; i > 0; ) {
                i -= 4;
                *(uint32_t *)H1_4(d + i) = *(uint32_t *)H1_4(s + i);
            }
        }
        break;

    case 2:
    case 6:
        if (d < s || d >= s + n) {
            for (i = 0; i < n; i += 2) {
                *(uint16_t *)H1_2(d + i) = *(uint16_t *)H1_2(s + i);
            }
        } else {
            for (i = n; i > 0; ) {
                i -= 2;
                *(uint16_t *)H1_2(d + i) = *(uint16_t *)H1_2(s + i);
            }
        }
        break;

    default:
        if (d < s || d >= s + n) {
            for (i = 0; i < n; i++) {
                *(uint8_t *)H1(d + i) = *(uint8_t *)H1(s + i);
            }
        } else {
            for (i = n; i > 0; ) {
                i -= 1;
                *(uint8_t *)H1(d + i) = *(uint8_t *)H1(s + i);
            }
        }
        break;
    }
}

/* Similarly for memset of 0.  */
static void swap_memzero(void *vd, size_t n)
{
    uintptr_t d = (uintptr_t)vd;
    uintptr_t o = (d | n) & 7;
    size_t i;

    /* Usually, the first bit of a predicate is set, so N is 0.  */
    if (likely(n == 0)) {
        return;
    }

#ifndef HOST_WORDS_BIGENDIAN
    o = 0;
#endif
    switch (o) {
    case 0:
        memset(vd, 0, n);
        break;

    case 4:
        for (i = 0; i < n; i += 4) {
            *(uint32_t *)H1_4(d + i) = 0;
        }
        break;

    case 2:
    case 6:
        for (i = 0; i < n; i += 2) {
            *(uint16_t *)H1_2(d + i) = 0;
        }
        break;

    default:
        for (i = 0; i < n; i++) {
            *(uint8_t *)H1(d + i) = 0;
        }
        break;
    }
}

void HELPER(sve_ext)(void *vd, void *vn, void *vm, uint32_t desc)
{
    intptr_t opr_sz = simd_oprsz(desc);
    size_t n_ofs = simd_data(desc);
    size_t n_siz = opr_sz - n_ofs;

    if (vd != vm) {
        swap_memmove(vd, (char *)vn + n_ofs, n_siz);
        swap_memmove((char *)vd + n_siz, vm, n_ofs);
    } else if (vd != vn) {
        swap_memmove((char *)vd + n_siz, vd, n_ofs);
        swap_memmove(vd, (char *)vn + n_ofs, n_siz);
    } else {
        /* vd == vn == vm.  Need temp space.  */
        ARMVectorReg tmp;
        swap_memmove(&tmp, vm, n_ofs);
        swap_memmove(vd, (char *)vd + n_ofs, n_siz);
        memcpy((char *)vd + n_siz, &tmp, n_ofs);
    }
}

#define DO_INSR(NAME, TYPE, H) \
void HELPER(NAME)(void *vd, void *vn, uint64_t val, uint32_t desc) \
{                                                                  \
    intptr_t opr_sz = simd_oprsz(desc);                            \
    swap_memmove((char *)vd + sizeof(TYPE), vn, opr_sz - sizeof(TYPE));    \
    *(TYPE *)((char *)vd + H(0)) = val;                                    \
}

DO_INSR(sve_insr_b, uint8_t, H1)
DO_INSR(sve_insr_h, uint16_t, H1_2)
DO_INSR(sve_insr_s, uint32_t, H1_4)
DO_INSR(sve_insr_d, uint64_t, )

#undef DO_INSR

void HELPER(sve_rev_b)(void *vd, void *vn, uint32_t desc)
{
    intptr_t i, j, opr_sz = simd_oprsz(desc);
    for (i = 0, j = opr_sz - 8; i < opr_sz / 2; i += 8, j -= 8) {
        uint64_t f = *(uint64_t *)((char *)vn + i);
        uint64_t b = *(uint64_t *)((char *)vn + j);
        *(uint64_t *)((char *)vd + i) = bswap64(b);
        *(uint64_t *)((char *)vd + j) = bswap64(f);
    }
}

void HELPER(sve_rev_h)(void *vd, void *vn, uint32_t desc)
{
    intptr_t i, j, opr_sz = simd_oprsz(desc);
    for (i = 0, j = opr_sz - 8; i < opr_sz / 2; i += 8, j -= 8) {
        uint64_t f = *(uint64_t *)((char *)vn + i);
        uint64_t b = *(uint64_t *)((char *)vn + j);
        *(uint64_t *)((char *)vd + i) = hswap64(b);
        *(uint64_t *)((char *)vd + j) = hswap64(f);
    }
}

void HELPER(sve_rev_s)(void *vd, void *vn, uint32_t desc)
{
    intptr_t i, j, opr_sz = simd_oprsz(desc);
    for (i = 0, j = opr_sz - 8; i < opr_sz / 2; i += 8, j -= 8) {
        uint64_t f = *(uint64_t *)((char *)vn + i);
        uint64_t b = *(uint64_t *)((char *)vn + j);
        *(uint64_t *)((char *)vd + i) = rol64(b, 32);
        *(uint64_t *)((char *)vd + j) = rol64(f, 32);
    }
}

void HELPER(sve_rev_d)(void *vd, void *vn, uint32_t desc)
{
    intptr_t i, j, opr_sz = simd_oprsz(desc);
    for (i = 0, j = opr_sz - 8; i < opr_sz / 2; i += 8, j -= 8) {
        uint64_t f = *(uint64_t *)((char *)vn + i);
        uint64_t b = *(uint64_t *)((char *)vn + j);
        *(uint64_t *)((char *)vd + i) = b;
        *(uint64_t *)((char *)vd + j) = f;
    }
}

#define DO_TBL(NAME, TYPE, H) \
void HELPER(NAME)(void *vd, void *vn, void *vm, uint32_t desc) \
{                                                              \
    intptr_t i, opr_sz = simd_oprsz(desc);                     \
    uintptr_t elem = opr_sz / sizeof(TYPE);                    \
    TYPE *d = vd, *n = vn, *m = vm;                            \
    ARMVectorReg tmp;                                          \
    if (unlikely(vd == vn)) {                                  \
        n = memcpy(&tmp, vn, opr_sz);                          \
    }                                                          \
    for (i = 0; i < elem; i++) {                               \
        TYPE j = m[H(i)];                                      \
        d[H(i)] = j < elem ? n[H(j)] : 0;                      \
    }                                                          \
}

DO_TBL(sve_tbl_b, uint8_t, H1)
DO_TBL(sve_tbl_h, uint16_t, H2)
DO_TBL(sve_tbl_s, uint32_t, H4)
DO_TBL(sve_tbl_d, uint64_t, )

#undef TBL

#define DO_UNPK(NAME, TYPED, TYPES, HD, HS) \
void HELPER(NAME)(void *vd, void *vn, uint32_t desc)           \
{                                                              \
    intptr_t i, opr_sz = simd_oprsz(desc);                     \
    TYPED *d = vd;                                             \
    TYPES *n = vn;                                             \
    ARMVectorReg tmp;                                          \
    if (unlikely((char *)vn - (char *)vd < opr_sz)) {                          \
        n = memcpy(&tmp, n, opr_sz / 2);                       \
    }                                                          \
    for (i = 0; i < opr_sz / sizeof(TYPED); i++) {             \
        d[HD(i)] = n[HS(i)];                                   \
    }                                                          \
}

DO_UNPK(sve_sunpk_h, int16_t, int8_t, H2, H1)
DO_UNPK(sve_sunpk_s, int32_t, int16_t, H4, H2)
DO_UNPK(sve_sunpk_d, int64_t, int32_t, , H4)

DO_UNPK(sve_uunpk_h, uint16_t, uint8_t, H2, H1)
DO_UNPK(sve_uunpk_s, uint32_t, uint16_t, H4, H2)
DO_UNPK(sve_uunpk_d, uint64_t, uint32_t, , H4)

#undef DO_UNPK

/* Mask of bits included in the even numbered predicates of width esz.
 * We also use this for expand_bits/compress_bits, and so extend the
 * same pattern out to 16-bit units.
 */
static const uint64_t even_bit_esz_masks[5] = {
    0x5555555555555555ull,
    0x3333333333333333ull,
    0x0f0f0f0f0f0f0f0full,
    0x00ff00ff00ff00ffull,
    0x0000ffff0000ffffull,
};

/* Zero-extend units of 2**N bits to units of 2**(N+1) bits.
 * For N==0, this corresponds to the operation that in qemu/bitops.h
 * we call half_shuffle64; this algorithm is from Hacker's Delight,
 * section 7-2 Shuffling Bits.
 */
static uint64_t expand_bits(uint64_t x, int n)
{
    int i;

    x &= 0xffffffffu;
    for (i = 4; i >= n; i--) {
        int sh = 1 << i;
        x = ((x << sh) | x) & even_bit_esz_masks[i];
    }
    return x;
}

/* Compress units of 2**(N+1) bits to units of 2**N bits.
 * For N==0, this corresponds to the operation that in qemu/bitops.h
 * we call half_unshuffle64; this algorithm is from Hacker's Delight,
 * section 7-2 Shuffling Bits, where it is called an inverse half shuffle.
 */
static uint64_t compress_bits(uint64_t x, int n)
{
    int i;

    for (i = n; i <= 4; i++) {
        int sh = 1 << i;
        x &= even_bit_esz_masks[i];
        x = (x >> sh) | x;
    }
    return x & 0xffffffffu;
}

void HELPER(sve_zip_p)(void *vd, void *vn, void *vm, uint32_t pred_desc)
{
    intptr_t oprsz = extract32(pred_desc, 0, SIMD_OPRSZ_BITS) + 2;
    int esz = extract32(pred_desc, SIMD_DATA_SHIFT, 2);
    intptr_t high = extract32(pred_desc, SIMD_DATA_SHIFT + 2, 1);
    uint64_t *d = vd;
    intptr_t i;

    if (oprsz <= 8) {
        uint64_t nn = *(uint64_t *)vn;
        uint64_t mm = *(uint64_t *)vm;
        int half = 4 * oprsz;

        nn = extract64(nn, high * half, half);
        mm = extract64(mm, high * half, half);
        nn = expand_bits(nn, esz);
        mm = expand_bits(mm, esz);
        d[0] = nn + (mm << (1 << esz));
    } else {
        ARMPredicateReg tmp_n, tmp_m;

        /* We produce output faster than we consume input.
           Therefore we must be mindful of possible overlap.  */
        if (((char *)vn - (char *)vd) < (uintptr_t)oprsz) {
            vn = memcpy(&tmp_n, vn, oprsz);
        }
        if (((char *)vm - (char *)vd) < (uintptr_t)oprsz) {
            vm = memcpy(&tmp_m, vm, oprsz);
        }
        if (high) {
            high = oprsz >> 1;
        }

        if ((high & 3) == 0) {
            uint32_t *n = vn, *m = vm;
            high >>= 2;

            for (i = 0; i < DIV_ROUND_UP(oprsz, 8); i++) {
                uint64_t nn = n[H4(high + i)];
                uint64_t mm = m[H4(high + i)];

                nn = expand_bits(nn, esz);
                mm = expand_bits(mm, esz);
                d[i] = nn + (mm << (1 << esz));
            }
        } else {
            uint8_t *n = vn, *m = vm;
            uint16_t *d16 = vd;

            for (i = 0; i < oprsz / 2; i++) {
                uint16_t nn = n[H1(high + i)];
                uint16_t mm = m[H1(high + i)];

                nn = expand_bits(nn, esz);
                mm = expand_bits(mm, esz);
                d16[H2(i)] = nn + (mm << (1 << esz));
            }
        }
    }
}

void HELPER(sve_uzp_p)(void *vd, void *vn, void *vm, uint32_t pred_desc)
{
    intptr_t oprsz = extract32(pred_desc, 0, SIMD_OPRSZ_BITS) + 2;
    int esz = extract32(pred_desc, SIMD_DATA_SHIFT, 2);
    int odd = extract32(pred_desc, SIMD_DATA_SHIFT + 2, 1) << esz;
    uint64_t *d = vd, *n = vn, *m = vm;
    uint64_t l, h;
    intptr_t i;

    if (oprsz <= 8) {
        l = compress_bits(n[0] >> odd, esz);
        h = compress_bits(m[0] >> odd, esz);
        d[0] = extract64(l + (h << (4 * oprsz)), 0, 8 * oprsz);
    } else {
        ARMPredicateReg tmp_m;
        intptr_t oprsz_16 = oprsz / 16;

        if (((char *)vm - (char *)vd) < (uintptr_t)oprsz) {
            m = memcpy(&tmp_m, vm, oprsz);
        }

        for (i = 0; i < oprsz_16; i++) {
            l = n[2 * i + 0];
            h = n[2 * i + 1];
            l = compress_bits(l >> odd, esz);
            h = compress_bits(h >> odd, esz);
            d[i] = l + (h << 32);
        }

        /* For VL which is not a power of 2, the results from M do not
           align nicely with the uint64_t for D.  Put the aligned results
           from M into TMP_M and then copy it into place afterward.  */
        if (oprsz & 15) {
            d[i] = compress_bits(n[2 * i] >> odd, esz);

            for (i = 0; i < oprsz_16; i++) {
                l = m[2 * i + 0];
                h = m[2 * i + 1];
                l = compress_bits(l >> odd, esz);
                h = compress_bits(h >> odd, esz);
                tmp_m.p[i] = l + (h << 32);
            }
            tmp_m.p[i] = compress_bits(m[2 * i] >> odd, esz);

            swap_memmove((char *)vd + oprsz / 2, &tmp_m, oprsz / 2);
        } else {
            for (i = 0; i < oprsz_16; i++) {
                l = m[2 * i + 0];
                h = m[2 * i + 1];
                l = compress_bits(l >> odd, esz);
                h = compress_bits(h >> odd, esz);
                d[oprsz_16 + i] = l + (h << 32);
            }
        }
    }
}

void HELPER(sve_trn_p)(void *vd, void *vn, void *vm, uint32_t pred_desc)
{
    intptr_t oprsz = extract32(pred_desc, 0, SIMD_OPRSZ_BITS) + 2;
    uintptr_t esz = extract32(pred_desc, SIMD_DATA_SHIFT, 2);
    bool odd = extract32(pred_desc, SIMD_DATA_SHIFT + 2, 1);
    uint64_t *d = vd, *n = vn, *m = vm;
    uint64_t mask;
    int shr, shl;
    intptr_t i;

    shl = 1 << esz;
    shr = 0;
    mask = even_bit_esz_masks[esz];
    if (odd) {
        mask <<= shl;
        shr = shl;
        shl = 0;
    }

    for (i = 0; i < DIV_ROUND_UP(oprsz, 8); i++) {
        uint64_t nn = (n[i] & mask) >> shr;
        uint64_t mm = (m[i] & mask) << shl;
        d[i] = nn + mm;
    }
}

/* Reverse units of 2**N bits.  */
static uint64_t reverse_bits_64(uint64_t x, int n)
{
    int i, sh;

    x = bswap64(x);
    for (i = 2, sh = 4; i >= n; i--, sh >>= 1) {
        uint64_t mask = even_bit_esz_masks[i];
        x = ((x & mask) << sh) | ((x >> sh) & mask);
    }
    return x;
}

static uint8_t reverse_bits_8(uint8_t x, int n)
{
    static const uint8_t mask[3] = { 0x55, 0x33, 0x0f };
    int i, sh;

    for (i = 2, sh = 4; i >= n; i--, sh >>= 1) {
        x = ((x & mask[i]) << sh) | ((x >> sh) & mask[i]);
    }
    return x;
}

void HELPER(sve_rev_p)(void *vd, void *vn, uint32_t pred_desc)
{
    intptr_t oprsz = extract32(pred_desc, 0, SIMD_OPRSZ_BITS) + 2;
    int esz = extract32(pred_desc, SIMD_DATA_SHIFT, 2);
    intptr_t i, oprsz_2 = oprsz / 2;

    if (oprsz <= 8) {
        uint64_t l = *(uint64_t *)vn;
        l = reverse_bits_64(l << (64 - 8 * oprsz), esz);
        *(uint64_t *)vd = l;
    } else if ((oprsz & 15) == 0) {
        for (i = 0; i < oprsz_2; i += 8) {
            intptr_t ih = oprsz - 8 - i;
            uint64_t l = reverse_bits_64(*(uint64_t *)((char *)vn + i), esz);
            uint64_t h = reverse_bits_64(*(uint64_t *)((char *)vn + ih), esz);
            *(uint64_t *)((char *)vd + i) = h;
            *(uint64_t *)((char *)vd + ih) = l;
        }
    } else {
        for (i = 0; i < oprsz_2; i += 1) {
            intptr_t il = H1(i);
            intptr_t ih = H1(oprsz - 1 - i);
            uint8_t l = reverse_bits_8(*(uint8_t *)((char *)vn + il), esz);
            uint8_t h = reverse_bits_8(*(uint8_t *)((char *)vn + ih), esz);
            *(uint8_t *)((char *)vd + il) = h;
            *(uint8_t *)((char *)vd + ih) = l;
        }
    }
}

void HELPER(sve_punpk_p)(void *vd, void *vn, uint32_t pred_desc)
{
    intptr_t oprsz = extract32(pred_desc, 0, SIMD_OPRSZ_BITS) + 2;
    intptr_t high = extract32(pred_desc, SIMD_DATA_SHIFT + 2, 1);
    uint64_t *d = vd;
    intptr_t i;

    if (oprsz <= 8) {
        uint64_t nn = *(uint64_t *)vn;
        int half = 4 * oprsz;

        nn = extract64(nn, high * half, half);
        nn = expand_bits(nn, 0);
        d[0] = nn;
    } else {
        ARMPredicateReg tmp_n;

        /* We produce output faster than we consume input.
           Therefore we must be mindful of possible overlap.  */
        if (((char *)vn - (char *)vd) < (uintptr_t)oprsz) {
            vn = memcpy(&tmp_n, vn, oprsz);
        }
        if (high) {
            high = oprsz >> 1;
        }

        if ((high & 3) == 0) {
            uint32_t *n = vn;
            high >>= 2;

            for (i = 0; i < DIV_ROUND_UP(oprsz, 8); i++) {
                uint64_t nn = n[H4(high + i)];
                d[i] = expand_bits(nn, 0);
            }
        } else {
            uint16_t *d16 = vd;
            uint8_t *n = vn;

            for (i = 0; i < oprsz / 2; i++) {
                uint16_t nn = n[H1(high + i)];
                d16[H2(i)] = expand_bits(nn, 0);
            }
        }
    }
}

#define DO_ZIP(NAME, TYPE, H) \
void HELPER(NAME)(void *vd, void *vn, void *vm, uint32_t desc)       \
{                                                                    \
    intptr_t oprsz = simd_oprsz(desc);                               \
    intptr_t i, oprsz_2 = oprsz / 2;                                 \
    ARMVectorReg tmp_n, tmp_m;                                       \
    /* We produce output faster than we consume input.               \
       Therefore we must be mindful of possible overlap.  */         \
    if (unlikely(((char *)vn - (char *)vd) < (uintptr_t)oprsz)) {                    \
        vn = memcpy(&tmp_n, vn, oprsz_2);                            \
    }                                                                \
    if (unlikely(((char *)vm - (char *)vd) < (uintptr_t)oprsz)) {                    \
        vm = memcpy(&tmp_m, vm, oprsz_2);                            \
    }                                                                \
    for (i = 0; i < oprsz_2; i += sizeof(TYPE)) {                    \
        *(TYPE *)((char *)vd + H(2 * i + 0)) = *(TYPE *)((char *)vn + H(i));         \
        *(TYPE *)((char *)vd + H(2 * i + sizeof(TYPE))) = *(TYPE *)((char *)vm + H(i)); \
    }                                                                \
}

DO_ZIP(sve_zip_b, uint8_t, H1)
DO_ZIP(sve_zip_h, uint16_t, H1_2)
DO_ZIP(sve_zip_s, uint32_t, H1_4)
DO_ZIP(sve_zip_d, uint64_t, )

#define DO_UZP(NAME, TYPE, H) \
void HELPER(NAME)(void *vd, void *vn, void *vm, uint32_t desc)         \
{                                                                      \
    intptr_t oprsz = simd_oprsz(desc);                                 \
    intptr_t oprsz_2 = oprsz / 2;                                      \
    intptr_t odd_ofs = simd_data(desc);                                \
    intptr_t i;                                                        \
    ARMVectorReg tmp_m;                                                \
    if (unlikely(((char *)vm - (char *)vd) < (uintptr_t)oprsz)) {                      \
        vm = memcpy(&tmp_m, vm, oprsz);                                \
    }                                                                  \
    for (i = 0; i < oprsz_2; i += sizeof(TYPE)) {                      \
        *(TYPE *)((char *)vd + H(i)) = *(TYPE *)((char *)vn + H(2 * i + odd_ofs));     \
    }                                                                  \
    for (i = 0; i < oprsz_2; i += sizeof(TYPE)) {                      \
        *(TYPE *)((char *)vd + H(oprsz_2 + i)) = *(TYPE *)((char *)vm + H(2 * i + odd_ofs)); \
    }                                                                  \
}

DO_UZP(sve_uzp_b, uint8_t, H1)
DO_UZP(sve_uzp_h, uint16_t, H1_2)
DO_UZP(sve_uzp_s, uint32_t, H1_4)
DO_UZP(sve_uzp_d, uint64_t, )

#define DO_TRN(NAME, TYPE, H) \
void HELPER(NAME)(void *vd, void *vn, void *vm, uint32_t desc)         \
{                                                                      \
    intptr_t oprsz = simd_oprsz(desc);                                 \
    intptr_t odd_ofs = simd_data(desc);                                \
    intptr_t i;                                                        \
    for (i = 0; i < oprsz; i += 2 * sizeof(TYPE)) {                    \
        TYPE ae = *(TYPE *)((char *)vn + H(i + odd_ofs));                      \
        TYPE be = *(TYPE *)((char *)vm + H(i + odd_ofs));                      \
        *(TYPE *)((char *)vd + H(i + 0)) = ae;                                 \
        *(TYPE *)((char *)vd + H(i + sizeof(TYPE))) = be;                      \
    }                                                                  \
}

DO_TRN(sve_trn_b, uint8_t, H1)
DO_TRN(sve_trn_h, uint16_t, H1_2)
DO_TRN(sve_trn_s, uint32_t, H1_4)
DO_TRN(sve_trn_d, uint64_t, )

#undef DO_ZIP
#undef DO_UZP
#undef DO_TRN

void HELPER(sve_compact_s)(void *vd, void *vn, void *vg, uint32_t desc)
{
    intptr_t i, j, opr_sz = simd_oprsz(desc) / 4;
    uint32_t *d = vd, *n = vn;
    uint8_t *pg = vg;

    for (i = j = 0; i < opr_sz; i++) {
        if (pg[H1(i / 2)] & (i & 1 ? 0x10 : 0x01)) {
            d[H4(j)] = n[H4(i)];
            j++;
        }
    }
    for (; j < opr_sz; j++) {
        d[H4(j)] = 0;
    }
}

void HELPER(sve_compact_d)(void *vd, void *vn, void *vg, uint32_t desc)
{
    intptr_t i, j, opr_sz = simd_oprsz(desc) / 8;
    uint64_t *d = vd, *n = vn;
    uint8_t *pg = vg;

    for (i = j = 0; i < opr_sz; i++) {
        if (pg[H1(i)] & 1) {
            d[j] = n[i];
            j++;
        }
    }
    for (; j < opr_sz; j++) {
        d[j] = 0;
    }
}

/* Similar to the ARM LastActiveElement pseudocode function, except the
 * result is multiplied by the element size.  This includes the not found
 * indication; e.g. not found for esz=3 is -8.
 */
int32_t HELPER(sve_last_active_element)(void *vg, uint32_t pred_desc)
{
    intptr_t oprsz = extract32(pred_desc, 0, SIMD_OPRSZ_BITS) + 2;
    intptr_t esz = extract32(pred_desc, SIMD_DATA_SHIFT, 2);

    return last_active_element(vg, DIV_ROUND_UP(oprsz, 8), esz);
}

void HELPER(sve_splice)(void *vd, void *vn, void *vm, void *vg, uint32_t desc)
{
    intptr_t opr_sz = simd_oprsz(desc) / 8;
    int esz = simd_data(desc);
    uint64_t pg, first_g, last_g, len, mask = pred_esz_masks[esz];
    intptr_t i, first_i, last_i;
    ARMVectorReg tmp;

    first_i = last_i = 0;
    first_g = last_g = 0;

    /* Find the extent of the active elements within VG.  */
    for (i = QEMU_ALIGN_UP(opr_sz, 8) - 8; i >= 0; i -= 8) {
        pg = *(uint64_t *)((char *)vg + i) & mask;
        if (pg) {
            if (last_g == 0) {
                last_g = pg;
                last_i = i;
            }
            first_g = pg;
            first_i = i;
        }
    }

    len = 0;
    if (first_g != 0) {
        first_i = first_i * 8 + ctz64(first_g);
        last_i = last_i * 8 + 63 - clz64(last_g);
        len = last_i - first_i + (1ULL << esz);
        if (vd == vm) {
            vm = memcpy(&tmp, vm, opr_sz * 8);
        }
        swap_memmove(vd, (char *)vn + first_i, len);
    }
    swap_memmove((char *)vd + len, vm, opr_sz * 8 - len);
}

void HELPER(sve_sel_zpzz_b)(void *vd, void *vn, void *vm,
                            void *vg, uint32_t desc)
{
    intptr_t i, opr_sz = simd_oprsz(desc) / 8;
    uint64_t *d = vd, *n = vn, *m = vm;
    uint8_t *pg = vg;

    for (i = 0; i < opr_sz; i += 1) {
        uint64_t nn = n[i], mm = m[i];
        uint64_t pp = expand_pred_b(pg[H1(i)]);
        d[i] = (nn & pp) | (mm & ~pp);
    }
}

void HELPER(sve_sel_zpzz_h)(void *vd, void *vn, void *vm,
                            void *vg, uint32_t desc)
{
    intptr_t i, opr_sz = simd_oprsz(desc) / 8;
    uint64_t *d = vd, *n = vn, *m = vm;
    uint8_t *pg = vg;

    for (i = 0; i < opr_sz; i += 1) {
        uint64_t nn = n[i], mm = m[i];
        uint64_t pp = expand_pred_h(pg[H1(i)]);
        d[i] = (nn & pp) | (mm & ~pp);
    }
}

void HELPER(sve_sel_zpzz_s)(void *vd, void *vn, void *vm,
                            void *vg, uint32_t desc)
{
    intptr_t i, opr_sz = simd_oprsz(desc) / 8;
    uint64_t *d = vd, *n = vn, *m = vm;
    uint8_t *pg = vg;

    for (i = 0; i < opr_sz; i += 1) {
        uint64_t nn = n[i], mm = m[i];
        uint64_t pp = expand_pred_s(pg[H1(i)]);
        d[i] = (nn & pp) | (mm & ~pp);
    }
}

void HELPER(sve_sel_zpzz_d)(void *vd, void *vn, void *vm,
                            void *vg, uint32_t desc)
{
    intptr_t i, opr_sz = simd_oprsz(desc) / 8;
    uint64_t *d = vd, *n = vn, *m = vm;
    uint8_t *pg = vg;

    for (i = 0; i < opr_sz; i += 1) {
        uint64_t nn = n[i], mm = m[i];
        d[i] = (pg[H1(i)] & 1 ? nn : mm);
    }
}

/* Two operand comparison controlled by a predicate.
 * ??? It is very tempting to want to be able to expand this inline
 * with x86 instructions, e.g.
 *
 *    vcmpeqw    zm, zn, %ymm0
 *    vpmovmskb  %ymm0, %eax
 *    and        $0x5555, %eax
 *    and        pg, %eax
 *
 * or even aarch64, e.g.
 *
 *    // mask = 4000 1000 0400 0100 0040 0010 0004 0001
 *    cmeq       v0.8h, zn, zm
 *    and        v0.8h, v0.8h, mask
 *    addv       h0, v0.8h
 *    and        v0.8b, pg
 *
 * However, coming up with an abstraction that allows vector inputs and
 * a scalar output, and also handles the byte-ordering of sub-uint64_t
 * scalar outputs, is tricky.
 */
#define DO_CMP_PPZZ(NAME, TYPE, OP, H, MASK)                                 \
uint32_t HELPER(NAME)(void *vd, void *vn, void *vm, void *vg, uint32_t desc) \
{                                                                            \
    intptr_t opr_sz = simd_oprsz(desc);                                      \
    uint32_t flags = PREDTEST_INIT;                                          \
    intptr_t i = opr_sz;                                                     \
    do {                                                                     \
        uint64_t out = 0, pg;                                                \
        do {                                                                 \
            i -= sizeof(TYPE), out <<= sizeof(TYPE);                         \
            TYPE nn = *(TYPE *)((char *)vn + H(i));                                  \
            TYPE mm = *(TYPE *)((char *)vm + H(i));                                  \
            out |= nn OP mm;                                                 \
        } while (i & 63);                                                    \
        pg = *(uint64_t *)((char *)vg + (i >> 3)) & MASK;                            \
        out &= pg;                                                           \
        *(uint64_t *)((char *)vd + (i >> 3)) = out;                                  \
        flags = iter_predtest_bwd(out, pg, flags);                           \
    } while (i > 0);                                                         \
    return flags;                                                            \
}

#define DO_CMP_PPZZ_B(NAME, TYPE, OP) \
    DO_CMP_PPZZ(NAME, TYPE, OP, H1,   0xffffffffffffffffull)
#define DO_CMP_PPZZ_H(NAME, TYPE, OP) \
    DO_CMP_PPZZ(NAME, TYPE, OP, H1_2, 0x5555555555555555ull)
#define DO_CMP_PPZZ_S(NAME, TYPE, OP) \
    DO_CMP_PPZZ(NAME, TYPE, OP, H1_4, 0x1111111111111111ull)
#define DO_CMP_PPZZ_D(NAME, TYPE, OP) \
    DO_CMP_PPZZ(NAME, TYPE, OP,     , 0x0101010101010101ull)

DO_CMP_PPZZ_B(sve_cmpeq_ppzz_b, uint8_t,  ==)
DO_CMP_PPZZ_H(sve_cmpeq_ppzz_h, uint16_t, ==)
DO_CMP_PPZZ_S(sve_cmpeq_ppzz_s, uint32_t, ==)
DO_CMP_PPZZ_D(sve_cmpeq_ppzz_d, uint64_t, ==)

DO_CMP_PPZZ_B(sve_cmpne_ppzz_b, uint8_t,  !=)
DO_CMP_PPZZ_H(sve_cmpne_ppzz_h, uint16_t, !=)
DO_CMP_PPZZ_S(sve_cmpne_ppzz_s, uint32_t, !=)
DO_CMP_PPZZ_D(sve_cmpne_ppzz_d, uint64_t, !=)

DO_CMP_PPZZ_B(sve_cmpgt_ppzz_b, int8_t,  >)
DO_CMP_PPZZ_H(sve_cmpgt_ppzz_h, int16_t, >)
DO_CMP_PPZZ_S(sve_cmpgt_ppzz_s, int32_t, >)
DO_CMP_PPZZ_D(sve_cmpgt_ppzz_d, int64_t, >)

DO_CMP_PPZZ_B(sve_cmpge_ppzz_b, int8_t,  >=)
DO_CMP_PPZZ_H(sve_cmpge_ppzz_h, int16_t, >=)
DO_CMP_PPZZ_S(sve_cmpge_ppzz_s, int32_t, >=)
DO_CMP_PPZZ_D(sve_cmpge_ppzz_d, int64_t, >=)

DO_CMP_PPZZ_B(sve_cmphi_ppzz_b, uint8_t,  >)
DO_CMP_PPZZ_H(sve_cmphi_ppzz_h, uint16_t, >)
DO_CMP_PPZZ_S(sve_cmphi_ppzz_s, uint32_t, >)
DO_CMP_PPZZ_D(sve_cmphi_ppzz_d, uint64_t, >)

DO_CMP_PPZZ_B(sve_cmphs_ppzz_b, uint8_t,  >=)
DO_CMP_PPZZ_H(sve_cmphs_ppzz_h, uint16_t, >=)
DO_CMP_PPZZ_S(sve_cmphs_ppzz_s, uint32_t, >=)
DO_CMP_PPZZ_D(sve_cmphs_ppzz_d, uint64_t, >=)

#undef DO_CMP_PPZZ_B
#undef DO_CMP_PPZZ_H
#undef DO_CMP_PPZZ_S
#undef DO_CMP_PPZZ_D
#undef DO_CMP_PPZZ

/* Similar, but the second source is "wide".  */
#define DO_CMP_PPZW(NAME, TYPE, TYPEW, OP, H, MASK)                     \
uint32_t HELPER(NAME)(void *vd, void *vn, void *vm, void *vg, uint32_t desc) \
{                                                                            \
    intptr_t opr_sz = simd_oprsz(desc);                                      \
    uint32_t flags = PREDTEST_INIT;                                          \
    intptr_t i = opr_sz;                                                     \
    do {                                                                     \
        uint64_t out = 0, pg;                                                \
        do {                                                                 \
            TYPEW mm = *(TYPEW *)((char *)vm + i - 8);                               \
            do {                                                             \
                i -= sizeof(TYPE), out <<= sizeof(TYPE);                     \
                TYPE nn = *(TYPE *)((char *)vn + H(i));                              \
                out |= nn OP mm;                                             \
            } while (i & 7);                                                 \
        } while (i & 63);                                                    \
        pg = *(uint64_t *)((char *)vg + (i >> 3)) & MASK;                            \
        out &= pg;                                                           \
        *(uint64_t *)((char *)vd + (i >> 3)) = out;                                  \
        flags = iter_predtest_bwd(out, pg, flags);                           \
    } while (i > 0);                                                         \
    return flags;                                                            \
}

#define DO_CMP_PPZW_B(NAME, TYPE, TYPEW, OP) \
    DO_CMP_PPZW(NAME, TYPE, TYPEW, OP, H1,   0xffffffffffffffffull)
#define DO_CMP_PPZW_H(NAME, TYPE, TYPEW, OP) \
    DO_CMP_PPZW(NAME, TYPE, TYPEW, OP, H1_2, 0x5555555555555555ull)
#define DO_CMP_PPZW_S(NAME, TYPE, TYPEW, OP) \
    DO_CMP_PPZW(NAME, TYPE, TYPEW, OP, H1_4, 0x1111111111111111ull)

DO_CMP_PPZW_B(sve_cmpeq_ppzw_b, int8_t,  uint64_t, ==)
DO_CMP_PPZW_H(sve_cmpeq_ppzw_h, int16_t, uint64_t, ==)
DO_CMP_PPZW_S(sve_cmpeq_ppzw_s, int32_t, uint64_t, ==)

DO_CMP_PPZW_B(sve_cmpne_ppzw_b, int8_t,  uint64_t, !=)
DO_CMP_PPZW_H(sve_cmpne_ppzw_h, int16_t, uint64_t, !=)
DO_CMP_PPZW_S(sve_cmpne_ppzw_s, int32_t, uint64_t, !=)

DO_CMP_PPZW_B(sve_cmpgt_ppzw_b, int8_t,   int64_t, >)
DO_CMP_PPZW_H(sve_cmpgt_ppzw_h, int16_t,  int64_t, >)
DO_CMP_PPZW_S(sve_cmpgt_ppzw_s, int32_t,  int64_t, >)

DO_CMP_PPZW_B(sve_cmpge_ppzw_b, int8_t,   int64_t, >=)
DO_CMP_PPZW_H(sve_cmpge_ppzw_h, int16_t,  int64_t, >=)
DO_CMP_PPZW_S(sve_cmpge_ppzw_s, int32_t,  int64_t, >=)

DO_CMP_PPZW_B(sve_cmphi_ppzw_b, uint8_t,  uint64_t, >)
DO_CMP_PPZW_H(sve_cmphi_ppzw_h, uint16_t, uint64_t, >)
DO_CMP_PPZW_S(sve_cmphi_ppzw_s, uint32_t, uint64_t, >)

DO_CMP_PPZW_B(sve_cmphs_ppzw_b, uint8_t,  uint64_t, >=)
DO_CMP_PPZW_H(sve_cmphs_ppzw_h, uint16_t, uint64_t, >=)
DO_CMP_PPZW_S(sve_cmphs_ppzw_s, uint32_t, uint64_t, >=)

DO_CMP_PPZW_B(sve_cmplt_ppzw_b, int8_t,   int64_t, <)
DO_CMP_PPZW_H(sve_cmplt_ppzw_h, int16_t,  int64_t, <)
DO_CMP_PPZW_S(sve_cmplt_ppzw_s, int32_t,  int64_t, <)

DO_CMP_PPZW_B(sve_cmple_ppzw_b, int8_t,   int64_t, <=)
DO_CMP_PPZW_H(sve_cmple_ppzw_h, int16_t,  int64_t, <=)
DO_CMP_PPZW_S(sve_cmple_ppzw_s, int32_t,  int64_t, <=)

DO_CMP_PPZW_B(sve_cmplo_ppzw_b, uint8_t,  uint64_t, <)
DO_CMP_PPZW_H(sve_cmplo_ppzw_h, uint16_t, uint64_t, <)
DO_CMP_PPZW_S(sve_cmplo_ppzw_s, uint32_t, uint64_t, <)

DO_CMP_PPZW_B(sve_cmpls_ppzw_b, uint8_t,  uint64_t, <=)
DO_CMP_PPZW_H(sve_cmpls_ppzw_h, uint16_t, uint64_t, <=)
DO_CMP_PPZW_S(sve_cmpls_ppzw_s, uint32_t, uint64_t, <=)

#undef DO_CMP_PPZW_B
#undef DO_CMP_PPZW_H
#undef DO_CMP_PPZW_S
#undef DO_CMP_PPZW

/* Similar, but the second source is immediate.  */
#define DO_CMP_PPZI(NAME, TYPE, OP, H, MASK)                         \
uint32_t HELPER(NAME)(void *vd, void *vn, void *vg, uint32_t desc)   \
{                                                                    \
    intptr_t opr_sz = simd_oprsz(desc);                              \
    uint32_t flags = PREDTEST_INIT;                                  \
    TYPE mm = simd_data(desc);                                       \
    intptr_t i = opr_sz;                                             \
    do {                                                             \
        uint64_t out = 0, pg;                                        \
        do {                                                         \
            i -= sizeof(TYPE), out <<= sizeof(TYPE);                 \
            TYPE nn = *(TYPE *)((char *)vn + H(i));                          \
            out |= nn OP mm;                                         \
        } while (i & 63);                                            \
        pg = *(uint64_t *)((char *)vg + (i >> 3)) & MASK;                    \
        out &= pg;                                                   \
        *(uint64_t *)((char *)vd + (i >> 3)) = out;                          \
        flags = iter_predtest_bwd(out, pg, flags);                   \
    } while (i > 0);                                                 \
    return flags;                                                    \
}

#define DO_CMP_PPZI_B(NAME, TYPE, OP) \
    DO_CMP_PPZI(NAME, TYPE, OP, H1,   0xffffffffffffffffull)
#define DO_CMP_PPZI_H(NAME, TYPE, OP) \
    DO_CMP_PPZI(NAME, TYPE, OP, H1_2, 0x5555555555555555ull)
#define DO_CMP_PPZI_S(NAME, TYPE, OP) \
    DO_CMP_PPZI(NAME, TYPE, OP, H1_4, 0x1111111111111111ull)
#define DO_CMP_PPZI_D(NAME, TYPE, OP) \
    DO_CMP_PPZI(NAME, TYPE, OP,     , 0x0101010101010101ull)

DO_CMP_PPZI_B(sve_cmpeq_ppzi_b, uint8_t,  ==)
DO_CMP_PPZI_H(sve_cmpeq_ppzi_h, uint16_t, ==)
DO_CMP_PPZI_S(sve_cmpeq_ppzi_s, uint32_t, ==)
DO_CMP_PPZI_D(sve_cmpeq_ppzi_d, uint64_t, ==)

DO_CMP_PPZI_B(sve_cmpne_ppzi_b, uint8_t,  !=)
DO_CMP_PPZI_H(sve_cmpne_ppzi_h, uint16_t, !=)
DO_CMP_PPZI_S(sve_cmpne_ppzi_s, uint32_t, !=)
DO_CMP_PPZI_D(sve_cmpne_ppzi_d, uint64_t, !=)

DO_CMP_PPZI_B(sve_cmpgt_ppzi_b, int8_t,  >)
DO_CMP_PPZI_H(sve_cmpgt_ppzi_h, int16_t, >)
DO_CMP_PPZI_S(sve_cmpgt_ppzi_s, int32_t, >)
DO_CMP_PPZI_D(sve_cmpgt_ppzi_d, int64_t, >)

DO_CMP_PPZI_B(sve_cmpge_ppzi_b, int8_t,  >=)
DO_CMP_PPZI_H(sve_cmpge_ppzi_h, int16_t, >=)
DO_CMP_PPZI_S(sve_cmpge_ppzi_s, int32_t, >=)
DO_CMP_PPZI_D(sve_cmpge_ppzi_d, int64_t, >=)

DO_CMP_PPZI_B(sve_cmphi_ppzi_b, uint8_t,  >)
DO_CMP_PPZI_H(sve_cmphi_ppzi_h, uint16_t, >)
DO_CMP_PPZI_S(sve_cmphi_ppzi_s, uint32_t, >)
DO_CMP_PPZI_D(sve_cmphi_ppzi_d, uint64_t, >)

DO_CMP_PPZI_B(sve_cmphs_ppzi_b, uint8_t,  >=)
DO_CMP_PPZI_H(sve_cmphs_ppzi_h, uint16_t, >=)
DO_CMP_PPZI_S(sve_cmphs_ppzi_s, uint32_t, >=)
DO_CMP_PPZI_D(sve_cmphs_ppzi_d, uint64_t, >=)

DO_CMP_PPZI_B(sve_cmplt_ppzi_b, int8_t,  <)
DO_CMP_PPZI_H(sve_cmplt_ppzi_h, int16_t, <)
DO_CMP_PPZI_S(sve_cmplt_ppzi_s, int32_t, <)
DO_CMP_PPZI_D(sve_cmplt_ppzi_d, int64_t, <)

DO_CMP_PPZI_B(sve_cmple_ppzi_b, int8_t,  <=)
DO_CMP_PPZI_H(sve_cmple_ppzi_h, int16_t, <=)
DO_CMP_PPZI_S(sve_cmple_ppzi_s, int32_t, <=)
DO_CMP_PPZI_D(sve_cmple_ppzi_d, int64_t, <=)

DO_CMP_PPZI_B(sve_cmplo_ppzi_b, uint8_t,  <)
DO_CMP_PPZI_H(sve_cmplo_ppzi_h, uint16_t, <)
DO_CMP_PPZI_S(sve_cmplo_ppzi_s, uint32_t, <)
DO_CMP_PPZI_D(sve_cmplo_ppzi_d, uint64_t, <)

DO_CMP_PPZI_B(sve_cmpls_ppzi_b, uint8_t,  <=)
DO_CMP_PPZI_H(sve_cmpls_ppzi_h, uint16_t, <=)
DO_CMP_PPZI_S(sve_cmpls_ppzi_s, uint32_t, <=)
DO_CMP_PPZI_D(sve_cmpls_ppzi_d, uint64_t, <=)

#undef DO_CMP_PPZI_B
#undef DO_CMP_PPZI_H
#undef DO_CMP_PPZI_S
#undef DO_CMP_PPZI_D
#undef DO_CMP_PPZI

/* Similar to the ARM LastActive pseudocode function.  */
static bool last_active_pred(void *vd, void *vg, intptr_t oprsz)
{
    intptr_t i;

    for (i = QEMU_ALIGN_UP(oprsz, 8) - 8; i >= 0; i -= 8) {
        uint64_t pg = *(uint64_t *)((char *)vg + i);
        if (pg) {
            return (pow2floor(pg) & *(uint64_t *)((char *)vd + i)) != 0;
        }
    }
    return 0;
}

/* Compute a mask into RETB that is true for all G, up to and including
 * (if after) or excluding (if !after) the first G & N.
 * Return true if BRK found.
 */
static bool compute_brk(uint64_t *retb, uint64_t n, uint64_t g,
                        bool brk, bool after)
{
    uint64_t b;

    if (brk) {
        b = 0;
    } else if ((g & n) == 0) {
        /* For all G, no N are set; break not found.  */
        b = g;
    } else {
        /* Break somewhere in N.  Locate it.  */
        b = g & n;            /* guard true, pred true */
#ifdef _MSC_VER
        b = b & (0 - b);      /* first such */
#else
        b = b & -b;           /* first such */
#endif
        if (after) {
            b = b | (b - 1);  /* break after same */
        } else {
            b = b - 1;        /* break before same */
        }
        brk = true;
    }

    *retb = b;
    return brk;
}

/* Compute a zeroing BRK.  */
static void compute_brk_z(uint64_t *d, uint64_t *n, uint64_t *g,
                          intptr_t oprsz, bool after)
{
    bool brk = false;
    intptr_t i;

    for (i = 0; i < DIV_ROUND_UP(oprsz, 8); ++i) {
        uint64_t this_b, this_g = g[i];

        brk = compute_brk(&this_b, n[i], this_g, brk, after);
        d[i] = this_b & this_g;
    }
}

/* Likewise, but also compute flags.  */
static uint32_t compute_brks_z(uint64_t *d, uint64_t *n, uint64_t *g,
                               intptr_t oprsz, bool after)
{
    uint32_t flags = PREDTEST_INIT;
    bool brk = false;
    intptr_t i;

    for (i = 0; i < DIV_ROUND_UP(oprsz, 8); ++i) {
        uint64_t this_b, this_d, this_g = g[i];

        brk = compute_brk(&this_b, n[i], this_g, brk, after);
        d[i] = this_d = this_b & this_g;
        flags = iter_predtest_fwd(this_d, this_g, flags);
    }
    return flags;
}

/* Compute a merging BRK.  */
static void compute_brk_m(uint64_t *d, uint64_t *n, uint64_t *g,
                          intptr_t oprsz, bool after)
{
    bool brk = false;
    intptr_t i;

    for (i = 0; i < DIV_ROUND_UP(oprsz, 8); ++i) {
        uint64_t this_b, this_g = g[i];

        brk = compute_brk(&this_b, n[i], this_g, brk, after);
        d[i] = (this_b & this_g) | (d[i] & ~this_g);
    }
}

/* Likewise, but also compute flags.  */
static uint32_t compute_brks_m(uint64_t *d, uint64_t *n, uint64_t *g,
                               intptr_t oprsz, bool after)
{
    uint32_t flags = PREDTEST_INIT;
    bool brk = false;
    intptr_t i;

    for (i = 0; i < oprsz / 8; ++i) {
        uint64_t this_b, this_d = d[i], this_g = g[i];

        brk = compute_brk(&this_b, n[i], this_g, brk, after);
        d[i] = this_d = (this_b & this_g) | (this_d & ~this_g);
        flags = iter_predtest_fwd(this_d, this_g, flags);
    }
    return flags;
}

static uint32_t do_zero(ARMPredicateReg *d, intptr_t oprsz)
{
    /* It is quicker to zero the whole predicate than loop on OPRSZ.
     * The compiler should turn this into 4 64-bit integer stores.
     */
    memset(d, 0, sizeof(ARMPredicateReg));
    return PREDTEST_INIT;
}

void HELPER(sve_brkpa)(void *vd, void *vn, void *vm, void *vg,
                       uint32_t pred_desc)
{
    intptr_t oprsz = extract32(pred_desc, 0, SIMD_OPRSZ_BITS) + 2;
    if (last_active_pred(vn, vg, oprsz)) {
        compute_brk_z(vd, vm, vg, oprsz, true);
    } else {
        do_zero(vd, oprsz);
    }
}

uint32_t HELPER(sve_brkpas)(void *vd, void *vn, void *vm, void *vg,
                            uint32_t pred_desc)
{
    intptr_t oprsz = extract32(pred_desc, 0, SIMD_OPRSZ_BITS) + 2;
    if (last_active_pred(vn, vg, oprsz)) {
        return compute_brks_z(vd, vm, vg, oprsz, true);
    } else {
        return do_zero(vd, oprsz);
    }
}

void HELPER(sve_brkpb)(void *vd, void *vn, void *vm, void *vg,
                       uint32_t pred_desc)
{
    intptr_t oprsz = extract32(pred_desc, 0, SIMD_OPRSZ_BITS) + 2;
    if (last_active_pred(vn, vg, oprsz)) {
        compute_brk_z(vd, vm, vg, oprsz, false);
    } else {
        do_zero(vd, oprsz);
    }
}

uint32_t HELPER(sve_brkpbs)(void *vd, void *vn, void *vm, void *vg,
                            uint32_t pred_desc)
{
    intptr_t oprsz = extract32(pred_desc, 0, SIMD_OPRSZ_BITS) + 2;
    if (last_active_pred(vn, vg, oprsz)) {
        return compute_brks_z(vd, vm, vg, oprsz, false);
    } else {
        return do_zero(vd, oprsz);
    }
}

void HELPER(sve_brka_z)(void *vd, void *vn, void *vg, uint32_t pred_desc)
{
    intptr_t oprsz = extract32(pred_desc, 0, SIMD_OPRSZ_BITS) + 2;
    compute_brk_z(vd, vn, vg, oprsz, true);
}

uint32_t HELPER(sve_brkas_z)(void *vd, void *vn, void *vg, uint32_t pred_desc)
{
    intptr_t oprsz = extract32(pred_desc, 0, SIMD_OPRSZ_BITS) + 2;
    return compute_brks_z(vd, vn, vg, oprsz, true);
}

void HELPER(sve_brkb_z)(void *vd, void *vn, void *vg, uint32_t pred_desc)
{
    intptr_t oprsz = extract32(pred_desc, 0, SIMD_OPRSZ_BITS) + 2;
    compute_brk_z(vd, vn, vg, oprsz, false);
}

uint32_t HELPER(sve_brkbs_z)(void *vd, void *vn, void *vg, uint32_t pred_desc)
{
    intptr_t oprsz = extract32(pred_desc, 0, SIMD_OPRSZ_BITS) + 2;
    return compute_brks_z(vd, vn, vg, oprsz, false);
}

void HELPER(sve_brka_m)(void *vd, void *vn, void *vg, uint32_t pred_desc)
{
    intptr_t oprsz = extract32(pred_desc, 0, SIMD_OPRSZ_BITS) + 2;
    compute_brk_m(vd, vn, vg, oprsz, true);
}

uint32_t HELPER(sve_brkas_m)(void *vd, void *vn, void *vg, uint32_t pred_desc)
{
    intptr_t oprsz = extract32(pred_desc, 0, SIMD_OPRSZ_BITS) + 2;
    return compute_brks_m(vd, vn, vg, oprsz, true);
}

void HELPER(sve_brkb_m)(void *vd, void *vn, void *vg, uint32_t pred_desc)
{
    intptr_t oprsz = extract32(pred_desc, 0, SIMD_OPRSZ_BITS) + 2;
    compute_brk_m(vd, vn, vg, oprsz, false);
}

uint32_t HELPER(sve_brkbs_m)(void *vd, void *vn, void *vg, uint32_t pred_desc)
{
    intptr_t oprsz = extract32(pred_desc, 0, SIMD_OPRSZ_BITS) + 2;
    return compute_brks_m(vd, vn, vg, oprsz, false);
}

void HELPER(sve_brkn)(void *vd, void *vn, void *vg, uint32_t pred_desc)
{
    intptr_t oprsz = extract32(pred_desc, 0, SIMD_OPRSZ_BITS) + 2;

    if (!last_active_pred(vn, vg, oprsz)) {
        do_zero(vd, oprsz);
    }
}

/* As if PredTest(Ones(PL), D, esz).  */
static uint32_t predtest_ones(ARMPredicateReg *d, intptr_t oprsz,
                              uint64_t esz_mask)
{
    uint32_t flags = PREDTEST_INIT;
    intptr_t i;

    for (i = 0; i < oprsz / 8; i++) {
        flags = iter_predtest_fwd(d->p[i], esz_mask, flags);
    }
    if (oprsz & 7) {
        uint64_t mask = ~(0xffffffffffffffffULL << (8 * (oprsz & 7)));
        flags = iter_predtest_fwd(d->p[i], esz_mask & mask, flags);
    }
    return flags;
}

uint32_t HELPER(sve_brkns)(void *vd, void *vn, void *vg, uint32_t pred_desc)
{
    intptr_t oprsz = extract32(pred_desc, 0, SIMD_OPRSZ_BITS) + 2;

    if (last_active_pred(vn, vg, oprsz)) {
        return predtest_ones(vd, oprsz, -1);
    } else {
        return do_zero(vd, oprsz);
    }
}

uint64_t HELPER(sve_cntp)(void *vn, void *vg, uint32_t pred_desc)
{
    intptr_t oprsz = extract32(pred_desc, 0, SIMD_OPRSZ_BITS) + 2;
    intptr_t esz = extract32(pred_desc, SIMD_DATA_SHIFT, 2);
    uint64_t *n = vn, *g = vg, sum = 0, mask = pred_esz_masks[esz];
    intptr_t i;

    for (i = 0; i < DIV_ROUND_UP(oprsz, 8); ++i) {
        uint64_t t = n[i] & g[i] & mask;
        sum += ctpop64(t);
    }
    return sum;
}

uint32_t HELPER(sve_while)(void *vd, uint32_t count, uint32_t pred_desc)
{
    uintptr_t oprsz = extract32(pred_desc, 0, SIMD_OPRSZ_BITS) + 2;
    intptr_t esz = extract32(pred_desc, SIMD_DATA_SHIFT, 2);
    uint64_t esz_mask = pred_esz_masks[esz];
    ARMPredicateReg *d = vd;
    uint32_t flags;
    intptr_t i;

    /* Begin with a zero predicate register.  */
    flags = do_zero(d, oprsz);
    if (count == 0) {
        return flags;
    }

    /* Set all of the requested bits.  */
    for (i = 0; i < count / 64; ++i) {
        d->p[i] = esz_mask;
    }
    if (count & 63) {
        d->p[i] = MAKE_64BIT_MASK(0, count & 63) & esz_mask;
    }

    return predtest_ones(d, oprsz, esz_mask);
}

/* Recursive reduction on a function;
 * C.f. the ARM ARM function ReducePredicated.
 *
 * While it would be possible to write this without the DATA temporary,
 * it is much simpler to process the predicate register this way.
 * The recursion is bounded to depth 7 (128 fp16 elements), so there's
 * little to gain with a more complex non-recursive form.
 */
#define DO_REDUCE(NAME, TYPE, H, FUNC, IDENT)                         \
static TYPE NAME##_reduce(TYPE *data, float_status *status, uintptr_t n) \
{                                                                     \
    if (n == 1) {                                                     \
        return *data;                                                 \
    } else {                                                          \
        uintptr_t half = n / 2;                                       \
        TYPE lo = NAME##_reduce(data, status, half);                  \
        TYPE hi = NAME##_reduce(data + half, status, half);           \
        return TYPE##_##FUNC(lo, hi, status);                         \
    }                                                                 \
}                                                                     \
uint64_t HELPER(NAME)(void *vn, void *vg, void *vs, uint32_t desc)    \
{                                                                     \
    uintptr_t i, oprsz = simd_oprsz(desc), maxsz = simd_maxsz(desc);  \
    TYPE data[sizeof(ARMVectorReg) / sizeof(TYPE)];                   \
    for (i = 0; i < oprsz; ) {                                        \
        uint16_t pg = *(uint16_t *)((char *)vg + H1_2(i >> 3));               \
        do {                                                          \
            TYPE nn = *(TYPE *)((char *)vn + H(i));                           \
            *(TYPE *)((char *)data + i) = (pg & 1 ? nn : IDENT);      \
            i += sizeof(TYPE), pg >>= sizeof(TYPE);                   \
        } while (i & 15);                                             \
    }                                                                 \
    for (; i < maxsz; i += sizeof(TYPE)) {                            \
        *(TYPE *)((char *)data + i) = IDENT;                          \
    }                                                                 \
    return NAME##_reduce(data, vs, maxsz / sizeof(TYPE));             \
}

DO_REDUCE(sve_faddv_h, float16, H1_2, add, float16_zero)
DO_REDUCE(sve_faddv_s, float32, H1_4, add, float32_zero)
DO_REDUCE(sve_faddv_d, float64,     , add, float64_zero)

/* Identity is floatN_default_nan, without the function call.  */
DO_REDUCE(sve_fminnmv_h, float16, H1_2, minnum, 0x7E00)
DO_REDUCE(sve_fminnmv_s, float32, H1_4, minnum, 0x7FC00000)
DO_REDUCE(sve_fminnmv_d, float64,     , minnum, 0x7FF8000000000000ULL)

DO_REDUCE(sve_fmaxnmv_h, float16, H1_2, maxnum, 0x7E00)
DO_REDUCE(sve_fmaxnmv_s, float32, H1_4, maxnum, 0x7FC00000)
DO_REDUCE(sve_fmaxnmv_d, float64,     , maxnum, 0x7FF8000000000000ULL)

DO_REDUCE(sve_fminv_h, float16, H1_2, min, float16_infinity)
DO_REDUCE(sve_fminv_s, float32, H1_4, min, float32_infinity)
DO_REDUCE(sve_fminv_d, float64,     , min, float64_infinity)

DO_REDUCE(sve_fmaxv_h, float16, H1_2, max, float16_chs(float16_infinity))
DO_REDUCE(sve_fmaxv_s, float32, H1_4, max, float32_chs(float32_infinity))
DO_REDUCE(sve_fmaxv_d, float64,     , max, float64_chs(float64_infinity))

#undef DO_REDUCE

uint64_t HELPER(sve_fadda_h)(uint64_t nn, void *vm, void *vg,
                             void *status, uint32_t desc)
{
    intptr_t i = 0, opr_sz = simd_oprsz(desc);
    float16 result = nn;

    do {
        uint16_t pg = *(uint16_t *)((char *)vg + H1_2(i >> 3));
        do {
            if (pg & 1) {
                float16 mm = *(float16 *)((char *)vm + H1_2(i));
                result = float16_add(result, mm, status);
            }
            i += sizeof(float16), pg >>= sizeof(float16);
        } while (i & 15);
    } while (i < opr_sz);

    return result;
}

uint64_t HELPER(sve_fadda_s)(uint64_t nn, void *vm, void *vg,
                             void *status, uint32_t desc)
{
    intptr_t i = 0, opr_sz = simd_oprsz(desc);
    float32 result = nn;

    do {
        uint16_t pg = *(uint16_t *)((char *)vg + H1_2(i >> 3));
        do {
            if (pg & 1) {
                float32 mm = *(float32 *)((char *)vm + H1_2(i));
                result = float32_add(result, mm, status);
            }
            i += sizeof(float32), pg >>= sizeof(float32);
        } while (i & 15);
    } while (i < opr_sz);

    return result;
}

uint64_t HELPER(sve_fadda_d)(uint64_t nn, void *vm, void *vg,
                             void *status, uint32_t desc)
{
    intptr_t i = 0, opr_sz = simd_oprsz(desc) / 8;
    uint64_t *m = vm;
    uint8_t *pg = vg;

    for (i = 0; i < opr_sz; i++) {
        if (pg[H1(i)] & 1) {
            nn = float64_add(nn, m[i], status);
        }
    }

    return nn;
}

/* Fully general three-operand expander, controlled by a predicate,
 * With the extra float_status parameter.
 */
#define DO_ZPZZ_FP(NAME, TYPE, H, OP)                           \
void HELPER(NAME)(void *vd, void *vn, void *vm, void *vg,       \
                  void *status, uint32_t desc)                  \
{                                                               \
    intptr_t i = simd_oprsz(desc);                              \
    uint64_t *g = vg;                                           \
    do {                                                        \
        uint64_t pg = g[(i - 1) >> 6];                          \
        do {                                                    \
            i -= sizeof(TYPE);                                  \
            if (likely((pg >> (i & 63)) & 1)) {                 \
                TYPE nn = *(TYPE *)((char *)vn + H(i));                 \
                TYPE mm = *(TYPE *)((char *)vm + H(i));                 \
                *(TYPE *)((char *)vd + H(i)) = OP(nn, mm, status);      \
            }                                                   \
        } while (i & 63);                                       \
    } while (i != 0);                                           \
}

DO_ZPZZ_FP(sve_fadd_h, uint16_t, H1_2, float16_add)
DO_ZPZZ_FP(sve_fadd_s, uint32_t, H1_4, float32_add)
DO_ZPZZ_FP(sve_fadd_d, uint64_t,     , float64_add)

DO_ZPZZ_FP(sve_fsub_h, uint16_t, H1_2, float16_sub)
DO_ZPZZ_FP(sve_fsub_s, uint32_t, H1_4, float32_sub)
DO_ZPZZ_FP(sve_fsub_d, uint64_t,     , float64_sub)

DO_ZPZZ_FP(sve_fmul_h, uint16_t, H1_2, float16_mul)
DO_ZPZZ_FP(sve_fmul_s, uint32_t, H1_4, float32_mul)
DO_ZPZZ_FP(sve_fmul_d, uint64_t,     , float64_mul)

DO_ZPZZ_FP(sve_fdiv_h, uint16_t, H1_2, float16_div)
DO_ZPZZ_FP(sve_fdiv_s, uint32_t, H1_4, float32_div)
DO_ZPZZ_FP(sve_fdiv_d, uint64_t,     , float64_div)

DO_ZPZZ_FP(sve_fmin_h, uint16_t, H1_2, float16_min)
DO_ZPZZ_FP(sve_fmin_s, uint32_t, H1_4, float32_min)
DO_ZPZZ_FP(sve_fmin_d, uint64_t,     , float64_min)

DO_ZPZZ_FP(sve_fmax_h, uint16_t, H1_2, float16_max)
DO_ZPZZ_FP(sve_fmax_s, uint32_t, H1_4, float32_max)
DO_ZPZZ_FP(sve_fmax_d, uint64_t,     , float64_max)

DO_ZPZZ_FP(sve_fminnum_h, uint16_t, H1_2, float16_minnum)
DO_ZPZZ_FP(sve_fminnum_s, uint32_t, H1_4, float32_minnum)
DO_ZPZZ_FP(sve_fminnum_d, uint64_t,     , float64_minnum)

DO_ZPZZ_FP(sve_fmaxnum_h, uint16_t, H1_2, float16_maxnum)
DO_ZPZZ_FP(sve_fmaxnum_s, uint32_t, H1_4, float32_maxnum)
DO_ZPZZ_FP(sve_fmaxnum_d, uint64_t,     , float64_maxnum)

static inline float16 abd_h(float16 a, float16 b, float_status *s)
{
    return float16_abs(float16_sub(a, b, s));
}

static inline float32 abd_s(float32 a, float32 b, float_status *s)
{
    return float32_abs(float32_sub(a, b, s));
}

static inline float64 abd_d(float64 a, float64 b, float_status *s)
{
    return float64_abs(float64_sub(a, b, s));
}

DO_ZPZZ_FP(sve_fabd_h, uint16_t, H1_2, abd_h)
DO_ZPZZ_FP(sve_fabd_s, uint32_t, H1_4, abd_s)
DO_ZPZZ_FP(sve_fabd_d, uint64_t,     , abd_d)

static inline float64 scalbn_d(float64 a, int64_t b, float_status *s)
{
    int b_int = MIN(MAX(b, INT_MIN), INT_MAX);
    return float64_scalbn(a, b_int, s);
}

DO_ZPZZ_FP(sve_fscalbn_h, int16_t, H1_2, float16_scalbn)
DO_ZPZZ_FP(sve_fscalbn_s, int32_t, H1_4, float32_scalbn)
DO_ZPZZ_FP(sve_fscalbn_d, int64_t,     , scalbn_d)

DO_ZPZZ_FP(sve_fmulx_h, uint16_t, H1_2, helper_advsimd_mulxh)
DO_ZPZZ_FP(sve_fmulx_s, uint32_t, H1_4, helper_vfp_mulxs)
DO_ZPZZ_FP(sve_fmulx_d, uint64_t,     , helper_vfp_mulxd)

#undef DO_ZPZZ_FP

/* Three-operand expander, with one scalar operand, controlled by
 * a predicate, with the extra float_status parameter.
 */
#define DO_ZPZS_FP(NAME, TYPE, H, OP) \
void HELPER(NAME)(void *vd, void *vn, void *vg, uint64_t scalar,  \
                  void *status, uint32_t desc)                    \
{                                                                 \
    intptr_t i = simd_oprsz(desc);                                \
    uint64_t *g = vg;                                             \
    TYPE mm = scalar;                                             \
    do {                                                          \
        uint64_t pg = g[(i - 1) >> 6];                            \
        do {                                                      \
            i -= sizeof(TYPE);                                    \
            if (likely((pg >> (i & 63)) & 1)) {                   \
                TYPE nn = *(TYPE *)((char *)vn + H(i));                   \
                *(TYPE *)((char *)vd + H(i)) = OP(nn, mm, status);        \
            }                                                     \
        } while (i & 63);                                         \
    } while (i != 0);                                             \
}

DO_ZPZS_FP(sve_fadds_h, float16, H1_2, float16_add)
DO_ZPZS_FP(sve_fadds_s, float32, H1_4, float32_add)
DO_ZPZS_FP(sve_fadds_d, float64,     , float64_add)

DO_ZPZS_FP(sve_fsubs_h, float16, H1_2, float16_sub)
DO_ZPZS_FP(sve_fsubs_s, float32, H1_4, float32_sub)
DO_ZPZS_FP(sve_fsubs_d, float64,     , float64_sub)

DO_ZPZS_FP(sve_fmuls_h, float16, H1_2, float16_mul)
DO_ZPZS_FP(sve_fmuls_s, float32, H1_4, float32_mul)
DO_ZPZS_FP(sve_fmuls_d, float64,     , float64_mul)

static inline float16 subr_h(float16 a, float16 b, float_status *s)
{
    return float16_sub(b, a, s);
}

static inline float32 subr_s(float32 a, float32 b, float_status *s)
{
    return float32_sub(b, a, s);
}

static inline float64 subr_d(float64 a, float64 b, float_status *s)
{
    return float64_sub(b, a, s);
}

DO_ZPZS_FP(sve_fsubrs_h, float16, H1_2, subr_h)
DO_ZPZS_FP(sve_fsubrs_s, float32, H1_4, subr_s)
DO_ZPZS_FP(sve_fsubrs_d, float64,     , subr_d)

DO_ZPZS_FP(sve_fmaxnms_h, float16, H1_2, float16_maxnum)
DO_ZPZS_FP(sve_fmaxnms_s, float32, H1_4, float32_maxnum)
DO_ZPZS_FP(sve_fmaxnms_d, float64,     , float64_maxnum)

DO_ZPZS_FP(sve_fminnms_h, float16, H1_2, float16_minnum)
DO_ZPZS_FP(sve_fminnms_s, float32, H1_4, float32_minnum)
DO_ZPZS_FP(sve_fminnms_d, float64,     , float64_minnum)

DO_ZPZS_FP(sve_fmaxs_h, float16, H1_2, float16_max)
DO_ZPZS_FP(sve_fmaxs_s, float32, H1_4, float32_max)
DO_ZPZS_FP(sve_fmaxs_d, float64,     , float64_max)

DO_ZPZS_FP(sve_fmins_h, float16, H1_2, float16_min)
DO_ZPZS_FP(sve_fmins_s, float32, H1_4, float32_min)
DO_ZPZS_FP(sve_fmins_d, float64,     , float64_min)

/* Fully general two-operand expander, controlled by a predicate,
 * With the extra float_status parameter.
 */
#define DO_ZPZ_FP(NAME, TYPE, H, OP)                                  \
void HELPER(NAME)(void *vd, void *vn, void *vg, void *status, uint32_t desc) \
{                                                                     \
    intptr_t i = simd_oprsz(desc);                                    \
    uint64_t *g = vg;                                                 \
    do {                                                              \
        uint64_t pg = g[(i - 1) >> 6];                                \
        do {                                                          \
            i -= sizeof(TYPE);                                        \
            if (likely((pg >> (i & 63)) & 1)) {                       \
                TYPE nn = *(TYPE *)((char *)vn + H(i));                       \
                *(TYPE *)((char *)vd + H(i)) = OP(nn, status);                \
            }                                                         \
        } while (i & 63);                                             \
    } while (i != 0);                                                 \
}

/* SVE fp16 conversions always use IEEE mode.  Like AdvSIMD, they ignore
 * FZ16.  When converting from fp16, this affects flushing input denormals;
 * when converting to fp16, this affects flushing output denormals.
 */
static inline float32 sve_f16_to_f32(float16 f, float_status *fpst)
{
    flag save = get_flush_inputs_to_zero(fpst);
    float32 ret;

    set_flush_inputs_to_zero(false, fpst);
    ret = float16_to_float32(f, true, fpst);
    set_flush_inputs_to_zero(save, fpst);
    return ret;
}

static inline float64 sve_f16_to_f64(float16 f, float_status *fpst)
{
    flag save = get_flush_inputs_to_zero(fpst);
    float64 ret;

    set_flush_inputs_to_zero(false, fpst);
    ret = float16_to_float64(f, true, fpst);
    set_flush_inputs_to_zero(save, fpst);
    return ret;
}

static inline float16 sve_f32_to_f16(float32 f, float_status *fpst)
{
    flag save = get_flush_to_zero(fpst);
    float16 ret;

    set_flush_to_zero(false, fpst);
    ret = float32_to_float16(f, true, fpst);
    set_flush_to_zero(save, fpst);
    return ret;
}

static inline float16 sve_f64_to_f16(float64 f, float_status *fpst)
{
    flag save = get_flush_to_zero(fpst);
    float16 ret;

    set_flush_to_zero(false, fpst);
    ret = float64_to_float16(f, true, fpst);
    set_flush_to_zero(save, fpst);
    return ret;
}

static inline int16_t vfp_float16_to_int16_rtz(float16 f, float_status *s)
{
    if (float16_is_any_nan(f)) {
        float_raise(float_flag_invalid, s);
        return 0;
    }
    return float16_to_int16_round_to_zero(f, s);
}

static inline int64_t vfp_float16_to_int64_rtz(float16 f, float_status *s)
{
    if (float16_is_any_nan(f)) {
        float_raise(float_flag_invalid, s);
        return 0;
    }
    return float16_to_int64_round_to_zero(f, s);
}

static inline int64_t vfp_float32_to_int64_rtz(float32 f, float_status *s)
{
    if (float32_is_any_nan(f)) {
        float_raise(float_flag_invalid, s);
        return 0;
    }
    return float32_to_int64_round_to_zero(f, s);
}

static inline int64_t vfp_float64_to_int64_rtz(float64 f, float_status *s)
{
    if (float64_is_any_nan(f)) {
        float_raise(float_flag_invalid, s);
        return 0;
    }
    return float64_to_int64_round_to_zero(f, s);
}

static inline uint16_t vfp_float16_to_uint16_rtz(float16 f, float_status *s)
{
    if (float16_is_any_nan(f)) {
        float_raise(float_flag_invalid, s);
        return 0;
    }
    return float16_to_uint16_round_to_zero(f, s);
}

static inline uint64_t vfp_float16_to_uint64_rtz(float16 f, float_status *s)
{
    if (float16_is_any_nan(f)) {
        float_raise(float_flag_invalid, s);
        return 0;
    }
    return float16_to_uint64_round_to_zero(f, s);
}

static inline uint64_t vfp_float32_to_uint64_rtz(float32 f, float_status *s)
{
    if (float32_is_any_nan(f)) {
        float_raise(float_flag_invalid, s);
        return 0;
    }
    return float32_to_uint64_round_to_zero(f, s);
}

static inline uint64_t vfp_float64_to_uint64_rtz(float64 f, float_status *s)
{
    if (float64_is_any_nan(f)) {
        float_raise(float_flag_invalid, s);
        return 0;
    }
    return float64_to_uint64_round_to_zero(f, s);
}

DO_ZPZ_FP(sve_fcvt_sh, uint32_t, H1_4, sve_f32_to_f16)
DO_ZPZ_FP(sve_fcvt_hs, uint32_t, H1_4, sve_f16_to_f32)
DO_ZPZ_FP(sve_fcvt_dh, uint64_t,     , sve_f64_to_f16)
DO_ZPZ_FP(sve_fcvt_hd, uint64_t,     , sve_f16_to_f64)
DO_ZPZ_FP(sve_fcvt_ds, uint64_t,     , float64_to_float32)
DO_ZPZ_FP(sve_fcvt_sd, uint64_t,     , float32_to_float64)

DO_ZPZ_FP(sve_fcvtzs_hh, uint16_t, H1_2, vfp_float16_to_int16_rtz)
DO_ZPZ_FP(sve_fcvtzs_hs, uint32_t, H1_4, helper_vfp_tosizh)
DO_ZPZ_FP(sve_fcvtzs_ss, uint32_t, H1_4, helper_vfp_tosizs)
DO_ZPZ_FP(sve_fcvtzs_hd, uint64_t,     , vfp_float16_to_int64_rtz)
DO_ZPZ_FP(sve_fcvtzs_sd, uint64_t,     , vfp_float32_to_int64_rtz)
DO_ZPZ_FP(sve_fcvtzs_ds, uint64_t,     , helper_vfp_tosizd)
DO_ZPZ_FP(sve_fcvtzs_dd, uint64_t,     , vfp_float64_to_int64_rtz)

DO_ZPZ_FP(sve_fcvtzu_hh, uint16_t, H1_2, vfp_float16_to_uint16_rtz)
DO_ZPZ_FP(sve_fcvtzu_hs, uint32_t, H1_4, helper_vfp_touizh)
DO_ZPZ_FP(sve_fcvtzu_ss, uint32_t, H1_4, helper_vfp_touizs)
DO_ZPZ_FP(sve_fcvtzu_hd, uint64_t,     , vfp_float16_to_uint64_rtz)
DO_ZPZ_FP(sve_fcvtzu_sd, uint64_t,     , vfp_float32_to_uint64_rtz)
DO_ZPZ_FP(sve_fcvtzu_ds, uint64_t,     , helper_vfp_touizd)
DO_ZPZ_FP(sve_fcvtzu_dd, uint64_t,     , vfp_float64_to_uint64_rtz)

DO_ZPZ_FP(sve_frint_h, uint16_t, H1_2, helper_advsimd_rinth)
DO_ZPZ_FP(sve_frint_s, uint32_t, H1_4, helper_rints)
DO_ZPZ_FP(sve_frint_d, uint64_t,     , helper_rintd)

DO_ZPZ_FP(sve_frintx_h, uint16_t, H1_2, float16_round_to_int)
DO_ZPZ_FP(sve_frintx_s, uint32_t, H1_4, float32_round_to_int)
DO_ZPZ_FP(sve_frintx_d, uint64_t,     , float64_round_to_int)

DO_ZPZ_FP(sve_frecpx_h, uint16_t, H1_2, helper_frecpx_f16)
DO_ZPZ_FP(sve_frecpx_s, uint32_t, H1_4, helper_frecpx_f32)
DO_ZPZ_FP(sve_frecpx_d, uint64_t,     , helper_frecpx_f64)

DO_ZPZ_FP(sve_fsqrt_h, uint16_t, H1_2, float16_sqrt)
DO_ZPZ_FP(sve_fsqrt_s, uint32_t, H1_4, float32_sqrt)
DO_ZPZ_FP(sve_fsqrt_d, uint64_t,     , float64_sqrt)

DO_ZPZ_FP(sve_scvt_hh, uint16_t, H1_2, int16_to_float16)
DO_ZPZ_FP(sve_scvt_sh, uint32_t, H1_4, int32_to_float16)
DO_ZPZ_FP(sve_scvt_ss, uint32_t, H1_4, int32_to_float32)
DO_ZPZ_FP(sve_scvt_sd, uint64_t,     , int32_to_float64)
DO_ZPZ_FP(sve_scvt_dh, uint64_t,     , int64_to_float16)
DO_ZPZ_FP(sve_scvt_ds, uint64_t,     , int64_to_float32)
DO_ZPZ_FP(sve_scvt_dd, uint64_t,     , int64_to_float64)

DO_ZPZ_FP(sve_ucvt_hh, uint16_t, H1_2, uint16_to_float16)
DO_ZPZ_FP(sve_ucvt_sh, uint32_t, H1_4, uint32_to_float16)
DO_ZPZ_FP(sve_ucvt_ss, uint32_t, H1_4, uint32_to_float32)
DO_ZPZ_FP(sve_ucvt_sd, uint64_t,     , uint32_to_float64)
DO_ZPZ_FP(sve_ucvt_dh, uint64_t,     , uint64_to_float16)
DO_ZPZ_FP(sve_ucvt_ds, uint64_t,     , uint64_to_float32)
DO_ZPZ_FP(sve_ucvt_dd, uint64_t,     , uint64_to_float64)

#undef DO_ZPZ_FP

/* 4-operand predicated multiply-add.  This requires 7 operands to pass
 * "properly", so we need to encode some of the registers into DESC.
 */
QEMU_BUILD_BUG_ON(SIMD_DATA_SHIFT + 20 > 32);

static void do_fmla_zpzzz_h(CPUARMState *env, void *vg, uint32_t desc,
                            uint16_t neg1, uint16_t neg3)
{
    intptr_t i = simd_oprsz(desc);
    unsigned rd = extract32(desc, SIMD_DATA_SHIFT, 5);
    unsigned rn = extract32(desc, SIMD_DATA_SHIFT + 5, 5);
    unsigned rm = extract32(desc, SIMD_DATA_SHIFT + 10, 5);
    unsigned ra = extract32(desc, SIMD_DATA_SHIFT + 15, 5);
    void *vd = &env->vfp.zregs[rd];
    void *vn = &env->vfp.zregs[rn];
    void *vm = &env->vfp.zregs[rm];
    void *va = &env->vfp.zregs[ra];
    uint64_t *g = vg;

    do {
        uint64_t pg = g[(i - 1) >> 6];
        do {
            i -= 2;
            if (likely((pg >> (i & 63)) & 1)) {
                float16 e1, e2, e3, r;

                e1 = *(uint16_t *)((char *)vn + H1_2(i)) ^ neg1;
                e2 = *(uint16_t *)((char *)vm + H1_2(i));
                e3 = *(uint16_t *)((char *)va + H1_2(i)) ^ neg3;
                r = float16_muladd(e1, e2, e3, 0, &env->vfp.fp_status_f16);
                *(uint16_t *)((char *)vd + H1_2(i)) = r;
            }
        } while (i & 63);
    } while (i != 0);
}

void HELPER(sve_fmla_zpzzz_h)(CPUARMState *env, void *vg, uint32_t desc)
{
    do_fmla_zpzzz_h(env, vg, desc, 0, 0);
}

void HELPER(sve_fmls_zpzzz_h)(CPUARMState *env, void *vg, uint32_t desc)
{
    do_fmla_zpzzz_h(env, vg, desc, 0x8000, 0);
}

void HELPER(sve_fnmla_zpzzz_h)(CPUARMState *env, void *vg, uint32_t desc)
{
    do_fmla_zpzzz_h(env, vg, desc, 0x8000, 0x8000);
}

void HELPER(sve_fnmls_zpzzz_h)(CPUARMState *env, void *vg, uint32_t desc)
{
    do_fmla_zpzzz_h(env, vg, desc, 0, 0x8000);
}

static void do_fmla_zpzzz_s(CPUARMState *env, void *vg, uint32_t desc,
                            uint32_t neg1, uint32_t neg3)
{
    intptr_t i = simd_oprsz(desc);
    unsigned rd = extract32(desc, SIMD_DATA_SHIFT, 5);
    unsigned rn = extract32(desc, SIMD_DATA_SHIFT + 5, 5);
    unsigned rm = extract32(desc, SIMD_DATA_SHIFT + 10, 5);
    unsigned ra = extract32(desc, SIMD_DATA_SHIFT + 15, 5);
    void *vd = &env->vfp.zregs[rd];
    void *vn = &env->vfp.zregs[rn];
    void *vm = &env->vfp.zregs[rm];
    void *va = &env->vfp.zregs[ra];
    uint64_t *g = vg;

    do {
        uint64_t pg = g[(i - 1) >> 6];
        do {
            i -= 4;
            if (likely((pg >> (i & 63)) & 1)) {
                float32 e1, e2, e3, r;

                e1 = *(uint32_t *)((char *)vn + H1_4(i)) ^ neg1;
                e2 = *(uint32_t *)((char *)vm + H1_4(i));
                e3 = *(uint32_t *)((char *)va + H1_4(i)) ^ neg3;
                r = float32_muladd(e1, e2, e3, 0, &env->vfp.fp_status);
                *(uint32_t *)((char *)vd + H1_4(i)) = r;
            }
        } while (i & 63);
    } while (i != 0);
}

void HELPER(sve_fmla_zpzzz_s)(CPUARMState *env, void *vg, uint32_t desc)
{
    do_fmla_zpzzz_s(env, vg, desc, 0, 0);
}

void HELPER(sve_fmls_zpzzz_s)(CPUARMState *env, void *vg, uint32_t desc)
{
    do_fmla_zpzzz_s(env, vg, desc, 0x80000000, 0);
}

void HELPER(sve_fnmla_zpzzz_s)(CPUARMState *env, void *vg, uint32_t desc)
{
    do_fmla_zpzzz_s(env, vg, desc, 0x80000000, 0x80000000);
}

void HELPER(sve_fnmls_zpzzz_s)(CPUARMState *env, void *vg, uint32_t desc)
{
    do_fmla_zpzzz_s(env, vg, desc, 0, 0x80000000);
}

static void do_fmla_zpzzz_d(CPUARMState *env, void *vg, uint32_t desc,
                            uint64_t neg1, uint64_t neg3)
{
    intptr_t i = simd_oprsz(desc);
    unsigned rd = extract32(desc, SIMD_DATA_SHIFT, 5);
    unsigned rn = extract32(desc, SIMD_DATA_SHIFT + 5, 5);
    unsigned rm = extract32(desc, SIMD_DATA_SHIFT + 10, 5);
    unsigned ra = extract32(desc, SIMD_DATA_SHIFT + 15, 5);
    void *vd = &env->vfp.zregs[rd];
    void *vn = &env->vfp.zregs[rn];
    void *vm = &env->vfp.zregs[rm];
    void *va = &env->vfp.zregs[ra];
    uint64_t *g = vg;

    do {
        uint64_t pg = g[(i - 1) >> 6];
        do {
            i -= 8;
            if (likely((pg >> (i & 63)) & 1)) {
                float64 e1, e2, e3, r;

                e1 = *(uint64_t *)((char *)vn + i) ^ neg1;
                e2 = *(uint64_t *)((char *)vm + i);
                e3 = *(uint64_t *)((char *)va + i) ^ neg3;
                r = float64_muladd(e1, e2, e3, 0, &env->vfp.fp_status);
                *(uint64_t *)((char *)vd + i) = r;
            }
        } while (i & 63);
    } while (i != 0);
}

void HELPER(sve_fmla_zpzzz_d)(CPUARMState *env, void *vg, uint32_t desc)
{
    do_fmla_zpzzz_d(env, vg, desc, 0, 0);
}

void HELPER(sve_fmls_zpzzz_d)(CPUARMState *env, void *vg, uint32_t desc)
{
    do_fmla_zpzzz_d(env, vg, desc, INT64_MIN, 0);
}

void HELPER(sve_fnmla_zpzzz_d)(CPUARMState *env, void *vg, uint32_t desc)
{
    do_fmla_zpzzz_d(env, vg, desc, INT64_MIN, INT64_MIN);
}

void HELPER(sve_fnmls_zpzzz_d)(CPUARMState *env, void *vg, uint32_t desc)
{
    do_fmla_zpzzz_d(env, vg, desc, 0, INT64_MIN);
}

/* Two operand floating-point comparison controlled by a predicate.
 * Unlike the integer version, we are not allowed to optimistically
 * compare operands, since the comparison may have side effects wrt
 * the FPSR.
 */
#define DO_FPCMP_PPZZ(NAME, TYPE, H, OP)                                \
void HELPER(NAME)(void *vd, void *vn, void *vm, void *vg,               \
                  void *status, uint32_t desc)                          \
{                                                                       \
    intptr_t i = simd_oprsz(desc), j = (i - 1) >> 6;                    \
    uint64_t *d = vd, *g = vg;                                          \
    do {                                                                \
        uint64_t out = 0, pg = g[j];                                    \
        do {                                                            \
            i -= sizeof(TYPE), out <<= sizeof(TYPE);                    \
            if (likely((pg >> (i & 63)) & 1)) {                         \
                TYPE nn = *(TYPE *)((char *)vn + H(i));                         \
                TYPE mm = *(TYPE *)((char *)vm + H(i));                         \
                out |= OP(TYPE, nn, mm, status);                        \
            }                                                           \
        } while (i & 63);                                               \
        d[j--] = out;                                                   \
    } while (i > 0);                                                    \
}

#define DO_FPCMP_PPZZ_H(NAME, OP) \
    DO_FPCMP_PPZZ(NAME##_h, float16, H1_2, OP)
#define DO_FPCMP_PPZZ_S(NAME, OP) \
    DO_FPCMP_PPZZ(NAME##_s, float32, H1_4, OP)
#define DO_FPCMP_PPZZ_D(NAME, OP) \
    DO_FPCMP_PPZZ(NAME##_d, float64,     , OP)

#define DO_FPCMP_PPZZ_ALL(NAME, OP) \
    DO_FPCMP_PPZZ_H(NAME, OP)   \
    DO_FPCMP_PPZZ_S(NAME, OP)   \
    DO_FPCMP_PPZZ_D(NAME, OP)

#define DO_FCMGE(TYPE, X, Y, ST)  TYPE##_compare(Y, X, ST) <= 0
#define DO_FCMGT(TYPE, X, Y, ST)  TYPE##_compare(Y, X, ST) < 0
#define DO_FCMLE(TYPE, X, Y, ST)  TYPE##_compare(X, Y, ST) <= 0
#define DO_FCMLT(TYPE, X, Y, ST)  TYPE##_compare(X, Y, ST) < 0
#define DO_FCMEQ(TYPE, X, Y, ST)  TYPE##_compare_quiet(X, Y, ST) == 0
#define DO_FCMNE(TYPE, X, Y, ST)  TYPE##_compare_quiet(X, Y, ST) != 0
#define DO_FCMUO(TYPE, X, Y, ST)  \
    TYPE##_compare_quiet(X, Y, ST) == float_relation_unordered
#define DO_FACGE(TYPE, X, Y, ST)  \
    TYPE##_compare(TYPE##_abs(Y), TYPE##_abs(X), ST) <= 0
#define DO_FACGT(TYPE, X, Y, ST)  \
    TYPE##_compare(TYPE##_abs(Y), TYPE##_abs(X), ST) < 0

DO_FPCMP_PPZZ_ALL(sve_fcmge, DO_FCMGE)
DO_FPCMP_PPZZ_ALL(sve_fcmgt, DO_FCMGT)
DO_FPCMP_PPZZ_ALL(sve_fcmeq, DO_FCMEQ)
DO_FPCMP_PPZZ_ALL(sve_fcmne, DO_FCMNE)
DO_FPCMP_PPZZ_ALL(sve_fcmuo, DO_FCMUO)
DO_FPCMP_PPZZ_ALL(sve_facge, DO_FACGE)
DO_FPCMP_PPZZ_ALL(sve_facgt, DO_FACGT)

#undef DO_FPCMP_PPZZ_ALL
#undef DO_FPCMP_PPZZ_D
#undef DO_FPCMP_PPZZ_S
#undef DO_FPCMP_PPZZ_H
#undef DO_FPCMP_PPZZ

/* One operand floating-point comparison against zero, controlled
 * by a predicate.
 */
#define DO_FPCMP_PPZ0(NAME, TYPE, H, OP)                   \
void HELPER(NAME)(void *vd, void *vn, void *vg,            \
                  void *status, uint32_t desc)             \
{                                                          \
    intptr_t i = simd_oprsz(desc), j = (i - 1) >> 6;       \
    uint64_t *d = vd, *g = vg;                             \
    do {                                                   \
        uint64_t out = 0, pg = g[j];                       \
        do {                                               \
            i -= sizeof(TYPE), out <<= sizeof(TYPE);       \
            if ((pg >> (i & 63)) & 1) {                    \
                TYPE nn = *(TYPE *)((char *)vn + H(i));            \
                out |= OP(TYPE, nn, 0, status);            \
            }                                              \
        } while (i & 63);                                  \
        d[j--] = out;                                      \
    } while (i > 0);                                       \
}

#define DO_FPCMP_PPZ0_H(NAME, OP) \
    DO_FPCMP_PPZ0(NAME##_h, float16, H1_2, OP)
#define DO_FPCMP_PPZ0_S(NAME, OP) \
    DO_FPCMP_PPZ0(NAME##_s, float32, H1_4, OP)
#define DO_FPCMP_PPZ0_D(NAME, OP) \
    DO_FPCMP_PPZ0(NAME##_d, float64,     , OP)

#define DO_FPCMP_PPZ0_ALL(NAME, OP) \
    DO_FPCMP_PPZ0_H(NAME, OP)   \
    DO_FPCMP_PPZ0_S(NAME, OP)   \
    DO_FPCMP_PPZ0_D(NAME, OP)

DO_FPCMP_PPZ0_ALL(sve_fcmge0, DO_FCMGE)
DO_FPCMP_PPZ0_ALL(sve_fcmgt0, DO_FCMGT)
DO_FPCMP_PPZ0_ALL(sve_fcmle0, DO_FCMLE)
DO_FPCMP_PPZ0_ALL(sve_fcmlt0, DO_FCMLT)
DO_FPCMP_PPZ0_ALL(sve_fcmeq0, DO_FCMEQ)
DO_FPCMP_PPZ0_ALL(sve_fcmne0, DO_FCMNE)

/* FP Trig Multiply-Add. */

void HELPER(sve_ftmad_h)(void *vd, void *vn, void *vm, void *vs, uint32_t desc)
{
    static const float16 coeff[16] = {
        0x3c00, 0xb155, 0x2030, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000,
        0x3c00, 0xb800, 0x293a, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000,
    };
    intptr_t i, opr_sz = simd_oprsz(desc) / sizeof(float16);
    intptr_t x = simd_data(desc);
    float16 *d = vd, *n = vn, *m = vm;
    for (i = 0; i < opr_sz; i++) {
        float16 mm = m[i];
        intptr_t xx = x;
        if (float16_is_neg(mm)) {
            mm = float16_abs(mm);
            xx += 8;
        }
        d[i] = float16_muladd(n[i], mm, coeff[xx], 0, vs);
    }
}

void HELPER(sve_ftmad_s)(void *vd, void *vn, void *vm, void *vs, uint32_t desc)
{
    static const float32 coeff[16] = {
        0x3f800000, 0xbe2aaaab, 0x3c088886, 0xb95008b9,
        0x36369d6d, 0x00000000, 0x00000000, 0x00000000,
        0x3f800000, 0xbf000000, 0x3d2aaaa6, 0xbab60705,
        0x37cd37cc, 0x00000000, 0x00000000, 0x00000000,
    };
    intptr_t i, opr_sz = simd_oprsz(desc) / sizeof(float32);
    intptr_t x = simd_data(desc);
    float32 *d = vd, *n = vn, *m = vm;
    for (i = 0; i < opr_sz; i++) {
        float32 mm = m[i];
        intptr_t xx = x;
        if (float32_is_neg(mm)) {
            mm = float32_abs(mm);
            xx += 8;
        }
        d[i] = float32_muladd(n[i], mm, coeff[xx], 0, vs);
    }
}

void HELPER(sve_ftmad_d)(void *vd, void *vn, void *vm, void *vs, uint32_t desc)
{
    static const float64 coeff[16] = {
        0x3ff0000000000000ull, 0xbfc5555555555543ull,
        0x3f8111111110f30cull, 0xbf2a01a019b92fc6ull,
        0x3ec71de351f3d22bull, 0xbe5ae5e2b60f7b91ull,
        0x3de5d8408868552full, 0x0000000000000000ull,
        0x3ff0000000000000ull, 0xbfe0000000000000ull,
        0x3fa5555555555536ull, 0xbf56c16c16c13a0bull,
        0x3efa01a019b1e8d8ull, 0xbe927e4f7282f468ull,
        0x3e21ee96d2641b13ull, 0xbda8f76380fbb401ull,
    };
    intptr_t i, opr_sz = simd_oprsz(desc) / sizeof(float64);
    intptr_t x = simd_data(desc);
    float64 *d = vd, *n = vn, *m = vm;
    for (i = 0; i < opr_sz; i++) {
        float64 mm = m[i];
        intptr_t xx = x;
        if (float64_is_neg(mm)) {
            mm = float64_abs(mm);
            xx += 8;
        }
        d[i] = float64_muladd(n[i], mm, coeff[xx], 0, vs);
    }
}

/*
 * FP Complex Add
 */

void HELPER(sve_fcadd_h)(void *vd, void *vn, void *vm, void *vg,
                         void *vs, uint32_t desc)
{
    intptr_t j, i = simd_oprsz(desc);
    uint64_t *g = vg;
    float16 neg_imag = float16_set_sign(0, simd_data(desc));
    float16 neg_real = float16_chs(neg_imag);

    do {
        uint64_t pg = g[(i - 1) >> 6];
        do {
            float16 e0, e1, e2, e3;

            /* I holds the real index; J holds the imag index.  */
            j = i - sizeof(float16);
            i -= 2 * sizeof(float16);

            e0 = *(float16 *)((char *)vn + H1_2(i));
            e1 = *(float16 *)((char *)vm + H1_2(j)) ^ neg_real;
            e2 = *(float16 *)((char *)vn + H1_2(j));
            e3 = *(float16 *)((char *)vm + H1_2(i)) ^ neg_imag;

            if (likely((pg >> (i & 63)) & 1)) {
                *(float16 *)((char *)vd + H1_2(i)) = float16_add(e0, e1, vs);
            }
            if (likely((pg >> (j & 63)) & 1)) {
                *(float16 *)((char *)vd + H1_2(j)) = float16_add(e2, e3, vs);
            }
        } while (i & 63);
    } while (i != 0);
}

void HELPER(sve_fcadd_s)(void *vd, void *vn, void *vm, void *vg,
                         void *vs, uint32_t desc)
{
    intptr_t j, i = simd_oprsz(desc);
    uint64_t *g = vg;
    float32 neg_imag = float32_set_sign(0, simd_data(desc));
    float32 neg_real = float32_chs(neg_imag);

    do {
        uint64_t pg = g[(i - 1) >> 6];
        do {
            float32 e0, e1, e2, e3;

            /* I holds the real index; J holds the imag index.  */
            j = i - sizeof(float32);
            i -= 2 * sizeof(float32);

            e0 = *(float32 *)((char *)vn + H1_2(i));
            e1 = *(float32 *)((char *)vm + H1_2(j)) ^ neg_real;
            e2 = *(float32 *)((char *)vn + H1_2(j));
            e3 = *(float32 *)((char *)vm + H1_2(i)) ^ neg_imag;

            if (likely((pg >> (i & 63)) & 1)) {
                *(float32 *)((char *)vd + H1_2(i)) = float32_add(e0, e1, vs);
            }
            if (likely((pg >> (j & 63)) & 1)) {
                *(float32 *)((char *)vd + H1_2(j)) = float32_add(e2, e3, vs);
            }
        } while (i & 63);
    } while (i != 0);
}

void HELPER(sve_fcadd_d)(void *vd, void *vn, void *vm, void *vg,
                         void *vs, uint32_t desc)
{
    intptr_t j, i = simd_oprsz(desc);
    uint64_t *g = vg;
    float64 neg_imag = float64_set_sign(0, simd_data(desc));
    float64 neg_real = float64_chs(neg_imag);

    do {
        uint64_t pg = g[(i - 1) >> 6];
        do {
            float64 e0, e1, e2, e3;

            /* I holds the real index; J holds the imag index.  */
            j = i - sizeof(float64);
            i -= 2 * sizeof(float64);

            e0 = *(float64 *)((char *)vn + H1_2(i));
            e1 = *(float64 *)((char *)vm + H1_2(j)) ^ neg_real;
            e2 = *(float64 *)((char *)vn + H1_2(j));
            e3 = *(float64 *)((char *)vm + H1_2(i)) ^ neg_imag;

            if (likely((pg >> (i & 63)) & 1)) {
                *(float64 *)((char *)vd + H1_2(i)) = float64_add(e0, e1, vs);
            }
            if (likely((pg >> (j & 63)) & 1)) {
                *(float64 *)((char *)vd + H1_2(j)) = float64_add(e2, e3, vs);
            }
        } while (i & 63);
    } while (i != 0);
}

/*
 * FP Complex Multiply
 */

QEMU_BUILD_BUG_ON(SIMD_DATA_SHIFT + 22 > 32);

void HELPER(sve_fcmla_zpzzz_h)(CPUARMState *env, void *vg, uint32_t desc)
{
    intptr_t j, i = simd_oprsz(desc);
    unsigned rd = extract32(desc, SIMD_DATA_SHIFT, 5);
    unsigned rn = extract32(desc, SIMD_DATA_SHIFT + 5, 5);
    unsigned rm = extract32(desc, SIMD_DATA_SHIFT + 10, 5);
    unsigned ra = extract32(desc, SIMD_DATA_SHIFT + 15, 5);
    unsigned rot = extract32(desc, SIMD_DATA_SHIFT + 20, 2);
    bool flip = rot & 1;
    float16 neg_imag, neg_real;
    void *vd = &env->vfp.zregs[rd];
    void *vn = &env->vfp.zregs[rn];
    void *vm = &env->vfp.zregs[rm];
    void *va = &env->vfp.zregs[ra];
    uint64_t *g = vg;

    neg_imag = float16_set_sign(0, (rot & 2) != 0);
    neg_real = float16_set_sign(0, rot == 1 || rot == 2);

    do {
        uint64_t pg = g[(i - 1) >> 6];
        do {
            float16 e1, e2, e3, e4, nr, ni, mr, mi, d;

            /* I holds the real index; J holds the imag index.  */
            j = i - sizeof(float16);
            i -= 2 * sizeof(float16);

            nr = *(float16 *)((char *)vn + H1_2(i));
            ni = *(float16 *)((char *)vn + H1_2(j));
            mr = *(float16 *)((char *)vm + H1_2(i));
            mi = *(float16 *)((char *)vm + H1_2(j));

            e2 = (flip ? ni : nr);
            e1 = (flip ? mi : mr) ^ neg_real;
            e4 = e2;
            e3 = (flip ? mr : mi) ^ neg_imag;

            if (likely((pg >> (i & 63)) & 1)) {
                d = *(float16 *)((char *)va + H1_2(i));
                d = float16_muladd(e2, e1, d, 0, &env->vfp.fp_status_f16);
                *(float16 *)((char *)vd + H1_2(i)) = d;
            }
            if (likely((pg >> (j & 63)) & 1)) {
                d = *(float16 *)((char *)va + H1_2(j));
                d = float16_muladd(e4, e3, d, 0, &env->vfp.fp_status_f16);
                *(float16 *)((char *)vd + H1_2(j)) = d;
            }
        } while (i & 63);
    } while (i != 0);
}

void HELPER(sve_fcmla_zpzzz_s)(CPUARMState *env, void *vg, uint32_t desc)
{
    intptr_t j, i = simd_oprsz(desc);
    unsigned rd = extract32(desc, SIMD_DATA_SHIFT, 5);
    unsigned rn = extract32(desc, SIMD_DATA_SHIFT + 5, 5);
    unsigned rm = extract32(desc, SIMD_DATA_SHIFT + 10, 5);
    unsigned ra = extract32(desc, SIMD_DATA_SHIFT + 15, 5);
    unsigned rot = extract32(desc, SIMD_DATA_SHIFT + 20, 2);
    bool flip = rot & 1;
    float32 neg_imag, neg_real;
    void *vd = &env->vfp.zregs[rd];
    void *vn = &env->vfp.zregs[rn];
    void *vm = &env->vfp.zregs[rm];
    void *va = &env->vfp.zregs[ra];
    uint64_t *g = vg;

    neg_imag = float32_set_sign(0, (rot & 2) != 0);
    neg_real = float32_set_sign(0, rot == 1 || rot == 2);

    do {
        uint64_t pg = g[(i - 1) >> 6];
        do {
            float32 e1, e2, e3, e4, nr, ni, mr, mi, d;

            /* I holds the real index; J holds the imag index.  */
            j = i - sizeof(float32);
            i -= 2 * sizeof(float32);

            nr = *(float32 *)((char *)vn + H1_2(i));
            ni = *(float32 *)((char *)vn + H1_2(j));
            mr = *(float32 *)((char *)vm + H1_2(i));
            mi = *(float32 *)((char *)vm + H1_2(j));

            e2 = (flip ? ni : nr);
            e1 = (flip ? mi : mr) ^ neg_real;
            e4 = e2;
            e3 = (flip ? mr : mi) ^ neg_imag;

            if (likely((pg >> (i & 63)) & 1)) {
                d = *(float32 *)((char *)va + H1_2(i));
                d = float32_muladd(e2, e1, d, 0, &env->vfp.fp_status);
                *(float32 *)((char *)vd + H1_2(i)) = d;
            }
            if (likely((pg >> (j & 63)) & 1)) {
                d = *(float32 *)((char *)va + H1_2(j));
                d = float32_muladd(e4, e3, d, 0, &env->vfp.fp_status);
                *(float32 *)((char *)vd + H1_2(j)) = d;
            }
        } while (i & 63);
    } while (i != 0);
}

void HELPER(sve_fcmla_zpzzz_d)(CPUARMState *env, void *vg, uint32_t desc)
{
    intptr_t j, i = simd_oprsz(desc);
    unsigned rd = extract32(desc, SIMD_DATA_SHIFT, 5);
    unsigned rn = extract32(desc, SIMD_DATA_SHIFT + 5, 5);
    unsigned rm = extract32(desc, SIMD_DATA_SHIFT + 10, 5);
    unsigned ra = extract32(desc, SIMD_DATA_SHIFT + 15, 5);
    unsigned rot = extract32(desc, SIMD_DATA_SHIFT + 20, 2);
    bool flip = rot & 1;
    float64 neg_imag, neg_real;
    void *vd = &env->vfp.zregs[rd];
    void *vn = &env->vfp.zregs[rn];
    void *vm = &env->vfp.zregs[rm];
    void *va = &env->vfp.zregs[ra];
    uint64_t *g = vg;

    neg_imag = float64_set_sign(0, (rot & 2) != 0);
    neg_real = float64_set_sign(0, rot == 1 || rot == 2);

    do {
        uint64_t pg = g[(i - 1) >> 6];
        do {
            float64 e1, e2, e3, e4, nr, ni, mr, mi, d;

            /* I holds the real index; J holds the imag index.  */
            j = i - sizeof(float64);
            i -= 2 * sizeof(float64);

            nr = *(float64 *)((char *)vn + H1_2(i));
            ni = *(float64 *)((char *)vn + H1_2(j));
            mr = *(float64 *)((char *)vm + H1_2(i));
            mi = *(float64 *)((char *)vm + H1_2(j));

            e2 = (flip ? ni : nr);
            e1 = (flip ? mi : mr) ^ neg_real;
            e4 = e2;
            e3 = (flip ? mr : mi) ^ neg_imag;

            if (likely((pg >> (i & 63)) & 1)) {
                d = *(float64 *)((char *)va + H1_2(i));
                d = float64_muladd(e2, e1, d, 0, &env->vfp.fp_status);
                *(float64 *)((char *)vd + H1_2(i)) = d;
            }
            if (likely((pg >> (j & 63)) & 1)) {
                d = *(float64 *)((char *)va + H1_2(j));
                d = float64_muladd(e4, e3, d, 0, &env->vfp.fp_status);
                *(float64 *)((char *)vd + H1_2(j)) = d;
            }
        } while (i & 63);
    } while (i != 0);
}

/*
 * Load contiguous data, protected by a governing predicate.
 */

/*
 * Load elements into @vd, controlled by @vg, from @host + @mem_ofs.
 * Memory is valid through @host + @mem_max.  The register element
 * indicies are inferred from @mem_ofs, as modified by the types for
 * which the helper is built.  Return the @mem_ofs of the first element
 * not loaded (which is @mem_max if they are all loaded).
 *
 * For softmmu, we have fully validated the guest page.  For user-only,
 * we cannot fully validate without taking the mmap lock, but since we
 * know the access is within one host page, if any access is valid they
 * all must be valid.  However, when @vg is all false, it may be that
 * no access is valid.
 */
typedef intptr_t sve_ld1_host_fn(void *vd, void *vg, void *host,
                                 intptr_t mem_ofs, intptr_t mem_max);

/*
 * Load one element into @vd + @reg_off from (@env, @vaddr, @ra).
 * The controlling predicate is known to be true.
 */
typedef void sve_ld1_tlb_fn(CPUARMState *env, void *vd, intptr_t reg_off,
                            target_ulong vaddr, TCGMemOpIdx oi, uintptr_t ra);
typedef sve_ld1_tlb_fn sve_st1_tlb_fn;

/*
 * Generate the above primitives.
 */

#define DO_LD_HOST(NAME, H, TYPEE, TYPEM, HOST) \
static intptr_t sve_##NAME##_host(void *vd, void *vg, void *host,           \
                                  intptr_t mem_off, const intptr_t mem_max) \
{                                                                           \
    intptr_t reg_off = mem_off * (sizeof(TYPEE) / sizeof(TYPEM));           \
    uint64_t *pg = vg;                                                      \
    while (mem_off + sizeof(TYPEM) <= mem_max) {                            \
        TYPEM val = 0;                                                      \
        if (likely((pg[reg_off >> 6] >> (reg_off & 63)) & 1)) {             \
            val = HOST((char *)host + mem_off);                                     \
        }                                                                   \
        *(TYPEE *)((char *)vd + H(reg_off)) = val;                                  \
        mem_off += sizeof(TYPEM), reg_off += sizeof(TYPEE);                 \
    }                                                                       \
    return mem_off;                                                         \
}

#define DO_LD_TLB(NAME, H, TYPEE, TYPEM, HOST, MOEND, TLB) \
static void sve_##NAME##_tlb(CPUARMState *env, void *vd, intptr_t reg_off,  \
                             target_ulong addr, TCGMemOpIdx oi, uintptr_t ra)  \
{                                                                           \
    TYPEM val = TLB(env, addr, oi, ra);                                     \
    *(TYPEE *)((char *)vd + H(reg_off)) = val;                                      \
}

#define DO_LD_PRIM_1(NAME, H, TE, TM)                   \
    DO_LD_HOST(NAME, H, TE, TM, ldub_p)                 \
    DO_LD_TLB(NAME, H, TE, TM, ldub_p, 0, helper_ret_ldub_mmu)

DO_LD_PRIM_1(ld1bb,  H1,   uint8_t,  uint8_t)
DO_LD_PRIM_1(ld1bhu, H1_2, uint16_t, uint8_t)
DO_LD_PRIM_1(ld1bhs, H1_2, uint16_t,  int8_t)
DO_LD_PRIM_1(ld1bsu, H1_4, uint32_t, uint8_t)
DO_LD_PRIM_1(ld1bss, H1_4, uint32_t,  int8_t)
DO_LD_PRIM_1(ld1bdu,     , uint64_t, uint8_t)
DO_LD_PRIM_1(ld1bds,     , uint64_t,  int8_t)

#define DO_LD_PRIM_2(NAME, end, MOEND, H, TE, TM, PH, PT)  \
    DO_LD_HOST(NAME##_##end, H, TE, TM, PH##_##end##_p)    \
    DO_LD_TLB(NAME##_##end, H, TE, TM, PH##_##end##_p,     \
              MOEND, helper_##end##_##PT##_mmu)

DO_LD_PRIM_2(ld1hh,  le, MO_LE, H1_2, uint16_t, uint16_t, lduw, lduw)
DO_LD_PRIM_2(ld1hsu, le, MO_LE, H1_4, uint32_t, uint16_t, lduw, lduw)
DO_LD_PRIM_2(ld1hss, le, MO_LE, H1_4, uint32_t,  int16_t, lduw, lduw)
DO_LD_PRIM_2(ld1hdu, le, MO_LE,     , uint64_t, uint16_t, lduw, lduw)
DO_LD_PRIM_2(ld1hds, le, MO_LE,     , uint64_t,  int16_t, lduw, lduw)

DO_LD_PRIM_2(ld1ss,  le, MO_LE, H1_4, uint32_t, uint32_t, ldl, ldul)
DO_LD_PRIM_2(ld1sdu, le, MO_LE,     , uint64_t, uint32_t, ldl, ldul)
DO_LD_PRIM_2(ld1sds, le, MO_LE,     , uint64_t,  int32_t, ldl, ldul)

DO_LD_PRIM_2(ld1dd,  le, MO_LE,     , uint64_t, uint64_t, ldq, ldq)

DO_LD_PRIM_2(ld1hh,  be, MO_BE, H1_2, uint16_t, uint16_t, lduw, lduw)
DO_LD_PRIM_2(ld1hsu, be, MO_BE, H1_4, uint32_t, uint16_t, lduw, lduw)
DO_LD_PRIM_2(ld1hss, be, MO_BE, H1_4, uint32_t,  int16_t, lduw, lduw)
DO_LD_PRIM_2(ld1hdu, be, MO_BE,     , uint64_t, uint16_t, lduw, lduw)
DO_LD_PRIM_2(ld1hds, be, MO_BE,     , uint64_t,  int16_t, lduw, lduw)

DO_LD_PRIM_2(ld1ss,  be, MO_BE, H1_4, uint32_t, uint32_t, ldl, ldul)
DO_LD_PRIM_2(ld1sdu, be, MO_BE,     , uint64_t, uint32_t, ldl, ldul)
DO_LD_PRIM_2(ld1sds, be, MO_BE,     , uint64_t,  int32_t, ldl, ldul)

DO_LD_PRIM_2(ld1dd,  be, MO_BE,     , uint64_t, uint64_t, ldq, ldq)

#undef DO_LD_TLB
#undef DO_LD_HOST
#undef DO_LD_PRIM_1
#undef DO_LD_PRIM_2

/*
 * Skip through a sequence of inactive elements in the guarding predicate @vg,
 * beginning at @reg_off bounded by @reg_max.  Return the offset of the active
 * element >= @reg_off, or @reg_max if there were no active elements at all.
 */
static intptr_t find_next_active(uint64_t *vg, intptr_t reg_off,
                                 intptr_t reg_max, int esz)
{
    uint64_t pg_mask = pred_esz_masks[esz];
    uint64_t pg = (vg[reg_off >> 6] & pg_mask) >> (reg_off & 63);

    /* In normal usage, the first element is active.  */
    if (likely(pg & 1)) {
        return reg_off;
    }

    if (pg == 0) {
        reg_off &= -64;
        do {
            reg_off += 64;
            if (unlikely(reg_off >= reg_max)) {
                /* The entire predicate was false.  */
                return reg_max;
            }
            pg = vg[reg_off >> 6] & pg_mask;
        } while (pg == 0);
    }
    reg_off += ctz64(pg);

    /* We should never see an out of range predicate bit set.  */
    tcg_debug_assert(reg_off < reg_max);
    return reg_off;
}

/*
 * Return the maximum offset <= @mem_max which is still within the page
 * referenced by @base + @mem_off.
 */
static intptr_t max_for_page(struct uc_struct *uc, target_ulong base, intptr_t mem_off,
                             intptr_t mem_max)
{
    target_ulong addr = base + mem_off;
    intptr_t split = -(intptr_t)(addr | TARGET_PAGE_MASK);
    return MIN(split, mem_max - mem_off) + mem_off;
}

/* These are normally defined only for CONFIG_USER_ONLY in <exec/cpu_ldst.h> */
static inline void set_helper_retaddr(uintptr_t ra) { }
static inline void clear_helper_retaddr(void) { }

/*
 * The result of tlb_vaddr_to_host for user-only is just g2h(x),
 * which is always non-null.  Elide the useless test.
 */
static inline bool test_host_page(void *host)
{
    return likely(host != NULL);
}

/*
 * Common helper for all contiguous one-register predicated loads.
 */
static void sve_ld1_r(CPUARMState *env, void *vg, const target_ulong addr,
                      uint32_t desc, const uintptr_t retaddr,
                      const int esz, const int msz,
                      sve_ld1_host_fn *host_fn,
                      sve_ld1_tlb_fn *tlb_fn)
{
    const TCGMemOpIdx oi = extract32(desc, SIMD_DATA_SHIFT, MEMOPIDX_SHIFT);
    const int mmu_idx = get_mmuidx(oi);
    const unsigned rd = extract32(desc, SIMD_DATA_SHIFT + MEMOPIDX_SHIFT, 5);
    void *vd = &env->vfp.zregs[rd];
    const int diffsz = esz - msz;
    const intptr_t reg_max = simd_oprsz(desc);
    const intptr_t mem_max = reg_max >> diffsz;
    ARMVectorReg scratch;
    void *host;
    intptr_t split, reg_off, mem_off;

    /* Find the first active element.  */
    reg_off = find_next_active(vg, 0, reg_max, esz);
    if (unlikely(reg_off == reg_max)) {
        /* The entire predicate was false; no load occurs.  */
        memset(vd, 0, reg_max);
        return;
    }
    mem_off = reg_off >> diffsz;
    set_helper_retaddr(retaddr);

    /*
     * If the (remaining) load is entirely within a single page, then:
     * For softmmu, and the tlb hits, then no faults will occur;
     * For user-only, either the first load will fault or none will.
     * We can thus perform the load directly to the destination and
     * Vd will be unmodified on any exception path.
     */
    split = max_for_page(env->uc, addr, mem_off, mem_max);
    if (likely(split == mem_max)) {
        host = tlb_vaddr_to_host(env, addr + mem_off, MMU_DATA_LOAD, mmu_idx);
        if (test_host_page(host)) {
            mem_off = host_fn(vd, vg, (char *)host - mem_off, mem_off, mem_max);
            tcg_debug_assert(mem_off == mem_max);
            clear_helper_retaddr();
            /* After having taken any fault, zero leading inactive elements. */
            swap_memzero(vd, reg_off);
            return;
        }
    }

    /*
     * Perform the predicated read into a temporary, thus ensuring
     * if the load of the last element faults, Vd is not modified.
     */
    memset(&scratch, 0, reg_max);
    goto start;
    while (1) {
        reg_off = find_next_active(vg, reg_off, reg_max, esz);
        if (reg_off >= reg_max) {
            break;
        }
        mem_off = reg_off >> diffsz;
        split = max_for_page(env->uc, addr, mem_off, mem_max);

    start:
        if (split - mem_off >= (1ULL << msz)) {
            /* At least one whole element on this page.  */
            host = tlb_vaddr_to_host(env, addr + mem_off,
                                     MMU_DATA_LOAD, mmu_idx);
            if (host) {
                mem_off = host_fn(&scratch, vg, (char *)host - mem_off,
                                  mem_off, split);
                reg_off = mem_off << diffsz;
                continue;
            }
        }

        /*
         * Perform one normal read.  This may fault, longjmping out to the
         * main loop in order to raise an exception.  It may succeed, and
         * as a side-effect load the TLB entry for the next round.  Finally,
         * in the extremely unlikely case we're performing this operation
         * on I/O memory, it may succeed but not bring in the TLB entry.
         * But even then we have still made forward progress.
         */
        tlb_fn(env, &scratch, reg_off, addr + mem_off, oi, retaddr);
        reg_off += 1ULL << esz;
    }

    clear_helper_retaddr();
    memcpy(vd, &scratch, reg_max);
}

#define DO_LD1_1(NAME, ESZ) \
void HELPER(sve_##NAME##_r)(CPUARMState *env, void *vg,        \
                            target_ulong addr, uint32_t desc)  \
{                                                              \
    sve_ld1_r(env, vg, addr, desc, GETPC(), ESZ, 0,            \
              sve_##NAME##_host, sve_##NAME##_tlb);            \
}

#define DO_LD1_2(NAME, ESZ, MSZ) \
void HELPER(sve_##NAME##_le_r)(CPUARMState *env, void *vg,        \
                               target_ulong addr, uint32_t desc)  \
{                                                                 \
    sve_ld1_r(env, vg, addr, desc, GETPC(), ESZ, MSZ,             \
              sve_##NAME##_le_host, sve_##NAME##_le_tlb);         \
}                                                                 \
void HELPER(sve_##NAME##_be_r)(CPUARMState *env, void *vg,        \
                               target_ulong addr, uint32_t desc)  \
{                                                                 \
    sve_ld1_r(env, vg, addr, desc, GETPC(), ESZ, MSZ,             \
              sve_##NAME##_be_host, sve_##NAME##_be_tlb);         \
}

DO_LD1_1(ld1bb,  0)
DO_LD1_1(ld1bhu, 1)
DO_LD1_1(ld1bhs, 1)
DO_LD1_1(ld1bsu, 2)
DO_LD1_1(ld1bss, 2)
DO_LD1_1(ld1bdu, 3)
DO_LD1_1(ld1bds, 3)

DO_LD1_2(ld1hh,  1, 1)
DO_LD1_2(ld1hsu, 2, 1)
DO_LD1_2(ld1hss, 2, 1)
DO_LD1_2(ld1hdu, 3, 1)
DO_LD1_2(ld1hds, 3, 1)

DO_LD1_2(ld1ss,  2, 2)
DO_LD1_2(ld1sdu, 3, 2)
DO_LD1_2(ld1sds, 3, 2)

DO_LD1_2(ld1dd,  3, 3)

#undef DO_LD1_1
#undef DO_LD1_2

/*
 * Common helpers for all contiguous 2,3,4-register predicated loads.
 */
static void sve_ld2_r(CPUARMState *env, void *vg, target_ulong addr,
                      uint32_t desc, int size, uintptr_t ra,
                      sve_ld1_tlb_fn *tlb_fn)
{
    const TCGMemOpIdx oi = extract32(desc, SIMD_DATA_SHIFT, MEMOPIDX_SHIFT);
    const unsigned rd = extract32(desc, SIMD_DATA_SHIFT + MEMOPIDX_SHIFT, 5);
    intptr_t i, oprsz = simd_oprsz(desc);
    ARMVectorReg scratch[2] = { 0 };

    set_helper_retaddr(ra);
    for (i = 0; i < oprsz; ) {
        uint16_t pg = *(uint16_t *)((char *)vg + H1_2(i >> 3));
        do {
            if (pg & 1) {
                tlb_fn(env, &scratch[0], i, addr, oi, ra);
                tlb_fn(env, &scratch[1], i, addr + size, oi, ra);
            }
            i += size, pg >>= size;
            addr += 2 * size;
        } while (i & 15);
    }
    clear_helper_retaddr();

    /* Wait until all exceptions have been raised to write back.  */
    memcpy(&env->vfp.zregs[rd], &scratch[0], oprsz);
    memcpy(&env->vfp.zregs[(rd + 1) & 31], &scratch[1], oprsz);
}

static void sve_ld3_r(CPUARMState *env, void *vg, target_ulong addr,
                      uint32_t desc, int size, uintptr_t ra,
                      sve_ld1_tlb_fn *tlb_fn)
{
    const TCGMemOpIdx oi = extract32(desc, SIMD_DATA_SHIFT, MEMOPIDX_SHIFT);
    const unsigned rd = extract32(desc, SIMD_DATA_SHIFT + MEMOPIDX_SHIFT, 5);
    intptr_t i, oprsz = simd_oprsz(desc);
    ARMVectorReg scratch[3] = { 0 };

    set_helper_retaddr(ra);
    for (i = 0; i < oprsz; ) {
        uint16_t pg = *(uint16_t *)((char *)vg + H1_2(i >> 3));
        do {
            if (pg & 1) {
                tlb_fn(env, &scratch[0], i, addr, oi, ra);
                tlb_fn(env, &scratch[1], i, addr + size, oi, ra);
                tlb_fn(env, &scratch[2], i, addr + 2 * size, oi, ra);
            }
            i += size, pg >>= size;
            addr += 3 * size;
        } while (i & 15);
    }
    clear_helper_retaddr();

    /* Wait until all exceptions have been raised to write back.  */
    memcpy(&env->vfp.zregs[rd], &scratch[0], oprsz);
    memcpy(&env->vfp.zregs[(rd + 1) & 31], &scratch[1], oprsz);
    memcpy(&env->vfp.zregs[(rd + 2) & 31], &scratch[2], oprsz);
}

static void sve_ld4_r(CPUARMState *env, void *vg, target_ulong addr,
                      uint32_t desc, int size, uintptr_t ra,
                      sve_ld1_tlb_fn *tlb_fn)
{
    const TCGMemOpIdx oi = extract32(desc, SIMD_DATA_SHIFT, MEMOPIDX_SHIFT);
    const unsigned rd = extract32(desc, SIMD_DATA_SHIFT + MEMOPIDX_SHIFT, 5);
    intptr_t i, oprsz = simd_oprsz(desc);
    ARMVectorReg scratch[4] = { 0 };

    set_helper_retaddr(ra);
    for (i = 0; i < oprsz; ) {
        uint16_t pg = *(uint16_t *)((char *)vg + H1_2(i >> 3));
        do {
            if (pg & 1) {
                tlb_fn(env, &scratch[0], i, addr, oi, ra);
                tlb_fn(env, &scratch[1], i, addr + size, oi, ra);
                tlb_fn(env, &scratch[2], i, addr + 2 * size, oi, ra);
                tlb_fn(env, &scratch[3], i, addr + 3 * size, oi, ra);
            }
            i += size, pg >>= size;
            addr += 4 * size;
        } while (i & 15);
    }
    clear_helper_retaddr();

    /* Wait until all exceptions have been raised to write back.  */
    memcpy(&env->vfp.zregs[rd], &scratch[0], oprsz);
    memcpy(&env->vfp.zregs[(rd + 1) & 31], &scratch[1], oprsz);
    memcpy(&env->vfp.zregs[(rd + 2) & 31], &scratch[2], oprsz);
    memcpy(&env->vfp.zregs[(rd + 3) & 31], &scratch[3], oprsz);
}

#define DO_LDN_1(N) \
void QEMU_FLATTEN HELPER(sve_ld##N##bb_r) \
    (CPUARMState *env, void *vg, target_ulong addr, uint32_t desc)  \
{                                                                   \
    sve_ld##N##_r(env, vg, addr, desc, 1, GETPC(), sve_ld1bb_tlb);  \
}

#define DO_LDN_2(N, SUFF, SIZE)                                       \
void QEMU_FLATTEN HELPER(sve_ld##N##SUFF##_le_r)                      \
    (CPUARMState *env, void *vg, target_ulong addr, uint32_t desc)    \
{                                                                     \
    sve_ld##N##_r(env, vg, addr, desc, SIZE, GETPC(),                 \
                  sve_ld1##SUFF##_le_tlb);                            \
}                                                                     \
void QEMU_FLATTEN HELPER(sve_ld##N##SUFF##_be_r)                      \
    (CPUARMState *env, void *vg, target_ulong addr, uint32_t desc)    \
{                                                                     \
    sve_ld##N##_r(env, vg, addr, desc, SIZE, GETPC(),                 \
                  sve_ld1##SUFF##_be_tlb);                            \
}

DO_LDN_1(2)
DO_LDN_1(3)
DO_LDN_1(4)

DO_LDN_2(2, hh, 2)
DO_LDN_2(3, hh, 2)
DO_LDN_2(4, hh, 2)

DO_LDN_2(2, ss, 4)
DO_LDN_2(3, ss, 4)
DO_LDN_2(4, ss, 4)

DO_LDN_2(2, dd, 8)
DO_LDN_2(3, dd, 8)
DO_LDN_2(4, dd, 8)

#undef DO_LDN_1
#undef DO_LDN_2

/*
 * Load contiguous data, first-fault and no-fault.
 *
 * For user-only, one could argue that we should hold the mmap_lock during
 * the operation so that there is no race between page_check_range and the
 * load operation.  However, unmapping pages out from under a running thread
 * is extraordinarily unlikely.  This theoretical race condition also affects
 * linux-user/ in its get_user/put_user macros.
 *
 * TODO: Construct some helpers, written in assembly, that interact with
 * handle_cpu_signal to produce memory ops which can properly report errors
 * without racing.
 */

/* Fault on byte I.  All bits in FFR from I are cleared.  The vector
 * result from I is CONSTRAINED UNPREDICTABLE; we choose the MERGE
 * option, which leaves subsequent data unchanged.
 */
static void record_fault(CPUARMState *env, uintptr_t i, uintptr_t oprsz)
{
    uint64_t *ffr = env->vfp.pregs[FFR_PRED_NUM].p;

    if (i & 63) {
        ffr[i / 64] &= MAKE_64BIT_MASK(0, i & 63);
        i = ROUND_UP(i, 64);
    }
    for (; i < oprsz; i += 64) {
        ffr[i / 64] = 0;
    }
}

/*
 * Common helper for all contiguous first-fault loads.
 */
static void sve_ldff1_r(CPUARMState *env, void *vg, const target_ulong addr,
                        uint32_t desc, const uintptr_t retaddr,
                        const int esz, const int msz,
                        sve_ld1_host_fn *host_fn,
                        sve_ld1_tlb_fn *tlb_fn)
{
    const TCGMemOpIdx oi = extract32(desc, SIMD_DATA_SHIFT, MEMOPIDX_SHIFT);
    const int mmu_idx = get_mmuidx(oi);
    const unsigned rd = extract32(desc, SIMD_DATA_SHIFT + MEMOPIDX_SHIFT, 5);
    void *vd = &env->vfp.zregs[rd];
    const int diffsz = esz - msz;
    const intptr_t reg_max = simd_oprsz(desc);
    const intptr_t mem_max = reg_max >> diffsz;
    intptr_t split, reg_off, mem_off;
    void *host;

    /* Skip to the first active element.  */
    reg_off = find_next_active(vg, 0, reg_max, esz);
    if (unlikely(reg_off == reg_max)) {
        /* The entire predicate was false; no load occurs.  */
        memset(vd, 0, reg_max);
        return;
    }
    mem_off = reg_off >> diffsz;
    set_helper_retaddr(retaddr);

    /*
     * If the (remaining) load is entirely within a single page, then:
     * For softmmu, and the tlb hits, then no faults will occur;
     * For user-only, either the first load will fault or none will.
     * We can thus perform the load directly to the destination and
     * Vd will be unmodified on any exception path.
     */
    split = max_for_page(env->uc, addr, mem_off, mem_max);
    if (likely(split == mem_max)) {
        host = tlb_vaddr_to_host(env, addr + mem_off, MMU_DATA_LOAD, mmu_idx);
        if (test_host_page(host)) {
            mem_off = host_fn(vd, vg, (char *)host - mem_off, mem_off, mem_max);
            tcg_debug_assert(mem_off == mem_max);
            clear_helper_retaddr();
            /* After any fault, zero any leading inactive elements.  */
            swap_memzero(vd, reg_off);
            return;
        }
    }

    /*
     * Perform one normal read, which will fault or not.
     * But it is likely to bring the page into the tlb.
     */
    tlb_fn(env, vd, reg_off, addr + mem_off, oi, retaddr);

    /* After any fault, zero any leading predicated false elts.  */
    swap_memzero(vd, reg_off);
    mem_off += 1ULL << msz;
    reg_off += 1ULL << esz;

    /* Try again to read the balance of the page.  */
    split = max_for_page(env->uc, addr, mem_off - 1, mem_max);
    if (split >= (1ULL << msz)) {
        host = tlb_vaddr_to_host(env, addr + mem_off, MMU_DATA_LOAD, mmu_idx);
        if (host) {
            mem_off = host_fn(vd, vg, (char *)host - mem_off, mem_off, split);
            reg_off = mem_off << diffsz;
        }
    }

    clear_helper_retaddr();
    record_fault(env, reg_off, reg_max);
}

/*
 * Common helper for all contiguous no-fault loads.
 */
static void sve_ldnf1_r(CPUARMState *env, void *vg, const target_ulong addr,
                        uint32_t desc, const int esz, const int msz,
                        sve_ld1_host_fn *host_fn)
{
    const unsigned rd = extract32(desc, SIMD_DATA_SHIFT + MEMOPIDX_SHIFT, 5);
    void *vd = &env->vfp.zregs[rd];
    const int diffsz = esz - msz;
    const intptr_t reg_max = simd_oprsz(desc);
    const intptr_t mem_max = reg_max >> diffsz;
    const int mmu_idx = cpu_mmu_index(env, false);
    intptr_t split, reg_off, mem_off;
    void *host;

    /* There will be no fault, so we may modify in advance.  */
    memset(vd, 0, reg_max);

    /* Skip to the first active element.  */
    reg_off = find_next_active(vg, 0, reg_max, esz);
    if (unlikely(reg_off == reg_max)) {
        /* The entire predicate was false; no load occurs.  */
        return;
    }
    mem_off = reg_off >> diffsz;

    /*
     * If the address is not in the TLB, we have no way to bring the
     * entry into the TLB without also risking a fault.  Note that
     * the corollary is that we never load from an address not in RAM.
     *
     * This last is out of spec, in a weird corner case.
     * Per the MemNF/MemSingleNF pseudocode, a NF load from Device memory
     * must not actually hit the bus -- it returns UNKNOWN data instead.
     * But if you map non-RAM with Normal memory attributes and do a NF
     * load then it should access the bus.  (Nobody ought actually do this
     * in the real world, obviously.)
     *
     * Then there are the annoying special cases with watchpoints...
     * TODO: Add a form of non-faulting loads using cc->tlb_fill(probe=true).
     */
    host = tlb_vaddr_to_host(env, addr + mem_off, MMU_DATA_LOAD, mmu_idx);
    split = max_for_page(env->uc, addr, mem_off, mem_max);
    if (host && split >= (1ULL << msz)) {
        mem_off = host_fn(vd, vg, (char *)host - mem_off, mem_off, split);
        reg_off = mem_off << diffsz;
    }

    record_fault(env, reg_off, reg_max);
}

#define DO_LDFF1_LDNF1_1(PART, ESZ) \
void HELPER(sve_ldff1##PART##_r)(CPUARMState *env, void *vg,            \
                                 target_ulong addr, uint32_t desc)      \
{                                                                       \
    sve_ldff1_r(env, vg, addr, desc, GETPC(), ESZ, 0,                   \
                sve_ld1##PART##_host, sve_ld1##PART##_tlb);             \
}                                                                       \
void HELPER(sve_ldnf1##PART##_r)(CPUARMState *env, void *vg,            \
                                 target_ulong addr, uint32_t desc)      \
{                                                                       \
    sve_ldnf1_r(env, vg, addr, desc, ESZ, 0, sve_ld1##PART##_host);     \
}

#define DO_LDFF1_LDNF1_2(PART, ESZ, MSZ) \
void HELPER(sve_ldff1##PART##_le_r)(CPUARMState *env, void *vg,         \
                                    target_ulong addr, uint32_t desc)   \
{                                                                       \
    sve_ldff1_r(env, vg, addr, desc, GETPC(), ESZ, MSZ,                 \
                sve_ld1##PART##_le_host, sve_ld1##PART##_le_tlb);       \
}                                                                       \
void HELPER(sve_ldnf1##PART##_le_r)(CPUARMState *env, void *vg,         \
                                    target_ulong addr, uint32_t desc)   \
{                                                                       \
    sve_ldnf1_r(env, vg, addr, desc, ESZ, MSZ, sve_ld1##PART##_le_host); \
}                                                                       \
void HELPER(sve_ldff1##PART##_be_r)(CPUARMState *env, void *vg,         \
                                    target_ulong addr, uint32_t desc)   \
{                                                                       \
    sve_ldff1_r(env, vg, addr, desc, GETPC(), ESZ, MSZ,                 \
                sve_ld1##PART##_be_host, sve_ld1##PART##_be_tlb);       \
}                                                                       \
void HELPER(sve_ldnf1##PART##_be_r)(CPUARMState *env, void *vg,         \
                                    target_ulong addr, uint32_t desc)   \
{                                                                       \
    sve_ldnf1_r(env, vg, addr, desc, ESZ, MSZ, sve_ld1##PART##_be_host); \
}

DO_LDFF1_LDNF1_1(bb,  0)
DO_LDFF1_LDNF1_1(bhu, 1)
DO_LDFF1_LDNF1_1(bhs, 1)
DO_LDFF1_LDNF1_1(bsu, 2)
DO_LDFF1_LDNF1_1(bss, 2)
DO_LDFF1_LDNF1_1(bdu, 3)
DO_LDFF1_LDNF1_1(bds, 3)

DO_LDFF1_LDNF1_2(hh,  1, 1)
DO_LDFF1_LDNF1_2(hsu, 2, 1)
DO_LDFF1_LDNF1_2(hss, 2, 1)
DO_LDFF1_LDNF1_2(hdu, 3, 1)
DO_LDFF1_LDNF1_2(hds, 3, 1)

DO_LDFF1_LDNF1_2(ss,  2, 2)
DO_LDFF1_LDNF1_2(sdu, 3, 2)
DO_LDFF1_LDNF1_2(sds, 3, 2)

DO_LDFF1_LDNF1_2(dd,  3, 3)

#undef DO_LDFF1_LDNF1_1
#undef DO_LDFF1_LDNF1_2

/*
 * Store contiguous data, protected by a governing predicate.
 */

#define DO_ST_TLB(NAME, H, TYPEM, HOST, MOEND, TLB) \
static void sve_##NAME##_tlb(CPUARMState *env, void *vd, intptr_t reg_off,  \
                             target_ulong addr, TCGMemOpIdx oi, uintptr_t ra) \
{                                                                           \
    TLB(env, addr, *(TYPEM *)((char *)vd + H(reg_off)), oi, ra);                    \
}

DO_ST_TLB(st1bb,   H1,  uint8_t, stb_p, 0, helper_ret_stb_mmu)
DO_ST_TLB(st1bh, H1_2, uint16_t, stb_p, 0, helper_ret_stb_mmu)
DO_ST_TLB(st1bs, H1_4, uint32_t, stb_p, 0, helper_ret_stb_mmu)
DO_ST_TLB(st1bd,     , uint64_t, stb_p, 0, helper_ret_stb_mmu)

DO_ST_TLB(st1hh_le, H1_2, uint16_t, stw_le_p, MO_LE, helper_le_stw_mmu)
DO_ST_TLB(st1hs_le, H1_4, uint32_t, stw_le_p, MO_LE, helper_le_stw_mmu)
DO_ST_TLB(st1hd_le,     , uint64_t, stw_le_p, MO_LE, helper_le_stw_mmu)

DO_ST_TLB(st1ss_le, H1_4, uint32_t, stl_le_p, MO_LE, helper_le_stl_mmu)
DO_ST_TLB(st1sd_le,     , uint64_t, stl_le_p, MO_LE, helper_le_stl_mmu)

DO_ST_TLB(st1dd_le,     , uint64_t, stq_le_p, MO_LE, helper_le_stq_mmu)

DO_ST_TLB(st1hh_be, H1_2, uint16_t, stw_be_p, MO_BE, helper_be_stw_mmu)
DO_ST_TLB(st1hs_be, H1_4, uint32_t, stw_be_p, MO_BE, helper_be_stw_mmu)
DO_ST_TLB(st1hd_be,     , uint64_t, stw_be_p, MO_BE, helper_be_stw_mmu)

DO_ST_TLB(st1ss_be, H1_4, uint32_t, stl_be_p, MO_BE, helper_be_stl_mmu)
DO_ST_TLB(st1sd_be,     , uint64_t, stl_be_p, MO_BE, helper_be_stl_mmu)

DO_ST_TLB(st1dd_be,     , uint64_t, stq_be_p, MO_BE, helper_be_stq_mmu)

#undef DO_ST_TLB

/*
 * Common helpers for all contiguous 1,2,3,4-register predicated stores.
 */
static void sve_st1_r(CPUARMState *env, void *vg, target_ulong addr,
                      uint32_t desc, const uintptr_t ra,
                      const int esize, const int msize,
                      sve_st1_tlb_fn *tlb_fn)
{
    const TCGMemOpIdx oi = extract32(desc, SIMD_DATA_SHIFT, MEMOPIDX_SHIFT);
    const unsigned rd = extract32(desc, SIMD_DATA_SHIFT + MEMOPIDX_SHIFT, 5);
    intptr_t i, oprsz = simd_oprsz(desc);
    void *vd = &env->vfp.zregs[rd];

    set_helper_retaddr(ra);
    for (i = 0; i < oprsz; ) {
        uint16_t pg = *(uint16_t *)((char *)vg + H1_2(i >> 3));
        do {
            if (pg & 1) {
                tlb_fn(env, vd, i, addr, oi, ra);
            }
            i += esize, pg >>= esize;
            addr += msize;
        } while (i & 15);
    }
    clear_helper_retaddr();
}

static void sve_st2_r(CPUARMState *env, void *vg, target_ulong addr,
                      uint32_t desc, const uintptr_t ra,
                      const int esize, const int msize,
                      sve_st1_tlb_fn *tlb_fn)
{
    const TCGMemOpIdx oi = extract32(desc, SIMD_DATA_SHIFT, MEMOPIDX_SHIFT);
    const unsigned rd = extract32(desc, SIMD_DATA_SHIFT + MEMOPIDX_SHIFT, 5);
    intptr_t i, oprsz = simd_oprsz(desc);
    void *d1 = &env->vfp.zregs[rd];
    void *d2 = &env->vfp.zregs[(rd + 1) & 31];

    set_helper_retaddr(ra);
    for (i = 0; i < oprsz; ) {
        uint16_t pg = *(uint16_t *)((char *)vg + H1_2(i >> 3));
        do {
            if (pg & 1) {
                tlb_fn(env, d1, i, addr, oi, ra);
                tlb_fn(env, d2, i, addr + msize, oi, ra);
            }
            i += esize, pg >>= esize;
            addr += 2 * msize;
        } while (i & 15);
    }
    clear_helper_retaddr();
}

static void sve_st3_r(CPUARMState *env, void *vg, target_ulong addr,
                      uint32_t desc, const uintptr_t ra,
                      const int esize, const int msize,
                      sve_st1_tlb_fn *tlb_fn)
{
    const TCGMemOpIdx oi = extract32(desc, SIMD_DATA_SHIFT, MEMOPIDX_SHIFT);
    const unsigned rd = extract32(desc, SIMD_DATA_SHIFT + MEMOPIDX_SHIFT, 5);
    intptr_t i, oprsz = simd_oprsz(desc);
    void *d1 = &env->vfp.zregs[rd];
    void *d2 = &env->vfp.zregs[(rd + 1) & 31];
    void *d3 = &env->vfp.zregs[(rd + 2) & 31];

    set_helper_retaddr(ra);
    for (i = 0; i < oprsz; ) {
        uint16_t pg = *(uint16_t *)((char *)vg + H1_2(i >> 3));
        do {
            if (pg & 1) {
                tlb_fn(env, d1, i, addr, oi, ra);
                tlb_fn(env, d2, i, addr + msize, oi, ra);
                tlb_fn(env, d3, i, addr + 2 * msize, oi, ra);
            }
            i += esize, pg >>= esize;
            addr += 3 * msize;
        } while (i & 15);
    }
    clear_helper_retaddr();
}

static void sve_st4_r(CPUARMState *env, void *vg, target_ulong addr,
                      uint32_t desc, const uintptr_t ra,
                      const int esize, const int msize,
                      sve_st1_tlb_fn *tlb_fn)
{
    const TCGMemOpIdx oi = extract32(desc, SIMD_DATA_SHIFT, MEMOPIDX_SHIFT);
    const unsigned rd = extract32(desc, SIMD_DATA_SHIFT + MEMOPIDX_SHIFT, 5);
    intptr_t i, oprsz = simd_oprsz(desc);
    void *d1 = &env->vfp.zregs[rd];
    void *d2 = &env->vfp.zregs[(rd + 1) & 31];
    void *d3 = &env->vfp.zregs[(rd + 2) & 31];
    void *d4 = &env->vfp.zregs[(rd + 3) & 31];

    set_helper_retaddr(ra);
    for (i = 0; i < oprsz; ) {
        uint16_t pg = *(uint16_t *)((char *)vg + H1_2(i >> 3));
        do {
            if (pg & 1) {
                tlb_fn(env, d1, i, addr, oi, ra);
                tlb_fn(env, d2, i, addr + msize, oi, ra);
                tlb_fn(env, d3, i, addr + 2 * msize, oi, ra);
                tlb_fn(env, d4, i, addr + 3 * msize, oi, ra);
            }
            i += esize, pg >>= esize;
            addr += 4 * msize;
        } while (i & 15);
    }
    clear_helper_retaddr();
}

#define DO_STN_1(N, NAME, ESIZE) \
void QEMU_FLATTEN HELPER(sve_st##N##NAME##_r) \
    (CPUARMState *env, void *vg, target_ulong addr, uint32_t desc)  \
{                                                                   \
    sve_st##N##_r(env, vg, addr, desc, GETPC(), ESIZE, 1,           \
                  sve_st1##NAME##_tlb);                             \
}

#define DO_STN_2(N, NAME, ESIZE, MSIZE) \
void QEMU_FLATTEN HELPER(sve_st##N##NAME##_le_r) \
    (CPUARMState *env, void *vg, target_ulong addr, uint32_t desc)    \
{                                                                     \
    sve_st##N##_r(env, vg, addr, desc, GETPC(), ESIZE, MSIZE,         \
                  sve_st1##NAME##_le_tlb);                            \
}                                                                     \
void QEMU_FLATTEN HELPER(sve_st##N##NAME##_be_r)                      \
    (CPUARMState *env, void *vg, target_ulong addr, uint32_t desc)    \
{                                                                     \
    sve_st##N##_r(env, vg, addr, desc, GETPC(), ESIZE, MSIZE,         \
                  sve_st1##NAME##_be_tlb);                            \
}

DO_STN_1(1, bb, 1)
DO_STN_1(1, bh, 2)
DO_STN_1(1, bs, 4)
DO_STN_1(1, bd, 8)
DO_STN_1(2, bb, 1)
DO_STN_1(3, bb, 1)
DO_STN_1(4, bb, 1)

DO_STN_2(1, hh, 2, 2)
DO_STN_2(1, hs, 4, 2)
DO_STN_2(1, hd, 8, 2)
DO_STN_2(2, hh, 2, 2)
DO_STN_2(3, hh, 2, 2)
DO_STN_2(4, hh, 2, 2)

DO_STN_2(1, ss, 4, 4)
DO_STN_2(1, sd, 8, 4)
DO_STN_2(2, ss, 4, 4)
DO_STN_2(3, ss, 4, 4)
DO_STN_2(4, ss, 4, 4)

DO_STN_2(1, dd, 8, 8)
DO_STN_2(2, dd, 8, 8)
DO_STN_2(3, dd, 8, 8)
DO_STN_2(4, dd, 8, 8)

#undef DO_STN_1
#undef DO_STN_2

/*
 * Loads with a vector index.
 */

/*
 * Load the element at @reg + @reg_ofs, sign or zero-extend as needed.
 */
typedef target_ulong zreg_off_fn(void *reg, intptr_t reg_ofs);

static target_ulong off_zsu_s(void *reg, intptr_t reg_ofs)
{
    return *(uint32_t *)((char *)reg + H1_4(reg_ofs));
}

static target_ulong off_zss_s(void *reg, intptr_t reg_ofs)
{
    return *(int32_t *)((char *)reg + H1_4(reg_ofs));
}

static target_ulong off_zsu_d(void *reg, intptr_t reg_ofs)
{
    return (uint32_t)*(uint64_t *)((char *)reg + reg_ofs);
}

static target_ulong off_zss_d(void *reg, intptr_t reg_ofs)
{
    return (int32_t)*(uint64_t *)((char *)reg + reg_ofs);
}

static target_ulong off_zd_d(void *reg, intptr_t reg_ofs)
{
    return *(uint64_t *)((char *)reg + reg_ofs);
}

static void sve_ld1_zs(CPUARMState *env, void *vd, void *vg, void *vm,
                       target_ulong base, uint32_t desc, uintptr_t ra,
                       zreg_off_fn *off_fn, sve_ld1_tlb_fn *tlb_fn)
{
    const TCGMemOpIdx oi = extract32(desc, SIMD_DATA_SHIFT, MEMOPIDX_SHIFT);
    const int scale = extract32(desc, SIMD_DATA_SHIFT + MEMOPIDX_SHIFT, 2);
    intptr_t i, oprsz = simd_oprsz(desc);
    ARMVectorReg scratch = { 0 };

    set_helper_retaddr(ra);
    for (i = 0; i < oprsz; ) {
        uint16_t pg = *(uint16_t *)((char *)vg + H1_2(i >> 3));
        do {
            if (likely(pg & 1)) {
                target_ulong off = off_fn(vm, i);
                tlb_fn(env, &scratch, i, base + (off << scale), oi, ra);
            }
            i += 4, pg >>= 4;
        } while (i & 15);
    }
    clear_helper_retaddr();

    /* Wait until all exceptions have been raised to write back.  */
    memcpy(vd, &scratch, oprsz);
}

static void sve_ld1_zd(CPUARMState *env, void *vd, void *vg, void *vm,
                       target_ulong base, uint32_t desc, uintptr_t ra,
                       zreg_off_fn *off_fn, sve_ld1_tlb_fn *tlb_fn)
{
    const TCGMemOpIdx oi = extract32(desc, SIMD_DATA_SHIFT, MEMOPIDX_SHIFT);
    const int scale = extract32(desc, SIMD_DATA_SHIFT + MEMOPIDX_SHIFT, 2);
    intptr_t i, oprsz = simd_oprsz(desc) / 8;
    ARMVectorReg scratch = { 0 };

    set_helper_retaddr(ra);
    for (i = 0; i < oprsz; i++) {
        uint8_t pg = *(uint8_t *)((char *)vg + H1(i));
        if (likely(pg & 1)) {
            target_ulong off = off_fn(vm, i * 8);
            tlb_fn(env, &scratch, i * 8, base + (off << scale), oi, ra);
        }
    }
    clear_helper_retaddr();

    /* Wait until all exceptions have been raised to write back.  */
    memcpy(vd, &scratch, oprsz * 8);
}

#define DO_LD1_ZPZ_S(MEM, OFS) \
void QEMU_FLATTEN HELPER(sve_ld##MEM##_##OFS) \
    (CPUARMState *env, void *vd, void *vg, void *vm,         \
     target_ulong base, uint32_t desc)                       \
{                                                            \
    sve_ld1_zs(env, vd, vg, vm, base, desc, GETPC(),         \
              off_##OFS##_s, sve_ld1##MEM##_tlb);            \
}

#define DO_LD1_ZPZ_D(MEM, OFS) \
void QEMU_FLATTEN HELPER(sve_ld##MEM##_##OFS) \
    (CPUARMState *env, void *vd, void *vg, void *vm,         \
     target_ulong base, uint32_t desc)                       \
{                                                            \
    sve_ld1_zd(env, vd, vg, vm, base, desc, GETPC(),         \
               off_##OFS##_d, sve_ld1##MEM##_tlb);           \
}

DO_LD1_ZPZ_S(bsu, zsu)
DO_LD1_ZPZ_S(bsu, zss)
DO_LD1_ZPZ_D(bdu, zsu)
DO_LD1_ZPZ_D(bdu, zss)
DO_LD1_ZPZ_D(bdu, zd)

DO_LD1_ZPZ_S(bss, zsu)
DO_LD1_ZPZ_S(bss, zss)
DO_LD1_ZPZ_D(bds, zsu)
DO_LD1_ZPZ_D(bds, zss)
DO_LD1_ZPZ_D(bds, zd)

DO_LD1_ZPZ_S(hsu_le, zsu)
DO_LD1_ZPZ_S(hsu_le, zss)
DO_LD1_ZPZ_D(hdu_le, zsu)
DO_LD1_ZPZ_D(hdu_le, zss)
DO_LD1_ZPZ_D(hdu_le, zd)

DO_LD1_ZPZ_S(hsu_be, zsu)
DO_LD1_ZPZ_S(hsu_be, zss)
DO_LD1_ZPZ_D(hdu_be, zsu)
DO_LD1_ZPZ_D(hdu_be, zss)
DO_LD1_ZPZ_D(hdu_be, zd)

DO_LD1_ZPZ_S(hss_le, zsu)
DO_LD1_ZPZ_S(hss_le, zss)
DO_LD1_ZPZ_D(hds_le, zsu)
DO_LD1_ZPZ_D(hds_le, zss)
DO_LD1_ZPZ_D(hds_le, zd)

DO_LD1_ZPZ_S(hss_be, zsu)
DO_LD1_ZPZ_S(hss_be, zss)
DO_LD1_ZPZ_D(hds_be, zsu)
DO_LD1_ZPZ_D(hds_be, zss)
DO_LD1_ZPZ_D(hds_be, zd)

DO_LD1_ZPZ_S(ss_le, zsu)
DO_LD1_ZPZ_S(ss_le, zss)
DO_LD1_ZPZ_D(sdu_le, zsu)
DO_LD1_ZPZ_D(sdu_le, zss)
DO_LD1_ZPZ_D(sdu_le, zd)

DO_LD1_ZPZ_S(ss_be, zsu)
DO_LD1_ZPZ_S(ss_be, zss)
DO_LD1_ZPZ_D(sdu_be, zsu)
DO_LD1_ZPZ_D(sdu_be, zss)
DO_LD1_ZPZ_D(sdu_be, zd)

DO_LD1_ZPZ_D(sds_le, zsu)
DO_LD1_ZPZ_D(sds_le, zss)
DO_LD1_ZPZ_D(sds_le, zd)

DO_LD1_ZPZ_D(sds_be, zsu)
DO_LD1_ZPZ_D(sds_be, zss)
DO_LD1_ZPZ_D(sds_be, zd)

DO_LD1_ZPZ_D(dd_le, zsu)
DO_LD1_ZPZ_D(dd_le, zss)
DO_LD1_ZPZ_D(dd_le, zd)

DO_LD1_ZPZ_D(dd_be, zsu)
DO_LD1_ZPZ_D(dd_be, zss)
DO_LD1_ZPZ_D(dd_be, zd)

#undef DO_LD1_ZPZ_S
#undef DO_LD1_ZPZ_D

/* First fault loads with a vector index.  */

/* Load one element into VD+REG_OFF from (ENV,VADDR) without faulting.
 * The controlling predicate is known to be true.  Return true if the
 * load was successful.
 */
typedef bool sve_ld1_nf_fn(CPUARMState *env, void *vd, intptr_t reg_off,
                           target_ulong vaddr, int mmu_idx);

#ifdef _MSC_VER
#define DO_LD_NF(NAME, H, TYPEE, TYPEM, HOST) \
static bool sve_ld##NAME##_nf(CPUARMState *env, void *vd, intptr_t reg_off, \
                              target_ulong addr, int mmu_idx)               \
{                                                                           \
    struct uc_struct *uc = env->uc;                                         \
    target_ulong next_page = 0ULL - (addr | TARGET_PAGE_MASK);                    \
    if (likely(next_page - addr >= sizeof(TYPEM))) {                        \
        void *host = tlb_vaddr_to_host(env, addr, MMU_DATA_LOAD, mmu_idx);  \
        if (likely(host)) {                                                 \
            TYPEM val = HOST(host);                                         \
            *(TYPEE *)((char *)vd + H(reg_off)) = val;                              \
            return true;                                                    \
        }                                                                   \
    }                                                                       \
    return false;                                                           \
}
#else
#define DO_LD_NF(NAME, H, TYPEE, TYPEM, HOST) \
static bool sve_ld##NAME##_nf(CPUARMState *env, void *vd, intptr_t reg_off, \
                              target_ulong addr, int mmu_idx)               \
{                                                                           \
    struct uc_struct *uc = env->uc;                                         \
    target_ulong next_page = -(addr | TARGET_PAGE_MASK);                    \
    if (likely(next_page - addr >= sizeof(TYPEM))) {                        \
        void *host = tlb_vaddr_to_host(env, addr, MMU_DATA_LOAD, mmu_idx);  \
        if (likely(host)) {                                                 \
            TYPEM val = HOST(host);                                         \
            *(TYPEE *)((char *)vd + H(reg_off)) = val;                              \
            return true;                                                    \
        }                                                                   \
    }                                                                       \
    return false;                                                           \
}
#endif

DO_LD_NF(bsu, H1_4, uint32_t, uint8_t, ldub_p)
DO_LD_NF(bss, H1_4, uint32_t,  int8_t, ldsb_p)
DO_LD_NF(bdu,     , uint64_t, uint8_t, ldub_p)
DO_LD_NF(bds,     , uint64_t,  int8_t, ldsb_p)

DO_LD_NF(hsu_le, H1_4, uint32_t, uint16_t, lduw_le_p)
DO_LD_NF(hss_le, H1_4, uint32_t,  int16_t, ldsw_le_p)
DO_LD_NF(hsu_be, H1_4, uint32_t, uint16_t, lduw_be_p)
DO_LD_NF(hss_be, H1_4, uint32_t,  int16_t, ldsw_be_p)
DO_LD_NF(hdu_le,     , uint64_t, uint16_t, lduw_le_p)
DO_LD_NF(hds_le,     , uint64_t,  int16_t, ldsw_le_p)
DO_LD_NF(hdu_be,     , uint64_t, uint16_t, lduw_be_p)
DO_LD_NF(hds_be,     , uint64_t,  int16_t, ldsw_be_p)

DO_LD_NF(ss_le,  H1_4, uint32_t, uint32_t, ldl_le_p)
DO_LD_NF(ss_be,  H1_4, uint32_t, uint32_t, ldl_be_p)
DO_LD_NF(sdu_le,     , uint64_t, uint32_t, ldl_le_p)
DO_LD_NF(sds_le,     , uint64_t,  int32_t, ldl_le_p)
DO_LD_NF(sdu_be,     , uint64_t, uint32_t, ldl_be_p)
DO_LD_NF(sds_be,     , uint64_t,  int32_t, ldl_be_p)

DO_LD_NF(dd_le,      , uint64_t, uint64_t, ldq_le_p)
DO_LD_NF(dd_be,      , uint64_t, uint64_t, ldq_be_p)

/*
 * Common helper for all gather first-faulting loads.
 */
static inline void sve_ldff1_zs(CPUARMState *env, void *vd, void *vg, void *vm,
                                target_ulong base, uint32_t desc, uintptr_t ra,
                                zreg_off_fn *off_fn, sve_ld1_tlb_fn *tlb_fn,
                                sve_ld1_nf_fn *nonfault_fn)
{
    const TCGMemOpIdx oi = extract32(desc, SIMD_DATA_SHIFT, MEMOPIDX_SHIFT);
    const int mmu_idx = get_mmuidx(oi);
    const int scale = extract32(desc, SIMD_DATA_SHIFT + MEMOPIDX_SHIFT, 2);
    intptr_t reg_off, reg_max = simd_oprsz(desc);
    target_ulong addr;

    /* Skip to the first true predicate.  */
    reg_off = find_next_active(vg, 0, reg_max, MO_32);
    if (likely(reg_off < reg_max)) {
        /* Perform one normal read, which will fault or not.  */
        set_helper_retaddr(ra);
        addr = off_fn(vm, reg_off);
        addr = base + (addr << scale);
        tlb_fn(env, vd, reg_off, addr, oi, ra);

        /* The rest of the reads will be non-faulting.  */
        clear_helper_retaddr();
    }

    /* After any fault, zero the leading predicated false elements.  */
    swap_memzero(vd, reg_off);

    while (likely((reg_off += 4) < reg_max)) {
        uint64_t pg = *(uint64_t *)((char *)vg + (reg_off >> 6) * 8);
        if (likely((pg >> (reg_off & 63)) & 1)) {
            addr = off_fn(vm, reg_off);
            addr = base + (addr << scale);
            if (!nonfault_fn(env, vd, reg_off, addr, mmu_idx)) {
                record_fault(env, reg_off, reg_max);
                break;
            }
        } else {
            *(uint32_t *)((char *)vd + H1_4(reg_off)) = 0;
        }
    }
}

static inline void sve_ldff1_zd(CPUARMState *env, void *vd, void *vg, void *vm,
                                target_ulong base, uint32_t desc, uintptr_t ra,
                                zreg_off_fn *off_fn, sve_ld1_tlb_fn *tlb_fn,
                                sve_ld1_nf_fn *nonfault_fn)
{
    const TCGMemOpIdx oi = extract32(desc, SIMD_DATA_SHIFT, MEMOPIDX_SHIFT);
    const int mmu_idx = get_mmuidx(oi);
    const int scale = extract32(desc, SIMD_DATA_SHIFT + MEMOPIDX_SHIFT, 2);
    intptr_t reg_off, reg_max = simd_oprsz(desc);
    target_ulong addr;

    /* Skip to the first true predicate.  */
    reg_off = find_next_active(vg, 0, reg_max, MO_64);
    if (likely(reg_off < reg_max)) {
        /* Perform one normal read, which will fault or not.  */
        set_helper_retaddr(ra);
        addr = off_fn(vm, reg_off);
        addr = base + (addr << scale);
        tlb_fn(env, vd, reg_off, addr, oi, ra);

        /* The rest of the reads will be non-faulting.  */
        clear_helper_retaddr();
    }

    /* After any fault, zero the leading predicated false elements.  */
    swap_memzero(vd, reg_off);

    while (likely((reg_off += 8) < reg_max)) {
        uint8_t pg = *(uint8_t *)((char *)vg + H1(reg_off >> 3));
        if (likely(pg & 1)) {
            addr = off_fn(vm, reg_off);
            addr = base + (addr << scale);
            if (!nonfault_fn(env, vd, reg_off, addr, mmu_idx)) {
                record_fault(env, reg_off, reg_max);
                break;
            }
        } else {
            *(uint64_t *)((char *)vd + reg_off) = 0;
        }
    }
}

#define DO_LDFF1_ZPZ_S(MEM, OFS) \
void HELPER(sve_ldff##MEM##_##OFS)                                      \
    (CPUARMState *env, void *vd, void *vg, void *vm,                    \
     target_ulong base, uint32_t desc)                                  \
{                                                                       \
    sve_ldff1_zs(env, vd, vg, vm, base, desc, GETPC(),                  \
                 off_##OFS##_s, sve_ld1##MEM##_tlb, sve_ld##MEM##_nf);  \
}

#define DO_LDFF1_ZPZ_D(MEM, OFS) \
void HELPER(sve_ldff##MEM##_##OFS)                                      \
    (CPUARMState *env, void *vd, void *vg, void *vm,                    \
     target_ulong base, uint32_t desc)                                  \
{                                                                       \
    sve_ldff1_zd(env, vd, vg, vm, base, desc, GETPC(),                  \
                 off_##OFS##_d, sve_ld1##MEM##_tlb, sve_ld##MEM##_nf);  \
}

DO_LDFF1_ZPZ_S(bsu, zsu)
DO_LDFF1_ZPZ_S(bsu, zss)
DO_LDFF1_ZPZ_D(bdu, zsu)
DO_LDFF1_ZPZ_D(bdu, zss)
DO_LDFF1_ZPZ_D(bdu, zd)

DO_LDFF1_ZPZ_S(bss, zsu)
DO_LDFF1_ZPZ_S(bss, zss)
DO_LDFF1_ZPZ_D(bds, zsu)
DO_LDFF1_ZPZ_D(bds, zss)
DO_LDFF1_ZPZ_D(bds, zd)

DO_LDFF1_ZPZ_S(hsu_le, zsu)
DO_LDFF1_ZPZ_S(hsu_le, zss)
DO_LDFF1_ZPZ_D(hdu_le, zsu)
DO_LDFF1_ZPZ_D(hdu_le, zss)
DO_LDFF1_ZPZ_D(hdu_le, zd)

DO_LDFF1_ZPZ_S(hsu_be, zsu)
DO_LDFF1_ZPZ_S(hsu_be, zss)
DO_LDFF1_ZPZ_D(hdu_be, zsu)
DO_LDFF1_ZPZ_D(hdu_be, zss)
DO_LDFF1_ZPZ_D(hdu_be, zd)

DO_LDFF1_ZPZ_S(hss_le, zsu)
DO_LDFF1_ZPZ_S(hss_le, zss)
DO_LDFF1_ZPZ_D(hds_le, zsu)
DO_LDFF1_ZPZ_D(hds_le, zss)
DO_LDFF1_ZPZ_D(hds_le, zd)

DO_LDFF1_ZPZ_S(hss_be, zsu)
DO_LDFF1_ZPZ_S(hss_be, zss)
DO_LDFF1_ZPZ_D(hds_be, zsu)
DO_LDFF1_ZPZ_D(hds_be, zss)
DO_LDFF1_ZPZ_D(hds_be, zd)

DO_LDFF1_ZPZ_S(ss_le,  zsu)
DO_LDFF1_ZPZ_S(ss_le,  zss)
DO_LDFF1_ZPZ_D(sdu_le, zsu)
DO_LDFF1_ZPZ_D(sdu_le, zss)
DO_LDFF1_ZPZ_D(sdu_le, zd)

DO_LDFF1_ZPZ_S(ss_be,  zsu)
DO_LDFF1_ZPZ_S(ss_be,  zss)
DO_LDFF1_ZPZ_D(sdu_be, zsu)
DO_LDFF1_ZPZ_D(sdu_be, zss)
DO_LDFF1_ZPZ_D(sdu_be, zd)

DO_LDFF1_ZPZ_D(sds_le, zsu)
DO_LDFF1_ZPZ_D(sds_le, zss)
DO_LDFF1_ZPZ_D(sds_le, zd)

DO_LDFF1_ZPZ_D(sds_be, zsu)
DO_LDFF1_ZPZ_D(sds_be, zss)
DO_LDFF1_ZPZ_D(sds_be, zd)

DO_LDFF1_ZPZ_D(dd_le, zsu)
DO_LDFF1_ZPZ_D(dd_le, zss)
DO_LDFF1_ZPZ_D(dd_le, zd)

DO_LDFF1_ZPZ_D(dd_be, zsu)
DO_LDFF1_ZPZ_D(dd_be, zss)
DO_LDFF1_ZPZ_D(dd_be, zd)

/* Stores with a vector index.  */

static void sve_st1_zs(CPUARMState *env, void *vd, void *vg, void *vm,
                       target_ulong base, uint32_t desc, uintptr_t ra,
                       zreg_off_fn *off_fn, sve_ld1_tlb_fn *tlb_fn)
{
    const TCGMemOpIdx oi = extract32(desc, SIMD_DATA_SHIFT, MEMOPIDX_SHIFT);
    const int scale = extract32(desc, SIMD_DATA_SHIFT + MEMOPIDX_SHIFT, 2);
    intptr_t i, oprsz = simd_oprsz(desc);

    set_helper_retaddr(ra);
    for (i = 0; i < oprsz; ) {
        uint16_t pg = *(uint16_t *)((char *)vg + H1_2(i >> 3));
        do {
            if (likely(pg & 1)) {
                target_ulong off = off_fn(vm, i);
                tlb_fn(env, vd, i, base + (off << scale), oi, ra);
            }
            i += 4, pg >>= 4;
        } while (i & 15);
    }
    clear_helper_retaddr();
}

static void sve_st1_zd(CPUARMState *env, void *vd, void *vg, void *vm,
                       target_ulong base, uint32_t desc, uintptr_t ra,
                       zreg_off_fn *off_fn, sve_ld1_tlb_fn *tlb_fn)
{
    const TCGMemOpIdx oi = extract32(desc, SIMD_DATA_SHIFT, MEMOPIDX_SHIFT);
    const int scale = extract32(desc, SIMD_DATA_SHIFT + MEMOPIDX_SHIFT, 2);
    intptr_t i, oprsz = simd_oprsz(desc) / 8;

    set_helper_retaddr(ra);
    for (i = 0; i < oprsz; i++) {
        uint8_t pg = *(uint8_t *)((char *)vg + H1(i));
        if (likely(pg & 1)) {
            target_ulong off = off_fn(vm, i * 8);
            tlb_fn(env, vd, i * 8, base + (off << scale), oi, ra);
        }
    }
    clear_helper_retaddr();
}

#define DO_ST1_ZPZ_S(MEM, OFS) \
void QEMU_FLATTEN HELPER(sve_st##MEM##_##OFS) \
    (CPUARMState *env, void *vd, void *vg, void *vm,         \
     target_ulong base, uint32_t desc)                       \
{                                                            \
    sve_st1_zs(env, vd, vg, vm, base, desc, GETPC(),         \
              off_##OFS##_s, sve_st1##MEM##_tlb);            \
}

#define DO_ST1_ZPZ_D(MEM, OFS) \
void QEMU_FLATTEN HELPER(sve_st##MEM##_##OFS) \
    (CPUARMState *env, void *vd, void *vg, void *vm,         \
     target_ulong base, uint32_t desc)                       \
{                                                            \
    sve_st1_zd(env, vd, vg, vm, base, desc, GETPC(),         \
               off_##OFS##_d, sve_st1##MEM##_tlb);           \
}

DO_ST1_ZPZ_S(bs, zsu)
DO_ST1_ZPZ_S(hs_le, zsu)
DO_ST1_ZPZ_S(hs_be, zsu)
DO_ST1_ZPZ_S(ss_le, zsu)
DO_ST1_ZPZ_S(ss_be, zsu)

DO_ST1_ZPZ_S(bs, zss)
DO_ST1_ZPZ_S(hs_le, zss)
DO_ST1_ZPZ_S(hs_be, zss)
DO_ST1_ZPZ_S(ss_le, zss)
DO_ST1_ZPZ_S(ss_be, zss)

DO_ST1_ZPZ_D(bd, zsu)
DO_ST1_ZPZ_D(hd_le, zsu)
DO_ST1_ZPZ_D(hd_be, zsu)
DO_ST1_ZPZ_D(sd_le, zsu)
DO_ST1_ZPZ_D(sd_be, zsu)
DO_ST1_ZPZ_D(dd_le, zsu)
DO_ST1_ZPZ_D(dd_be, zsu)

DO_ST1_ZPZ_D(bd, zss)
DO_ST1_ZPZ_D(hd_le, zss)
DO_ST1_ZPZ_D(hd_be, zss)
DO_ST1_ZPZ_D(sd_le, zss)
DO_ST1_ZPZ_D(sd_be, zss)
DO_ST1_ZPZ_D(dd_le, zss)
DO_ST1_ZPZ_D(dd_be, zss)

DO_ST1_ZPZ_D(bd, zd)
DO_ST1_ZPZ_D(hd_le, zd)
DO_ST1_ZPZ_D(hd_be, zd)
DO_ST1_ZPZ_D(sd_le, zd)
DO_ST1_ZPZ_D(sd_be, zd)
DO_ST1_ZPZ_D(dd_le, zd)
DO_ST1_ZPZ_D(dd_be, zd)

#undef DO_ST1_ZPZ_S
#undef DO_ST1_ZPZ_D
