/*
 *  MIPS emulation for qemu: CPU initialisation routines.
 *
 *  Copyright (c) 2004-2005 Jocelyn Mayer
 *  Copyright (c) 2007 Herve Poussineau
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

/* CPU / CPU family specific config register values. */

/* Have config1, uncached coherency */
#define MIPS_CONFIG0                                              \
  ((1U << CP0C0_M) | (0x2 << CP0C0_K0))

/* Have config2, no coprocessor2 attached, no MDMX support attached,
   no performance counters, watch registers present,
   no code compression, EJTAG present, no FPU */
#define MIPS_CONFIG1                                              \
((1U << CP0C1_M) |                                                \
 (0 << CP0C1_C2) | (0 << CP0C1_MD) | (0 << CP0C1_PC) |            \
 (1 << CP0C1_WR) | (0 << CP0C1_CA) | (1 << CP0C1_EP) |            \
 (0 << CP0C1_FP))

/* Have config3, no tertiary/secondary caches implemented */
#define MIPS_CONFIG2                                              \
((1U << CP0C2_M))

/* No config4, no DSP ASE, no large physaddr (PABITS),
   no external interrupt controller, no vectored interrupts,
   no 1kb pages, no SmartMIPS ASE, no trace logic */
#define MIPS_CONFIG3                                              \
((0 << CP0C3_M) | (0 << CP0C3_DSPP) | (0 << CP0C3_LPA) |          \
 (0 << CP0C3_VEIC) | (0 << CP0C3_VInt) | (0 << CP0C3_SP) |        \
 (0 << CP0C3_SM) | (0 << CP0C3_TL))

#define MIPS_CONFIG4                                              \
((0 << CP0C4_M))

#define MIPS_CONFIG5                                              \
((0 << CP0C5_M))

/* MMU types, the first four entries have the same layout as the
   CP0C0_MT field.  */
enum mips_mmu_types {
    MMU_TYPE_NONE,
    MMU_TYPE_R4000,
    MMU_TYPE_RESERVED,
    MMU_TYPE_FMT,
    MMU_TYPE_R3000,
    MMU_TYPE_R6000,
    MMU_TYPE_R8000
};

struct mips_def_t {
    const char *name;
    int32_t CP0_PRid;
    int32_t CP0_Config0;
    int32_t CP0_Config1;
    int32_t CP0_Config2;
    int32_t CP0_Config3;
    int32_t CP0_Config4;
    int32_t CP0_Config4_rw_bitmask;
    int32_t CP0_Config5;
    int32_t CP0_Config5_rw_bitmask;
    int32_t CP0_Config6;
    int32_t CP0_Config7;
    target_ulong CP0_LLAddr_rw_bitmask;
    int CP0_LLAddr_shift;
    int32_t SYNCI_Step;
    int32_t CCRes;
    int32_t CP0_Status_rw_bitmask;
    int32_t CP0_TCStatus_rw_bitmask;
    int32_t CP0_SRSCtl;
    int32_t CP1_fcr0;
    int32_t MSAIR;
    int32_t SEGBITS;
    int32_t PABITS;
    int32_t CP0_SRSConf0_rw_bitmask;
    int32_t CP0_SRSConf0;
    int32_t CP0_SRSConf1_rw_bitmask;
    int32_t CP0_SRSConf1;
    int32_t CP0_SRSConf2_rw_bitmask;
    int32_t CP0_SRSConf2;
    int32_t CP0_SRSConf3_rw_bitmask;
    int32_t CP0_SRSConf3;
    int32_t CP0_SRSConf4_rw_bitmask;
    int32_t CP0_SRSConf4;
    int32_t CP0_PageGrain_rw_bitmask;
    int32_t CP0_PageGrain;
    int insn_flags;
    enum mips_mmu_types mmu_type;
};

/*****************************************************************************/
/* MIPS CPU definitions */
static const mips_def_t mips_defs[] =
{
    {
        "4Kc",
        0x00018000,
        MIPS_CONFIG0 | (MMU_TYPE_R4000 << CP0C0_MT),
        MIPS_CONFIG1 | (15 << CP0C1_MMU) |
                       (0 << CP0C1_IS) | (3 << CP0C1_IL) | (1 << CP0C1_IA) |
                       (0 << CP0C1_DS) | (3 << CP0C1_DL) | (1 << CP0C1_DA) |
                       (0 << CP0C1_CA),
        MIPS_CONFIG2,
        MIPS_CONFIG3,
        0,0,
        0,0,
        0,
        0,
        0,
        4,
        32,
        2,
        0x1278FF17,
        0,
        0,
        0,
        0,
        32,
        32,
        0,0, 0,0, 0,0, 0,0, 0,0, 0,0,
        CPU_MIPS32,
        MMU_TYPE_R4000,
    },
    {
        "4Km",
        0x00018300,
        /* Config1 implemented, fixed mapping MMU,
           no virtual icache, uncached coherency. */
        MIPS_CONFIG0 | (MMU_TYPE_FMT << CP0C0_MT),
        MIPS_CONFIG1 |
                       (0 << CP0C1_IS) | (3 << CP0C1_IL) | (1 << CP0C1_IA) |
                       (0 << CP0C1_DS) | (3 << CP0C1_DL) | (1 << CP0C1_DA) |
                       (1 << CP0C1_CA),
        MIPS_CONFIG2,
        MIPS_CONFIG3,
        0,0,
        0,0,
        0,
        0,
        
        0,
        4,
        32,
        2,
        0x1258FF17,
        0,

        0,
        0,
        0,
        32,
        32,
        0,0, 0,0, 0,0, 0,0, 0,0, 0,0,
        CPU_MIPS32 | ASE_MIPS16,
        MMU_TYPE_FMT,
    },
    {
        "4KEcR1",
        0x00018400,
        MIPS_CONFIG0 | (MMU_TYPE_R4000 << CP0C0_MT),
        MIPS_CONFIG1 | (15 << CP0C1_MMU) |
                       (0 << CP0C1_IS) | (3 << CP0C1_IL) | (1 << CP0C1_IA) |
                       (0 << CP0C1_DS) | (3 << CP0C1_DL) | (1 << CP0C1_DA) |
                       (0 << CP0C1_CA),
        MIPS_CONFIG2,
        MIPS_CONFIG3,
        0,0,
        0,0,
        0,
        0,
        0,
        4,
        32,
        2,
        0x1278FF17,
        0,
        0,
        0,
        0,
        32,
        32,
        0,0, 0,0, 0,0, 0,0, 0,0, 0,0,
        CPU_MIPS32,
        MMU_TYPE_R4000,
    },
    {
        "4KEmR1",
        0x00018500,
        MIPS_CONFIG0 | (MMU_TYPE_FMT << CP0C0_MT),
        MIPS_CONFIG1 |
                       (0 << CP0C1_IS) | (3 << CP0C1_IL) | (1 << CP0C1_IA) |
                       (0 << CP0C1_DS) | (3 << CP0C1_DL) | (1 << CP0C1_DA) |
                       (1 << CP0C1_CA),
        MIPS_CONFIG2,
        MIPS_CONFIG3,
        0,0,
        0,0,
        0,
        0,
        0,
        4,
        32,
        2,
        0x1258FF17,
        0,
        0,
        0,
        0,
        32,
        32,
        0,0, 0,0, 0,0, 0,0, 0,0, 0,0,
        CPU_MIPS32 | ASE_MIPS16,
        MMU_TYPE_FMT,
    },
    {
        "4KEc",
        0x00019000,
        MIPS_CONFIG0 | (0x1 << CP0C0_AR) |
                    (MMU_TYPE_R4000 << CP0C0_MT),
        MIPS_CONFIG1 | (15 << CP0C1_MMU) |
                       (0 << CP0C1_IS) | (3 << CP0C1_IL) | (1 << CP0C1_IA) |
                       (0 << CP0C1_DS) | (3 << CP0C1_DL) | (1 << CP0C1_DA) |
                       (0 << CP0C1_CA),
        MIPS_CONFIG2,
        MIPS_CONFIG3 | (0 << CP0C3_VInt),
        0,0,
        0,0,
        0,
        0,
        0,
        4,
        32,
        2,
        0x1278FF17,
        0,
        0,
        0,
        0,
        32,
        32,
        0,0, 0,0, 0,0, 0,0, 0,0, 0,0,
        CPU_MIPS32R2,
        MMU_TYPE_R4000,
    },
    {
        "4KEm",
        0x00019100,
        MIPS_CONFIG0 | (0x1 << CP0C0_AR) |
                       (MMU_TYPE_FMT << CP0C0_MT),
        MIPS_CONFIG1 |
                       (0 << CP0C1_IS) | (3 << CP0C1_IL) | (1 << CP0C1_IA) |
                       (0 << CP0C1_DS) | (3 << CP0C1_DL) | (1 << CP0C1_DA) |
                       (1 << CP0C1_CA),
        MIPS_CONFIG2,
        MIPS_CONFIG3,
        0,0,
        0,0,
        0,
        0,
        0,
        4,
        32,
        2,
        0x1258FF17,
        0,
        0,
        0,
        0,
        32,
        32,
        0,0, 0,0, 0,0, 0,0, 0,0, 0,0,
        CPU_MIPS32R2 | ASE_MIPS16,
        MMU_TYPE_FMT,
    },
    {
        "24Kc",
        0x00019300,
        MIPS_CONFIG0 | (0x1 << CP0C0_AR) |
                       (MMU_TYPE_R4000 << CP0C0_MT),
        MIPS_CONFIG1 | (15 << CP0C1_MMU) |
                       (0 << CP0C1_IS) | (3 << CP0C1_IL) | (1 << CP0C1_IA) |
                       (0 << CP0C1_DS) | (3 << CP0C1_DL) | (1 << CP0C1_DA) |
                       (1 << CP0C1_CA),
        MIPS_CONFIG2,
        MIPS_CONFIG3 | (0 << CP0C3_VInt),
        0,0,
        0,0,
        0,
        0,
        0,
        4,
        32,
        2,
        /* No DSP implemented. */
        0x1278FF1F,
        0,
        0,
        0,
        32,
        32,
        0,0, 0,0, 0,0, 0,0, 0,0, 0,0,
        CPU_MIPS32R2 | ASE_MIPS16,
        MMU_TYPE_R4000,
    },
    {
        "24Kf",
        0x00019300,
        MIPS_CONFIG0 | (0x1 << CP0C0_AR) |
                    (MMU_TYPE_R4000 << CP0C0_MT),
        MIPS_CONFIG1 | (1 << CP0C1_FP) | (15 << CP0C1_MMU) |
                       (0 << CP0C1_IS) | (3 << CP0C1_IL) | (1 << CP0C1_IA) |
                       (0 << CP0C1_DS) | (3 << CP0C1_DL) | (1 << CP0C1_DA) |
                       (1 << CP0C1_CA),
        MIPS_CONFIG2,
        MIPS_CONFIG3 | (0 << CP0C3_VInt),
        0,0,
        0,0,
        0,
        0,
        0,
        4,
        32,
        2,
        /* No DSP implemented. */
        0x3678FF1F,
        0,
        0,
        (1 << FCR0_F64) | (1 << FCR0_L) | (1 << FCR0_W) |
                    (1 << FCR0_D) | (1 << FCR0_S) | (0x93 << FCR0_PRID),
        0,
        32,
        32,
        0,0, 0,0, 0,0, 0,0, 0,0, 0,0,
        CPU_MIPS32R2 | ASE_MIPS16,
        MMU_TYPE_R4000,
    },
    {
        "34Kf",
        0x00019500,
        MIPS_CONFIG0 | (0x1 << CP0C0_AR) |
                       (MMU_TYPE_R4000 << CP0C0_MT),
        MIPS_CONFIG1 | (1 << CP0C1_FP) | (15 << CP0C1_MMU) |
                       (0 << CP0C1_IS) | (3 << CP0C1_IL) | (1 << CP0C1_IA) |
                       (0 << CP0C1_DS) | (3 << CP0C1_DL) | (1 << CP0C1_DA) |
                       (1 << CP0C1_CA),
        MIPS_CONFIG2,
        MIPS_CONFIG3 | (1 << CP0C3_VInt) | (1 << CP0C3_MT) |
                       (1 << CP0C3_DSPP),
        0,
        0,
        32,
        2,
        0x3778FF1F,
        (0 << CP0TCSt_TCU3) | (0 << CP0TCSt_TCU2) |
                    (1 << CP0TCSt_TCU1) | (1 << CP0TCSt_TCU0) |
                    (0 << CP0TCSt_TMX) | (1 << CP0TCSt_DT) |
                    (1 << CP0TCSt_DA) | (1 << CP0TCSt_A) |
                    (0x3 << CP0TCSt_TKSU) | (1 << CP0TCSt_IXMT) |
                    (0xff << CP0TCSt_TASID),
        (0xf << CP0SRSCtl_HSS),
        0,
        32,
        32,
        (1 << FCR0_F64) | (1 << FCR0_L) | (1 << FCR0_W) |
                    (1 << FCR0_D) | (1 << FCR0_S) | (0x95 << FCR0_PRID),
        0x3fffffff,
        (1U << CP0SRSC0_M) | (0x3fe << CP0SRSC0_SRS3) |
                    (0x3fe << CP0SRSC0_SRS2) | (0x3fe << CP0SRSC0_SRS1),
        0x3fffffff,
        (1U << CP0SRSC1_M) | (0x3fe << CP0SRSC1_SRS6) |
                    (0x3fe << CP0SRSC1_SRS5) | (0x3fe << CP0SRSC1_SRS4),
        0x3fffffff,
        (1U << CP0SRSC2_M) | (0x3fe << CP0SRSC2_SRS9) |
                    (0x3fe << CP0SRSC2_SRS8) | (0x3fe << CP0SRSC2_SRS7),
        0x3fffffff,
        (1U << CP0SRSC3_M) | (0x3fe << CP0SRSC3_SRS12) |
                    (0x3fe << CP0SRSC3_SRS11) | (0x3fe << CP0SRSC3_SRS10),
        0x3fffffff,
        (0x3fe << CP0SRSC4_SRS15) |
                    (0x3fe << CP0SRSC4_SRS14) | (0x3fe << CP0SRSC4_SRS13),
        0,0,
        CPU_MIPS32R2 | ASE_MIPS16 | ASE_DSP | ASE_MT,
        MMU_TYPE_R4000,
    },
    {
        "74Kf",
        0x00019700,
        MIPS_CONFIG0 | (0x1 << CP0C0_AR) |
                    (MMU_TYPE_R4000 << CP0C0_MT),
        MIPS_CONFIG1 | (1 << CP0C1_FP) | (15 << CP0C1_MMU) |
                       (0 << CP0C1_IS) | (3 << CP0C1_IL) | (1 << CP0C1_IA) |
                       (0 << CP0C1_DS) | (3 << CP0C1_DL) | (1 << CP0C1_DA) |
                       (1 << CP0C1_CA),
        MIPS_CONFIG2,
        MIPS_CONFIG3 | (1 << CP0C3_DSP2P) | (1 << CP0C3_DSPP) |
                       (0 << CP0C3_VInt),
        0,0,
        0,0,
        0,
        0,
        0,
        4,
        32,
        2,
        0x3778FF1F,
        0,
        0,
        (1 << FCR0_F64) | (1 << FCR0_L) | (1 << FCR0_W) |
                    (1 << FCR0_D) | (1 << FCR0_S) | (0x93 << FCR0_PRID),
        0,
        32,
        32,
        0,0, 0,0, 0,0, 0,0, 0,0, 0,0,
        CPU_MIPS32R2 | ASE_MIPS16 | ASE_DSP | ASE_DSPR2,
        MMU_TYPE_R4000,
    },
    {
        /* A generic CPU providing MIPS32 Release 5 features.
           FIXME: Eventually this should be replaced by a real CPU model. */
        "mips32r5-generic",
        0x00019700,
        MIPS_CONFIG0 | (0x1 << CP0C0_AR) |
                    (MMU_TYPE_R4000 << CP0C0_MT),
        MIPS_CONFIG1 | (1 << CP0C1_FP) | (15 << CP0C1_MMU) |
                       (0 << CP0C1_IS) | (3 << CP0C1_IL) | (1 << CP0C1_IA) |
                       (0 << CP0C1_DS) | (3 << CP0C1_DL) | (1 << CP0C1_DA) |
                       (1 << CP0C1_CA),
        MIPS_CONFIG2,
        MIPS_CONFIG3 | (1U << CP0C3_M) | (1 << CP0C3_MSAP),
        MIPS_CONFIG4 | (1U << CP0C4_M),
        0,
        MIPS_CONFIG5 | (1 << CP0C5_UFR),
        (0 << CP0C5_M) | (1 << CP0C5_K) |
                                  (1 << CP0C5_CV) | (0 << CP0C5_EVA) |
                                  (1 << CP0C5_MSAEn) | (1 << CP0C5_UFR) |
                                  (0 << CP0C5_NFExists),
        0,
        0,
        0,
        4,
        32,
        2,
        0x3778FF1F,
        0,
        0,
        (1 << FCR0_UFRP) | (1 << FCR0_F64) | (1 << FCR0_L) |
                    (1 << FCR0_W) | (1 << FCR0_D) | (1 << FCR0_S) |
                    (0x93 << FCR0_PRID),
        0,
        32,
        32,
        0,0, 0,0, 0,0, 0,0, 0,0, 0,0,
        CPU_MIPS32R5 | ASE_MIPS16 | ASE_MSA,
        MMU_TYPE_R4000,
    },
#if defined(TARGET_MIPS64)
    {
        "R4000",
        0x00000400,
        /* No L2 cache, icache size 8k, dcache size 8k, uncached coherency. */
        (1 << 17) | (0x1 << 9) | (0x1 << 6) | (0x2 << CP0C0_K0),
        /* Note: Config1 is only used internally, the R4000 has only Config0. */
        (1 << CP0C1_FP) | (47 << CP0C1_MMU),
        0,
        0,
        0,0,
        0,0,
        0,
        0,
        0xFFFFFFFF,
        4,
        16,
        2,
        0x3678FFFF,
        0,
        0,
        /* The R4000 has a full 64bit FPU but doesn't use the fcr0 bits. */
        (0x5 << FCR0_PRID) | (0x0 << FCR0_REV),
        0,
        40,
        36,
        0,0, 0,0, 0,0, 0,0, 0,0, 0,0,
        CPU_MIPS3,
        MMU_TYPE_R4000,
    },
    {
        "VR5432",
        0x00005400,
        /* No L2 cache, icache size 8k, dcache size 8k, uncached coherency. */
        (1 << 17) | (0x1 << 9) | (0x1 << 6) | (0x2 << CP0C0_K0),
        (1 << CP0C1_FP) | (47 << CP0C1_MMU),
        0,
        0,
        0,0,
        0,0,
        0,
        0,
        0xFFFFFFFFL,
        4,
        16,
        2,
        0x3678FFFF,
        0,
        0,
        /* The VR5432 has a full 64bit FPU but doesn't use the fcr0 bits. */
        (0x54 << FCR0_PRID) | (0x0 << FCR0_REV),
        0,
        40,
        32,
        0,0, 0,0, 0,0, 0,0, 0,0, 0,0,
        CPU_VR54XX,
        MMU_TYPE_R4000,
    },
    {
        "5Kc",
        0x00018100,
        MIPS_CONFIG0 | (0x2 << CP0C0_AT) |
                       (MMU_TYPE_R4000 << CP0C0_MT),
        MIPS_CONFIG1 | (31 << CP0C1_MMU) |
                       (1 << CP0C1_IS) | (4 << CP0C1_IL) | (1 << CP0C1_IA) |
                       (1 << CP0C1_DS) | (4 << CP0C1_DL) | (1 << CP0C1_DA) |
                       (1 << CP0C1_PC) | (1 << CP0C1_WR) | (1 << CP0C1_EP),
        MIPS_CONFIG2,
        MIPS_CONFIG3,
        0,0,
        0,0,
        0,
        0,
        0,
        4,
        32,
        2,
        0x32F8FFFF,
        0,
        0,
        0,
        0,
        42,
        36,
        0,0, 0,0, 0,0, 0,0, 0,0, 0,0,
        CPU_MIPS64,
        MMU_TYPE_R4000,
    },
    {
        "5Kf",
        0x00018100,
        MIPS_CONFIG0 | (0x2 << CP0C0_AT) |
                       (MMU_TYPE_R4000 << CP0C0_MT),
        MIPS_CONFIG1 | (1 << CP0C1_FP) | (31 << CP0C1_MMU) |
                       (1 << CP0C1_IS) | (4 << CP0C1_IL) | (1 << CP0C1_IA) |
                       (1 << CP0C1_DS) | (4 << CP0C1_DL) | (1 << CP0C1_DA) |
                       (1 << CP0C1_PC) | (1 << CP0C1_WR) | (1 << CP0C1_EP),
        MIPS_CONFIG2,
        MIPS_CONFIG3,
        0,0,
        0,0,
        0,
        0,
        
        0,
        4,
        32,
        2,
        0x36F8FFFF,
        0,
        0,
        /* The 5Kf has F64 / L / W but doesn't use the fcr0 bits. */
        (1 << FCR0_D) | (1 << FCR0_S) |
                    (0x81 << FCR0_PRID) | (0x0 << FCR0_REV),
        0,
        42,
        36,
        0,0, 0,0, 0,0, 0,0, 0,0, 0,0,
        CPU_MIPS64,
        MMU_TYPE_R4000,
    },
    {
        "20Kc",
        /* We emulate a later version of the 20Kc, earlier ones had a broken
           WAIT instruction. */
        0x000182a0,
        MIPS_CONFIG0 | (0x2 << CP0C0_AT) |
                    (MMU_TYPE_R4000 << CP0C0_MT) | (1 << CP0C0_VI),
        MIPS_CONFIG1 | (1 << CP0C1_FP) | (47 << CP0C1_MMU) |
                       (2 << CP0C1_IS) | (4 << CP0C1_IL) | (3 << CP0C1_IA) |
                       (2 << CP0C1_DS) | (4 << CP0C1_DL) | (3 << CP0C1_DA) |
                       (1 << CP0C1_PC) | (1 << CP0C1_WR) | (1 << CP0C1_EP),
        MIPS_CONFIG2,
        MIPS_CONFIG3,
        0,.0,
        0,0,
        0,
        0,
        0,
        0,
        32,
        1,
        0x36FBFFFF,
        0,
        0,
        /* The 20Kc has F64 / L / W but doesn't use the fcr0 bits. */
        (1 << FCR0_3D) | (1 << FCR0_PS) |
                    (1 << FCR0_D) | (1 << FCR0_S) |
                    (0x82 << FCR0_PRID) | (0x0 << FCR0_REV),
        0,
        40,
        36,
        0,0, 0,0, 0,0, 0,0, 0,0, 0,0,
        CPU_MIPS64 | ASE_MIPS3D,
        MMU_TYPE_R4000,
    },
    {
        /* A generic CPU providing MIPS64 Release 2 features.
           FIXME: Eventually this should be replaced by a real CPU model. */
        "MIPS64R2-generic",
        0x00010000,
        MIPS_CONFIG0 | (0x1 << CP0C0_AR) | (0x2 << CP0C0_AT) |
                       (MMU_TYPE_R4000 << CP0C0_MT),
        MIPS_CONFIG1 | (1 << CP0C1_FP) | (63 << CP0C1_MMU) |
                       (2 << CP0C1_IS) | (4 << CP0C1_IL) | (3 << CP0C1_IA) |
                       (2 << CP0C1_DS) | (4 << CP0C1_DL) | (3 << CP0C1_DA) |
                       (1 << CP0C1_PC) | (1 << CP0C1_WR) | (1 << CP0C1_EP),
        MIPS_CONFIG2,
        MIPS_CONFIG3 | (1 << CP0C3_LPA),
        0,0,
        0,0,
        0,
        0,
        0,
        0,
        32,
        2,
        0x36FBFFFF,
        0,
        0,
        (1 << FCR0_F64) | (1 << FCR0_3D) | (1 << FCR0_PS) |
                    (1 << FCR0_L) | (1 << FCR0_W) | (1 << FCR0_D) |
                    (1 << FCR0_S) | (0x00 << FCR0_PRID) | (0x0 << FCR0_REV),
        0,
        42,
        /* The architectural limit is 59, but we have hardcoded 36 bit
           in some places...
        59, */ /* the architectural limit */
        36,
        0,0, 0,0, 0,0, 0,0, 0,0, 0,0,
        CPU_MIPS64R2 | ASE_MIPS3D,
        MMU_TYPE_R4000,
    },
    {
        /* A generic CPU supporting MIPS64 Release 6 ISA.
           FIXME: Support IEEE 754-2008 FP and misaligned memory accesses.
                  Eventually this should be replaced by a real CPU model. */
        "MIPS64R6-generic",
        0x00010000,
        MIPS_CONFIG0 | (0x2 << CP0C0_AR) | (0x2 << CP0C0_AT) |
                       (MMU_TYPE_R4000 << CP0C0_MT),
        MIPS_CONFIG1 | (1 << CP0C1_FP) | (63 << CP0C1_MMU) |
                       (2 << CP0C1_IS) | (4 << CP0C1_IL) | (3 << CP0C1_IA) |
                       (2 << CP0C1_DS) | (4 << CP0C1_DL) | (3 << CP0C1_DA) |
                       (0 << CP0C1_PC) | (1 << CP0C1_WR) | (1 << CP0C1_EP),
        MIPS_CONFIG2,
        MIPS_CONFIG3 | (1 << CP0C3_RXI) | (1 << CP0C3_BP) |
                       (1 << CP0C3_BI) | (1 << CP0C3_ULRI) | (1U << CP0C3_M),
        MIPS_CONFIG4 | (0xfc << CP0C4_KScrExist) |
                       (3 << CP0C4_IE) | (1 << CP0C4_M),
        0,
        0,
        (1 << CP0C5_SBRI),
        0,
        0,
        0,
        0,
        32,
        2,
        0x30D8FFFF,
        0,
        0,
        (1 << FCR0_F64) | (1 << FCR0_L) | (1 << FCR0_W) |
                    (1 << FCR0_D) | (1 << FCR0_S) | (0x00 << FCR0_PRID) |
                    (0x0 << FCR0_REV),
        0,
        42,
        /* The architectural limit is 59, but we have hardcoded 36 bit
           in some places...
        59, */ /* the architectural limit */
        36,
        0,0, 0,0, 0,0, 0,0, 0,0,
        (1 << CP0PG_IEC) | (1 << CP0PG_XIE) |
                         (1U << CP0PG_RIE),
        0,
        CPU_MIPS64R6,
        MMU_TYPE_R4000,
    },
    {
        "Loongson-2E",
        0x6302,
        /*64KB I-cache and d-cache. 4 way with 32 bit cache line size*/
        (0x1<<17) | (0x1<<16) | (0x1<<11) | (0x1<<8) | (0x1<<5) |
                       (0x1<<4) | (0x1<<1),
        /* Note: Config1 is only used internally, Loongson-2E has only Config0. */
        (1 << CP0C1_FP) | (47 << CP0C1_MMU),
        0,
        0,
        0,0,
        0,0,
        0,
        0,
        0,
        0,
        16,
        2,
        0x35D0FFFF,
        0,
        0,
        (0x5 << FCR0_PRID) | (0x1 << FCR0_REV),
        0,
        40,
        40,
        0,0, 0,0, 0,0, 0,0, 0,0, 0,0,
        CPU_LOONGSON2E,
        MMU_TYPE_R4000,
    },
    {
      "Loongson-2F",
      0x6303,
      /*64KB I-cache and d-cache. 4 way with 32 bit cache line size*/
      (0x1<<17) | (0x1<<16) | (0x1<<11) | (0x1<<8) | (0x1<<5) |
                     (0x1<<4) | (0x1<<1),
      /* Note: Config1 is only used internally, Loongson-2F has only Config0. */
      (1 << CP0C1_FP) | (47 << CP0C1_MMU),
      0,
      0,
      0,0,
      0,0,
      0,
      0,
      0,
      0,
      16,
      2,
      0xF5D0FF1F,   /*bit5:7 not writable*/
      0,
      0,
      (0x5 << FCR0_PRID) | (0x1 << FCR0_REV),
      0,
      40,
      40,
      0,0, 0,0, 0,0, 0,0, 0,0, 0,0,
      CPU_LOONGSON2F,
      MMU_TYPE_R4000,
    },
    {
        /* A generic CPU providing MIPS64 ASE DSP 2 features.
           FIXME: Eventually this should be replaced by a real CPU model. */
        "mips64dspr2",
        0x00010000,
        MIPS_CONFIG0 | (0x1 << CP0C0_AR) | (0x2 << CP0C0_AT) |
                       (MMU_TYPE_R4000 << CP0C0_MT),
        MIPS_CONFIG1 | (1 << CP0C1_FP) | (63 << CP0C1_MMU) |
                       (2 << CP0C1_IS) | (4 << CP0C1_IL) | (3 << CP0C1_IA) |
                       (2 << CP0C1_DS) | (4 << CP0C1_DL) | (3 << CP0C1_DA) |
                       (1 << CP0C1_PC) | (1 << CP0C1_WR) | (1 << CP0C1_EP),
        MIPS_CONFIG2,
        MIPS_CONFIG3 | (1U << CP0C3_M) | (1 << CP0C3_DSP2P) |
                       (1 << CP0C3_DSPP) | (1 << CP0C3_LPA),
        0,0,
        0,0,
        0,
        0,
        0,
        0,
        32,
        2,
        0x37FBFFFF,
        0,
        0,
        (1 << FCR0_F64) | (1 << FCR0_3D) | (1 << FCR0_PS) |
                    (1 << FCR0_L) | (1 << FCR0_W) | (1 << FCR0_D) |
                    (1 << FCR0_S) | (0x00 << FCR0_PRID) | (0x0 << FCR0_REV),
        0,
        42,
        /* The architectural limit is 59, but we have hardcoded 36 bit
           in some places...
        59, */ /* the architectural limit */
        36,
        0,0, 0,0, 0,0, 0,0, 0,0, 0,0,
        CPU_MIPS64R2 | ASE_DSP | ASE_DSPR2,
        MMU_TYPE_R4000,
    },
    
#endif
};

static const mips_def_t *cpu_mips_find_by_name (const char *name)
{
    int i;

    for (i = 0; i < ARRAY_SIZE(mips_defs); i++) {
        if (strcasecmp(name, mips_defs[i].name) == 0) {
            return &mips_defs[i];
        }
    }
    return NULL;
}

void mips_cpu_list (FILE *f, fprintf_function cpu_fprintf)
{
    int i;

    for (i = 0; i < ARRAY_SIZE(mips_defs); i++) {
        (*cpu_fprintf)(f, "MIPS '%s'\n",
                       mips_defs[i].name);
    }
}

#ifndef CONFIG_USER_ONLY
static void no_mmu_init (CPUMIPSState *env, const mips_def_t *def)
{
    env->tlb->nb_tlb = 1;
    env->tlb->map_address = &no_mmu_map_address;
}

static void fixed_mmu_init (CPUMIPSState *env, const mips_def_t *def)
{
    env->tlb->nb_tlb = 1;
    env->tlb->map_address = &fixed_mmu_map_address;
}

static void r4k_mmu_init (CPUMIPSState *env, const mips_def_t *def)
{
    env->tlb->nb_tlb = 1 + ((def->CP0_Config1 >> CP0C1_MMU) & 63);
    env->tlb->map_address = &r4k_map_address;
    env->tlb->helper_tlbwi = r4k_helper_tlbwi;
    env->tlb->helper_tlbwr = r4k_helper_tlbwr;
    env->tlb->helper_tlbp = r4k_helper_tlbp;
    env->tlb->helper_tlbr = r4k_helper_tlbr;
    env->tlb->helper_tlbinv = r4k_helper_tlbinv;
    env->tlb->helper_tlbinvf = r4k_helper_tlbinvf;
}

static void mmu_init (CPUMIPSState *env, const mips_def_t *def)
{
    MIPSCPU *cpu = mips_env_get_cpu(env);

    env->tlb = g_malloc0(sizeof(CPUMIPSTLBContext));

    switch (def->mmu_type) {
        case MMU_TYPE_NONE:
            no_mmu_init(env, def);
            break;
        case MMU_TYPE_R4000:
            r4k_mmu_init(env, def);
            break;
        case MMU_TYPE_FMT:
            fixed_mmu_init(env, def);
            break;
        case MMU_TYPE_R3000:
        case MMU_TYPE_R6000:
        case MMU_TYPE_R8000:
        default:
            cpu_abort(CPU(cpu), "MMU type not supported\n");
    }
}
#endif /* CONFIG_USER_ONLY */

static void fpu_init (CPUMIPSState *env, const mips_def_t *def)
{
    int i;

    for (i = 0; i < MIPS_FPU_MAX; i++)
        env->fpus[i].fcr0 = def->CP1_fcr0;

    memcpy(&env->active_fpu, &env->fpus[0], sizeof(env->active_fpu));
}

static void mvp_init (CPUMIPSState *env, const mips_def_t *def)
{
    env->mvp = g_malloc0(sizeof(CPUMIPSMVPContext));

    /* MVPConf1 implemented, TLB sharable, no gating storage support,
       programmable cache partitioning implemented, number of allocatable
       and sharable TLB entries, MVP has allocatable TCs, 2 VPEs
       implemented, 5 TCs implemented. */
    env->mvp->CP0_MVPConf0 = (1U << CP0MVPC0_M) | (1 << CP0MVPC0_TLBS) |
                             (0 << CP0MVPC0_GS) | (1 << CP0MVPC0_PCP) |
// TODO: actually do 2 VPEs.
//                             (1 << CP0MVPC0_TCA) | (0x1 << CP0MVPC0_PVPE) |
//                             (0x04 << CP0MVPC0_PTC);
                             (1 << CP0MVPC0_TCA) | (0x0 << CP0MVPC0_PVPE) |
                             (0x00 << CP0MVPC0_PTC);
#if !defined(CONFIG_USER_ONLY)
    /* Usermode has no TLB support */
    env->mvp->CP0_MVPConf0 |= (env->tlb->nb_tlb << CP0MVPC0_PTLBE);
#endif

    /* Allocatable CP1 have media extensions, allocatable CP1 have FP support,
       no UDI implemented, no CP2 implemented, 1 CP1 implemented. */
    env->mvp->CP0_MVPConf1 = (1U << CP0MVPC1_CIM) | (1 << CP0MVPC1_CIF) |
                             (0x0 << CP0MVPC1_PCX) | (0x0 << CP0MVPC1_PCP2) |
                             (0x1 << CP0MVPC1_PCP1);
}

static void msa_reset(CPUMIPSState *env)
{
#ifdef CONFIG_USER_ONLY
    /* MSA access enabled */
    env->CP0_Config5 |= 1 << CP0C5_MSAEn;
    env->CP0_Status |= (1 << CP0St_CU1) | (1 << CP0St_FR);
#endif

    /* MSA CSR:
       - non-signaling floating point exception mode off (NX bit is 0)
       - Cause, Enables, and Flags are all 0
       - round to nearest / ties to even (RM bits are 0) */
    env->active_tc.msacsr = 0;

    /* tininess detected after rounding.*/
    set_float_detect_tininess(float_tininess_after_rounding,
                              &env->active_tc.msa_fp_status);

    /* clear float_status exception flags */
    set_float_exception_flags(0, &env->active_tc.msa_fp_status);

    /* set float_status rounding mode */
    set_float_rounding_mode(float_round_nearest_even,
                            &env->active_tc.msa_fp_status);

    /* set float_status flush modes */
    set_flush_to_zero(0, &env->active_tc.msa_fp_status);
    set_flush_inputs_to_zero(0, &env->active_tc.msa_fp_status);

    /* clear float_status nan mode */
    set_default_nan_mode(0, &env->active_tc.msa_fp_status);
}
