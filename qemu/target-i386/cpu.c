/*
 *  i386 CPUID helper functions
 *
 *  Copyright (c) 2003 Fabrice Bellard
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
/* Modified for Unicorn Engine by Chen Huitao<chenhuitao@hfmrit.com>, 2020 */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "unicorn/platform.h"
#include "cpu.h"
#include "sysemu/cpus.h"
#include "topology.h"
#include "sysemu/sysemu.h"
#include "uc_priv.h"

/* Cache topology CPUID constants: */

/* CPUID Leaf 2 Descriptors */

#define CPUID_2_L1D_32KB_8WAY_64B 0x2c
#define CPUID_2_L1I_32KB_8WAY_64B 0x30
#define CPUID_2_L2_2MB_8WAY_64B   0x7d


/* CPUID Leaf 4 constants: */

/* EAX: */
#define CPUID_4_TYPE_DCACHE  1
#define CPUID_4_TYPE_ICACHE  2
#define CPUID_4_TYPE_UNIFIED 3

#define CPUID_4_LEVEL(l)          ((l) << 5)

#define CPUID_4_SELF_INIT_LEVEL (1 << 8)
#define CPUID_4_FULLY_ASSOC     (1 << 9)

/* EDX: */
#define CPUID_4_NO_INVD_SHARING (1 << 0)
#define CPUID_4_INCLUSIVE       (1 << 1)
#define CPUID_4_COMPLEX_IDX     (1 << 2)

#define ASSOC_FULL 0xFF

/* AMD associativity encoding used on CPUID Leaf 0x80000006: */
#define AMD_ENC_ASSOC(a) (a <=   1 ? a   : \
                          a ==   2 ? 0x2 : \
                          a ==   4 ? 0x4 : \
                          a ==   8 ? 0x6 : \
                          a ==  16 ? 0x8 : \
                          a ==  32 ? 0xA : \
                          a ==  48 ? 0xB : \
                          a ==  64 ? 0xC : \
                          a ==  96 ? 0xD : \
                          a == 128 ? 0xE : \
                          a == ASSOC_FULL ? 0xF : \
                          0 /* invalid value */)


/* Definitions of the hardcoded cache entries we expose: */

/* L1 data cache: */
#define L1D_LINE_SIZE         64
#define L1D_ASSOCIATIVITY      8
#define L1D_SETS              64
#define L1D_PARTITIONS         1
/* Size = LINE_SIZE*ASSOCIATIVITY*SETS*PARTITIONS = 32KiB */
#define L1D_DESCRIPTOR CPUID_2_L1D_32KB_8WAY_64B
/*FIXME: CPUID leaf 0x80000005 is inconsistent with leaves 2 & 4 */
#define L1D_LINES_PER_TAG      1
#define L1D_SIZE_KB_AMD       64
#define L1D_ASSOCIATIVITY_AMD  2

/* L1 instruction cache: */
#define L1I_LINE_SIZE         64
#define L1I_ASSOCIATIVITY      8
#define L1I_SETS              64
#define L1I_PARTITIONS         1
/* Size = LINE_SIZE*ASSOCIATIVITY*SETS*PARTITIONS = 32KiB */
#define L1I_DESCRIPTOR CPUID_2_L1I_32KB_8WAY_64B
/*FIXME: CPUID leaf 0x80000005 is inconsistent with leaves 2 & 4 */
#define L1I_LINES_PER_TAG      1
#define L1I_SIZE_KB_AMD       64
#define L1I_ASSOCIATIVITY_AMD  2

/* Level 2 unified cache: */
#define L2_LINE_SIZE          64
#define L2_ASSOCIATIVITY      16
#define L2_SETS             4096
#define L2_PARTITIONS          1
/* Size = LINE_SIZE*ASSOCIATIVITY*SETS*PARTITIONS = 4MiB */
/*FIXME: CPUID leaf 2 descriptor is inconsistent with CPUID leaf 4 */
#define L2_DESCRIPTOR CPUID_2_L2_2MB_8WAY_64B
/*FIXME: CPUID leaf 0x80000006 is inconsistent with leaves 2 & 4 */
#define L2_LINES_PER_TAG       1
#define L2_SIZE_KB_AMD       512

/* No L3 cache: */
#define L3_SIZE_KB             0 /* disabled */
#define L3_ASSOCIATIVITY       0 /* disabled */
#define L3_LINES_PER_TAG       0 /* disabled */
#define L3_LINE_SIZE           0 /* disabled */

/* TLB definitions: */

#define L1_DTLB_2M_ASSOC       1
#define L1_DTLB_2M_ENTRIES   255
#define L1_DTLB_4K_ASSOC       1
#define L1_DTLB_4K_ENTRIES   255

#define L1_ITLB_2M_ASSOC       1
#define L1_ITLB_2M_ENTRIES   255
#define L1_ITLB_4K_ASSOC       1
#define L1_ITLB_4K_ENTRIES   255

#define L2_DTLB_2M_ASSOC       0 /* disabled */
#define L2_DTLB_2M_ENTRIES     0 /* disabled */
#define L2_DTLB_4K_ASSOC       4
#define L2_DTLB_4K_ENTRIES   512

#define L2_ITLB_2M_ASSOC       0 /* disabled */
#define L2_ITLB_2M_ENTRIES     0 /* disabled */
#define L2_ITLB_4K_ASSOC       4
#define L2_ITLB_4K_ENTRIES   512


/* feature flags taken from "Intel Processor Identification and the CPUID
 * Instruction" and AMD's "CPUID Specification".  In cases of disagreement
 * between feature naming conventions, aliases may be added.
 */
static const char *feature_name[] = {
    "fpu", "vme", "de", "pse",
    "tsc", "msr", "pae", "mce",
    "cx8", "apic", NULL, "sep",
    "mtrr", "pge", "mca", "cmov",
    "pat", "pse36", "pn" /* Intel psn */, "clflush" /* Intel clfsh */,
    NULL, "ds" /* Intel dts */, "acpi", "mmx",
    "fxsr", "sse", "sse2", "ss",
    "ht" /* Intel htt */, "tm", "ia64", "pbe",
};
static const char *ext_feature_name[] = {
    "pni|sse3" /* Intel,AMD sse3 */, "pclmulqdq|pclmuldq", "dtes64", "monitor",
    "ds_cpl", "vmx", "smx", "est",
    "tm2", "ssse3", "cid", NULL,
    "fma", "cx16", "xtpr", "pdcm",
    NULL, "pcid", "dca", "sse4.1|sse4_1",
    "sse4.2|sse4_2", "x2apic", "movbe", "popcnt",
    "tsc-deadline", "aes", "xsave", "osxsave",
    "avx", "f16c", "rdrand", "hypervisor",
};
/* Feature names that are already defined on feature_name[] but are set on
 * CPUID[8000_0001].EDX on AMD CPUs don't have their names on
 * ext2_feature_name[]. They are copied automatically to cpuid_ext2_features
 * if and only if CPU vendor is AMD.
 */
static const char *ext2_feature_name[] = {
    NULL /* fpu */, NULL /* vme */, NULL /* de */, NULL /* pse */,
    NULL /* tsc */, NULL /* msr */, NULL /* pae */, NULL /* mce */,
    NULL /* cx8 */ /* AMD CMPXCHG8B */, NULL /* apic */, NULL, "syscall",
    NULL /* mtrr */, NULL /* pge */, NULL /* mca */, NULL /* cmov */,
    NULL /* pat */, NULL /* pse36 */, NULL, NULL /* Linux mp */,
    "nx|xd", NULL, "mmxext", NULL /* mmx */,
    NULL /* fxsr */, "fxsr_opt|ffxsr", "pdpe1gb" /* AMD Page1GB */, "rdtscp",
    NULL, "lm|i64", "3dnowext", "3dnow",
};
static const char *ext3_feature_name[] = {
    "lahf_lm" /* AMD LahfSahf */, "cmp_legacy", "svm", "extapic" /* AMD ExtApicSpace */,
    "cr8legacy" /* AMD AltMovCr8 */, "abm", "sse4a", "misalignsse",
    "3dnowprefetch", "osvw", "ibs", "xop",
    "skinit", "wdt", NULL, "lwp",
    "fma4", "tce", NULL, "nodeid_msr",
    NULL, "tbm", "topoext", "perfctr_core",
    "perfctr_nb", NULL, NULL, NULL,
    NULL, NULL, NULL, NULL,
};

static const char *ext4_feature_name[] = {
    NULL, NULL, "xstore", "xstore-en",
    NULL, NULL, "xcrypt", "xcrypt-en",
    "ace2", "ace2-en", "phe", "phe-en",
    "pmm", "pmm-en", NULL, NULL,
    NULL, NULL, NULL, NULL,
    NULL, NULL, NULL, NULL,
    NULL, NULL, NULL, NULL,
    NULL, NULL, NULL, NULL,
};

static const char *cpuid_7_0_ebx_feature_name[] = {
    "fsgsbase", "tsc_adjust", NULL, "bmi1", "hle", "avx2", NULL, "smep",
    "bmi2", "erms", "invpcid", "rtm", NULL, NULL, "mpx", NULL,
    "avx512f", NULL, "rdseed", "adx", "smap", NULL, NULL, NULL,
    NULL, NULL, "avx512pf", "avx512er", "avx512cd", NULL, NULL, NULL,
};

static const char *cpuid_apm_edx_feature_name[] = {
    NULL, NULL, NULL, NULL,
    NULL, NULL, NULL, NULL,
    "invtsc", NULL, NULL, NULL,
    NULL, NULL, NULL, NULL,
    NULL, NULL, NULL, NULL,
    NULL, NULL, NULL, NULL,
    NULL, NULL, NULL, NULL,
    NULL, NULL, NULL, NULL,
};

#define I486_FEATURES (CPUID_FP87 | CPUID_VME | CPUID_PSE)
#define PENTIUM_FEATURES (I486_FEATURES | CPUID_DE | CPUID_TSC | \
          CPUID_MSR | CPUID_MCE | CPUID_CX8 | CPUID_MMX | CPUID_APIC)
#define PENTIUM2_FEATURES (PENTIUM_FEATURES | CPUID_PAE | CPUID_SEP | \
          CPUID_MTRR | CPUID_PGE | CPUID_MCA | CPUID_CMOV | CPUID_PAT | \
          CPUID_PSE36 | CPUID_FXSR)
#define PENTIUM3_FEATURES (PENTIUM2_FEATURES | CPUID_SSE)
#define PPRO_FEATURES (CPUID_FP87 | CPUID_DE | CPUID_PSE | CPUID_TSC | \
          CPUID_MSR | CPUID_MCE | CPUID_CX8 | CPUID_PGE | CPUID_CMOV | \
          CPUID_PAT | CPUID_FXSR | CPUID_MMX | CPUID_SSE | CPUID_SSE2 | \
          CPUID_PAE | CPUID_SEP | CPUID_APIC)

#define TCG_FEATURES (CPUID_FP87 | CPUID_PSE | CPUID_TSC | CPUID_MSR | \
          CPUID_PAE | CPUID_MCE | CPUID_CX8 | CPUID_APIC | CPUID_SEP | \
          CPUID_MTRR | CPUID_PGE | CPUID_MCA | CPUID_CMOV | CPUID_PAT | \
          CPUID_PSE36 | CPUID_CLFLUSH | CPUID_ACPI | CPUID_MMX | \
          CPUID_FXSR | CPUID_SSE | CPUID_SSE2 | CPUID_SS)
          /* partly implemented:
          CPUID_MTRR, CPUID_MCA, CPUID_CLFLUSH (needed for Win64) */
          /* missing:
          CPUID_VME, CPUID_DTS, CPUID_SS, CPUID_HT, CPUID_TM, CPUID_PBE */
#define TCG_EXT_FEATURES (CPUID_EXT_SSE3 | CPUID_EXT_PCLMULQDQ | \
          CPUID_EXT_MONITOR | CPUID_EXT_SSSE3 | CPUID_EXT_CX16 | \
          CPUID_EXT_SSE41 | CPUID_EXT_SSE42 | CPUID_EXT_POPCNT | \
          CPUID_EXT_MOVBE | CPUID_EXT_AES | CPUID_EXT_HYPERVISOR)
          /* missing:
          CPUID_EXT_DTES64, CPUID_EXT_DSCPL, CPUID_EXT_VMX, CPUID_EXT_SMX,
          CPUID_EXT_EST, CPUID_EXT_TM2, CPUID_EXT_CID, CPUID_EXT_FMA,
          CPUID_EXT_XTPR, CPUID_EXT_PDCM, CPUID_EXT_PCID, CPUID_EXT_DCA,
          CPUID_EXT_X2APIC, CPUID_EXT_TSC_DEADLINE_TIMER, CPUID_EXT_XSAVE,
          CPUID_EXT_OSXSAVE, CPUID_EXT_AVX, CPUID_EXT_F16C,
          CPUID_EXT_RDRAND */

#ifdef TARGET_X86_64
#define TCG_EXT2_X86_64_FEATURES (CPUID_EXT2_SYSCALL | CPUID_EXT2_LM)
#else
#define TCG_EXT2_X86_64_FEATURES 0
#endif

#define TCG_EXT2_FEATURES ((TCG_FEATURES & CPUID_EXT2_AMD_ALIASES) | \
          CPUID_EXT2_NX | CPUID_EXT2_MMXEXT | CPUID_EXT2_RDTSCP | \
          CPUID_EXT2_3DNOW | CPUID_EXT2_3DNOWEXT | CPUID_EXT2_PDPE1GB | \
          TCG_EXT2_X86_64_FEATURES)
#define TCG_EXT3_FEATURES (CPUID_EXT3_LAHF_LM | CPUID_EXT3_SVM | \
          CPUID_EXT3_CR8LEG | CPUID_EXT3_ABM | CPUID_EXT3_SSE4A)
#define TCG_EXT4_FEATURES 0
#define TCG_SVM_FEATURES 0
#define TCG_KVM_FEATURES 0
#define TCG_7_0_EBX_FEATURES (CPUID_7_0_EBX_SMEP | CPUID_7_0_EBX_SMAP | \
          CPUID_7_0_EBX_BMI1 | CPUID_7_0_EBX_BMI2 | CPUID_7_0_EBX_ADX)
          /* missing:
          CPUID_7_0_EBX_FSGSBASE, CPUID_7_0_EBX_HLE, CPUID_7_0_EBX_AVX2,
          CPUID_7_0_EBX_ERMS, CPUID_7_0_EBX_INVPCID, CPUID_7_0_EBX_RTM,
          CPUID_7_0_EBX_RDSEED */
#define TCG_APM_FEATURES 0


typedef struct FeatureWordInfo {
    const char **feat_names;
    uint32_t cpuid_eax;   /* Input EAX for CPUID */
    bool cpuid_needs_ecx; /* CPUID instruction uses ECX as input */
    uint32_t cpuid_ecx;   /* Input ECX value for CPUID */
    int cpuid_reg;        /* output register (R_* constant) */
    uint32_t tcg_features; /* Feature flags supported by TCG */
    uint32_t unmigratable_flags; /* Feature flags known to be unmigratable */
} FeatureWordInfo;

static FeatureWordInfo feature_word_info[FEATURE_WORDS] = {
#ifdef _MSC_VER
    // FEAT_1_EDX
    {
        feature_name,
        1,
        false,0,
        R_EDX,
        TCG_FEATURES,
    },
    // FEAT_1_ECX
    {
        ext_feature_name,
        1,
        false,0,
        R_ECX,
        TCG_EXT_FEATURES,
    },
    // FEAT_7_0_EBX
    {
        cpuid_7_0_ebx_feature_name,
        7,
        true, 0,
        R_EBX,
        TCG_7_0_EBX_FEATURES,
    },
    // FEAT_8000_0001_EDX
    {
        ext2_feature_name,
        0x80000001,
        false,0,
        R_EDX,
        TCG_EXT2_FEATURES,
    },
    // FEAT_8000_0001_ECX
    {
        ext3_feature_name,
        0x80000001,
        false,0,
        R_ECX,
        TCG_EXT3_FEATURES,
    },
    // FEAT_8000_0007_EDX
    {
        cpuid_apm_edx_feature_name,
        0x80000007,
        false,0,
        R_EDX,
        TCG_APM_FEATURES,
        CPUID_APM_INVTSC,
    },
    // FEAT_C000_0001_EDX
    {
        ext4_feature_name,
        0xC0000001,
        false,0,
        R_EDX,
        TCG_EXT4_FEATURES,
    },
    // FEAT_KVM
    {0},
    // FEAT_SVM
    {0},
#else
    [FEAT_1_EDX] = {
        .feat_names = feature_name,
        .cpuid_eax = 1, .cpuid_reg = R_EDX,
        .tcg_features = TCG_FEATURES,
    },
    [FEAT_1_ECX] = {
        .feat_names = ext_feature_name,
        .cpuid_eax = 1, .cpuid_reg = R_ECX,
        .tcg_features = TCG_EXT_FEATURES,
    },
    [FEAT_8000_0001_EDX] = {
        .feat_names = ext2_feature_name,
        .cpuid_eax = 0x80000001, .cpuid_reg = R_EDX,
        .tcg_features = TCG_EXT2_FEATURES,
    },
    [FEAT_8000_0001_ECX] = {
        .feat_names = ext3_feature_name,
        .cpuid_eax = 0x80000001, .cpuid_reg = R_ECX,
        .tcg_features = TCG_EXT3_FEATURES,
    },
    [FEAT_C000_0001_EDX] = {
        .feat_names = ext4_feature_name,
        .cpuid_eax = 0xC0000001, .cpuid_reg = R_EDX,
        .tcg_features = TCG_EXT4_FEATURES,
    },
    [FEAT_7_0_EBX] = {
        .feat_names = cpuid_7_0_ebx_feature_name,
        .cpuid_eax = 7,
        .cpuid_needs_ecx = true, .cpuid_ecx = 0,
        .cpuid_reg = R_EBX,
        .tcg_features = TCG_7_0_EBX_FEATURES,
    },
    [FEAT_8000_0007_EDX] = {
        .feat_names = cpuid_apm_edx_feature_name,
        .cpuid_eax = 0x80000007,
        .cpuid_reg = R_EDX,
        .tcg_features = TCG_APM_FEATURES,
        .unmigratable_flags = CPUID_APM_INVTSC,
    },
#endif
};

typedef enum X86CPURegister32
{
    X86_CPU_REGISTER32_EAX = 0,
    X86_CPU_REGISTER32_EBX = 1,
    X86_CPU_REGISTER32_ECX = 2,
    X86_CPU_REGISTER32_EDX = 3,
    X86_CPU_REGISTER32_ESP = 4,
    X86_CPU_REGISTER32_EBP = 5,
    X86_CPU_REGISTER32_ESI = 6,
    X86_CPU_REGISTER32_EDI = 7,
    X86_CPU_REGISTER32_MAX = 8,
} X86CPURegister32;

typedef struct X86RegisterInfo32 {
    /* Name of register */
    const char *name;
    /* QAPI enum value register */
    X86CPURegister32 qapi_enum;
} X86RegisterInfo32;

#define REGISTER(reg) \
    { #reg, X86_CPU_REGISTER32_##reg }
static const X86RegisterInfo32 x86_reg_info_32[CPU_NB_REGS32] = {
    REGISTER(EAX),
    REGISTER(ECX),
    REGISTER(EDX),
    REGISTER(EBX),
    REGISTER(ESP),
    REGISTER(EBP),
    REGISTER(ESI),
    REGISTER(EDI),
};
#undef REGISTER

typedef struct ExtSaveArea {
    uint32_t feature, bits;
    uint32_t offset, size;
} ExtSaveArea;

const char *get_register_name_32(unsigned int reg)
{
    if (reg >= CPU_NB_REGS32) {
        return NULL;
    }
    return x86_reg_info_32[reg].name;
}

#ifdef _MSC_VER
#include <intrin.h>
#endif

void host_cpuid(uint32_t function, uint32_t count,
                uint32_t *eax, uint32_t *ebx, uint32_t *ecx, uint32_t *edx)
{
    uint32_t vec[4];

#ifdef _MSC_VER
    __cpuidex((int*)vec, function, count);
#else
#ifdef __x86_64__
    asm volatile("cpuid"
                 : "=a"(vec[0]), "=b"(vec[1]),
                   "=c"(vec[2]), "=d"(vec[3])
                 : "0"(function), "c"(count) : "cc");
#elif defined(__i386__)
    asm volatile("pusha \n\t"
                 "cpuid \n\t"
                 "mov %%eax, 0(%2) \n\t"
                 "mov %%ebx, 4(%2) \n\t"
                 "mov %%ecx, 8(%2) \n\t"
                 "mov %%edx, 12(%2) \n\t"
                 "popa"
                 : : "a"(function), "c"(count), "S"(vec)
                 : "memory", "cc");
#else
    abort();
#endif
#endif // _MSC_VER

    if (eax)
        *eax = vec[0];
    if (ebx)
        *ebx = vec[1];
    if (ecx)
        *ecx = vec[2];
    if (edx)
        *edx = vec[3];
}

#define iswhite(c) ((c) && ((c) <= ' ' || '~' < (c)))

/* general substring compare of *[s1..e1) and *[s2..e2).  sx is start of
 * a substring.  ex if !NULL points to the first char after a substring,
 * otherwise the string is assumed to sized by a terminating nul.
 * Return lexical ordering of *s1:*s2.
 */
static int sstrcmp(const char *s1, const char *e1,
                   const char *s2, const char *e2)
{
    for (;;) {
        if (!*s1 || !*s2 || *s1 != *s2)
            return (*s1 - *s2);
        ++s1, ++s2;
        if (s1 == e1 && s2 == e2)
            return (0);
        else if (s1 == e1)
            return (*s2);
        else if (s2 == e2)
            return (*s1);
    }
}

/* compare *[s..e) to *altstr.  *altstr may be a simple string or multiple
 * '|' delimited (possibly empty) strings in which case search for a match
 * within the alternatives proceeds left to right.  Return 0 for success,
 * non-zero otherwise.
 */
static int altcmp(const char *s, const char *e, const char *altstr)
{
    const char *p, *q;

    for (q = p = altstr; ; ) {
        while (*p && *p != '|')
            ++p;
        if ((q == p && !*s) || (q != p && !sstrcmp(s, e, q, p)))
            return (0);
        if (!*p)
            return (1);
        else
            q = ++p;
    }
}

/* search featureset for flag *[s..e), if found set corresponding bit in
 * *pval and return true, otherwise return false
 */
static bool lookup_feature(uint32_t *pval, const char *s, const char *e,
                           const char **featureset)
{
    uint32_t mask;
    const char **ppc;
    bool found = false;

    for (mask = 1, ppc = featureset; mask; mask <<= 1, ++ppc) {
        if (*ppc && !altcmp(s, e, *ppc)) {
            *pval |= mask;
            found = true;
        }
    }
    return found;
}

static void add_flagname_to_bitmaps(const char *flagname,
                                    FeatureWordArray words)
{
    FeatureWord w;
    for (w = 0; w < FEATURE_WORDS; w++) {
        FeatureWordInfo *wi = &feature_word_info[w];
        if (wi->feat_names &&
            lookup_feature(&words[w], flagname, NULL, wi->feat_names)) {
            break;
        }
    }
}

struct X86CPUDefinition {
    const char *name;
    uint32_t level;
    uint32_t xlevel;
    uint32_t xlevel2;
    /* vendor is zero-terminated, 12 character ASCII string */
    char vendor[CPUID_VENDOR_SZ + 1];
    int family;
    int model;
    int stepping;
    FeatureWordArray features;
    char model_id[48];
    bool cache_info_passthrough;
};

static X86CPUDefinition builtin_x86_defs[] = {
    {
        "qemu64",
        4, 0x8000000A, 0,
        CPUID_VENDOR_AMD,
        6, 6, 3,
        {
        // FEAT_1_EDX
            PPRO_FEATURES |
            CPUID_MTRR | CPUID_CLFLUSH | CPUID_MCA |
            CPUID_PSE36,
        // FEAT_1_ECX
            CPUID_EXT_SSE3 | CPUID_EXT_CX16 | CPUID_EXT_POPCNT,
        // FEAT_7_0_EBX
            0,
        // FEAT_8000_0001_EDX
            (PPRO_FEATURES & CPUID_EXT2_AMD_ALIASES) |
            CPUID_EXT2_LM | CPUID_EXT2_SYSCALL | CPUID_EXT2_NX,
        // FEAT_8000_0001_ECX
            CPUID_EXT3_LAHF_LM | CPUID_EXT3_SVM |
            CPUID_EXT3_ABM | CPUID_EXT3_SSE4A,
        },
    },
    {
        "phenom",
        5, 0x8000001A, 0,
        CPUID_VENDOR_AMD,
        16, 2, 3,
        {
        /* Missing: CPUID_HT */
        // FEAT_1_EDX
            PPRO_FEATURES |
            CPUID_MTRR | CPUID_CLFLUSH | CPUID_MCA |
            CPUID_PSE36 | CPUID_VME,
        // FEAT_1_ECX
            CPUID_EXT_SSE3 | CPUID_EXT_MONITOR | CPUID_EXT_CX16 |
            CPUID_EXT_POPCNT,
        // FEAT_7_0_EBX
            0,
        // FEAT_8000_0001_EDX
            (PPRO_FEATURES & CPUID_EXT2_AMD_ALIASES) |
            CPUID_EXT2_LM | CPUID_EXT2_SYSCALL | CPUID_EXT2_NX |
            CPUID_EXT2_3DNOW | CPUID_EXT2_3DNOWEXT | CPUID_EXT2_MMXEXT |
            CPUID_EXT2_FFXSR | CPUID_EXT2_PDPE1GB | CPUID_EXT2_RDTSCP,
        /* Missing: CPUID_EXT3_CMP_LEG, CPUID_EXT3_EXTAPIC,
                  CPUID_EXT3_CR8LEG,
                  CPUID_EXT3_MISALIGNSSE, CPUID_EXT3_3DNOWPREFETCH,
                  CPUID_EXT3_OSVW, CPUID_EXT3_IBS */
        // FEAT_8000_0001_ECX
            CPUID_EXT3_LAHF_LM | CPUID_EXT3_SVM |
            CPUID_EXT3_ABM | CPUID_EXT3_SSE4A,
        // FEAT_8000_0007_EDX
            0,
        // FEAT_C000_0001_EDX
            0,
        // FEAT_KVM
            0,
        /* Missing: CPUID_SVM_LBRV */
        // FEAT_SVM
            CPUID_SVM_NPT,
        },
        "AMD Phenom(tm) 9550 Quad-Core Processor",
    },
    {
        "core2duo",
        10, 0x80000008, 0,
        CPUID_VENDOR_INTEL,
        6, 15, 11,
        {
        /* Missing: CPUID_DTS, CPUID_HT, CPUID_TM, CPUID_PBE */
        // FEAT_1_EDX
            PPRO_FEATURES |
            CPUID_MTRR | CPUID_CLFLUSH | CPUID_MCA |
            CPUID_PSE36 | CPUID_VME | CPUID_ACPI | CPUID_SS,
        /* Missing: CPUID_EXT_DTES64, CPUID_EXT_DSCPL, CPUID_EXT_EST,
         * CPUID_EXT_TM2, CPUID_EXT_XTPR, CPUID_EXT_PDCM, CPUID_EXT_VMX */
        // FEAT_1_ECX
            CPUID_EXT_SSE3 | CPUID_EXT_MONITOR | CPUID_EXT_SSSE3 |
            CPUID_EXT_CX16,
        // FEAT_7_0_EBX
            0,
        // FEAT_8000_0001_EDX
            CPUID_EXT2_LM | CPUID_EXT2_SYSCALL | CPUID_EXT2_NX,
        // FEAT_8000_0001_ECX
            CPUID_EXT3_LAHF_LM,
        },
        "Intel(R) Core(TM)2 Duo CPU     T7700  @ 2.40GHz",
    },
    {
        "kvm64",
        5, 0x80000008, 0,
        CPUID_VENDOR_INTEL,
        15, 6, 1,
        {
        /* Missing: CPUID_VME, CPUID_HT */
        // FEAT_1_EDX
            PPRO_FEATURES |
            CPUID_MTRR | CPUID_CLFLUSH | CPUID_MCA |
            CPUID_PSE36,
        /* Missing: CPUID_EXT_POPCNT, CPUID_EXT_MONITOR */
        // FEAT_1_ECX
            CPUID_EXT_SSE3 | CPUID_EXT_CX16,
        // FEAT_7_0_EBX
            0,
        /* Missing: CPUID_EXT2_PDPE1GB, CPUID_EXT2_RDTSCP */
        // FEAT_8000_0001_EDX
            (PPRO_FEATURES & CPUID_EXT2_AMD_ALIASES) |
            CPUID_EXT2_LM | CPUID_EXT2_SYSCALL | CPUID_EXT2_NX,
        /* Missing: CPUID_EXT3_LAHF_LM, CPUID_EXT3_CMP_LEG, CPUID_EXT3_EXTAPIC,
                    CPUID_EXT3_CR8LEG, CPUID_EXT3_ABM, CPUID_EXT3_SSE4A,
                    CPUID_EXT3_MISALIGNSSE, CPUID_EXT3_3DNOWPREFETCH,
                    CPUID_EXT3_OSVW, CPUID_EXT3_IBS, CPUID_EXT3_SVM */
        // FEAT_8000_0001_ECX
            0,
        },
        "Common KVM processor",
    },
    {
        "qemu32",
        4, 0x80000004, 0,
        CPUID_VENDOR_INTEL,
        6, 6, 3,
        {
        // FEAT_1_EDX
            PPRO_FEATURES,
        // FEAT_1_ECX
            CPUID_EXT_SSE3 | CPUID_EXT_POPCNT,
        },
    },
    {
        "kvm32",
        5, 0x80000008, 0,
        CPUID_VENDOR_INTEL,
        15, 6, 1,
        {
        // FEAT_1_EDX
            PPRO_FEATURES |
            CPUID_MTRR | CPUID_CLFLUSH | CPUID_MCA | CPUID_PSE36,
        // FEAT_1_ECX
            CPUID_EXT_SSE3,
        // FEAT_7_0_EBX
            0,
        // FEAT_8000_0001_EDX
            PPRO_FEATURES & CPUID_EXT2_AMD_ALIASES,
        // FEAT_8000_0001_ECX
            0,
        },
        "Common 32-bit KVM processor",
    },
    {
        "coreduo",
        10, 0x80000008, 0,
        CPUID_VENDOR_INTEL,
        6, 14, 8,
        {
        /* Missing: CPUID_DTS, CPUID_HT, CPUID_TM, CPUID_PBE */
        // FEAT_1_EDX
            PPRO_FEATURES | CPUID_VME |
            CPUID_MTRR | CPUID_CLFLUSH | CPUID_MCA | CPUID_ACPI |
            CPUID_SS,
        /* Missing: CPUID_EXT_EST, CPUID_EXT_TM2 , CPUID_EXT_XTPR,
         * CPUID_EXT_PDCM, CPUID_EXT_VMX */
        // FEAT_1_ECX
            CPUID_EXT_SSE3 | CPUID_EXT_MONITOR,
        // FEAT_7_0_EBX
            0,
        // FEAT_8000_0001_EDX
            CPUID_EXT2_NX,
        },
        "Genuine Intel(R) CPU           T2600  @ 2.16GHz",
    },
    {
        "486",
        1, 0, 0,
        CPUID_VENDOR_INTEL,
        4, 8, 0,
        {
        // FEAT_1_EDX
            I486_FEATURES,
        },
    },
    {
        "pentium",
        1, 0, 0,
        CPUID_VENDOR_INTEL,
        5, 4, 3,
        {
        // FEAT_1_EDX
            PENTIUM_FEATURES,
        },
    },
    {
        "pentium2",
        2, 0, 0,
        CPUID_VENDOR_INTEL,
        6, 5, 2,
        {
        // FEAT_1_EDX
            PENTIUM2_FEATURES,
        },
    },
    {
        "pentium3",
        2, 0, 0,
        CPUID_VENDOR_INTEL,
        6, 7, 3,
        {
        // FEAT_1_EDX
            PENTIUM3_FEATURES,
        },
    },
    {
        "athlon",
        2, 0x80000008, 0,
        CPUID_VENDOR_AMD,
        6, 2, 3,
        {
        // FEAT_1_EDX
            PPRO_FEATURES | CPUID_PSE36 | CPUID_VME | CPUID_MTRR |
            CPUID_MCA,
        // FEAT_1_ECX
            0,
        // FEAT_7_0_EBX
            0,
        // FEAT_8000_0001_EDX
            (PPRO_FEATURES & CPUID_EXT2_AMD_ALIASES) |
            CPUID_EXT2_MMXEXT | CPUID_EXT2_3DNOW | CPUID_EXT2_3DNOWEXT,
        },
    },
    {
        "n270",
        /* original is on level 10 */
        5, 0x8000000A, 0,
        CPUID_VENDOR_INTEL,
        6, 28, 2,
        {
        /* Missing: CPUID_DTS, CPUID_HT, CPUID_TM, CPUID_PBE */
        // FEAT_1_EDX
            PPRO_FEATURES |
            CPUID_MTRR | CPUID_CLFLUSH | CPUID_MCA | CPUID_VME |
            CPUID_ACPI | CPUID_SS,
            /* Some CPUs got no CPUID_SEP */
        /* Missing: CPUID_EXT_DSCPL, CPUID_EXT_EST, CPUID_EXT_TM2,
         * CPUID_EXT_XTPR */
        // FEAT_1_ECX
            CPUID_EXT_SSE3 | CPUID_EXT_MONITOR | CPUID_EXT_SSSE3 |
            CPUID_EXT_MOVBE,
        // FEAT_7_0_EBX
            0,
        // FEAT_8000_0001_EDX
            (PPRO_FEATURES & CPUID_EXT2_AMD_ALIASES) |
            CPUID_EXT2_NX,
        // FEAT_8000_0001_ECX
            CPUID_EXT3_LAHF_LM,
        },
        "Intel(R) Atom(TM) CPU N270   @ 1.60GHz",
    },
    {
        "Conroe",
        4, 0x8000000A, 0,
        CPUID_VENDOR_INTEL,
        6, 15, 3,
        {
        // FEAT_1_EDX
            CPUID_SSE2 | CPUID_SSE | CPUID_FXSR | CPUID_MMX |
            CPUID_CLFLUSH | CPUID_PSE36 | CPUID_PAT | CPUID_CMOV | CPUID_MCA |
            CPUID_PGE | CPUID_MTRR | CPUID_SEP | CPUID_APIC | CPUID_CX8 |
            CPUID_MCE | CPUID_PAE | CPUID_MSR | CPUID_TSC | CPUID_PSE |
            CPUID_DE | CPUID_FP87,
        // FEAT_1_ECX
            CPUID_EXT_SSSE3 | CPUID_EXT_SSE3,
        // FEAT_7_0_EBX
            0,
        // FEAT_8000_0001_EDX
            CPUID_EXT2_LM | CPUID_EXT2_NX | CPUID_EXT2_SYSCALL,
        // FEAT_8000_0001_ECX
            CPUID_EXT3_LAHF_LM,
        },
        "Intel Celeron_4x0 (Conroe/Merom Class Core 2)",
    },
    {
        "Penryn",
        4, 0x8000000A, 0,
        CPUID_VENDOR_INTEL,
        6, 23, 3,
        {
        // FEAT_1_EDX
            CPUID_SSE2 | CPUID_SSE | CPUID_FXSR | CPUID_MMX |
            CPUID_CLFLUSH | CPUID_PSE36 | CPUID_PAT | CPUID_CMOV | CPUID_MCA |
            CPUID_PGE | CPUID_MTRR | CPUID_SEP | CPUID_APIC | CPUID_CX8 |
            CPUID_MCE | CPUID_PAE | CPUID_MSR | CPUID_TSC | CPUID_PSE |
            CPUID_DE | CPUID_FP87,
        // FEAT_1_ECX
            CPUID_EXT_SSE41 | CPUID_EXT_CX16 | CPUID_EXT_SSSE3 |
            CPUID_EXT_SSE3,
        // FEAT_7_0_EBX
            0,
        // FEAT_8000_0001_EDX
            CPUID_EXT2_LM | CPUID_EXT2_NX | CPUID_EXT2_SYSCALL,
        // FEAT_8000_0001_ECX
            CPUID_EXT3_LAHF_LM,
        },
        "Intel Core 2 Duo P9xxx (Penryn Class Core 2)",
    },
    {
        "Nehalem",
        4, 0x8000000A, 0,
        CPUID_VENDOR_INTEL,
        6, 26, 3,
        {
        // FEAT_1_EDX
            CPUID_SSE2 | CPUID_SSE | CPUID_FXSR | CPUID_MMX |
            CPUID_CLFLUSH | CPUID_PSE36 | CPUID_PAT | CPUID_CMOV | CPUID_MCA |
            CPUID_PGE | CPUID_MTRR | CPUID_SEP | CPUID_APIC | CPUID_CX8 |
            CPUID_MCE | CPUID_PAE | CPUID_MSR | CPUID_TSC | CPUID_PSE |
            CPUID_DE | CPUID_FP87,
        // FEAT_1_ECX
            CPUID_EXT_POPCNT | CPUID_EXT_SSE42 | CPUID_EXT_SSE41 |
            CPUID_EXT_CX16 | CPUID_EXT_SSSE3 | CPUID_EXT_SSE3,
        // FEAT_7_0_EBX
            0,
        // FEAT_8000_0001_EDX
            CPUID_EXT2_LM | CPUID_EXT2_SYSCALL | CPUID_EXT2_NX,
        // FEAT_8000_0001_ECX
            CPUID_EXT3_LAHF_LM,
        },
        "Intel Core i7 9xx (Nehalem Class Core i7)",
    },
    {
        "Westmere",
        11, 0x8000000A, 0,
        CPUID_VENDOR_INTEL,
        6, 44, 1,
        {
        // FEAT_1_EDX
            CPUID_SSE2 | CPUID_SSE | CPUID_FXSR | CPUID_MMX |
            CPUID_CLFLUSH | CPUID_PSE36 | CPUID_PAT | CPUID_CMOV | CPUID_MCA |
            CPUID_PGE | CPUID_MTRR | CPUID_SEP | CPUID_APIC | CPUID_CX8 |
            CPUID_MCE | CPUID_PAE | CPUID_MSR | CPUID_TSC | CPUID_PSE |
            CPUID_DE | CPUID_FP87,
        // FEAT_1_ECX
            CPUID_EXT_AES | CPUID_EXT_POPCNT | CPUID_EXT_SSE42 |
            CPUID_EXT_SSE41 | CPUID_EXT_CX16 | CPUID_EXT_SSSE3 |
            CPUID_EXT_PCLMULQDQ | CPUID_EXT_SSE3,
        // FEAT_7_0_EBX
            0,
        // FEAT_8000_0001_EDX
            CPUID_EXT2_LM | CPUID_EXT2_SYSCALL | CPUID_EXT2_NX,
        // FEAT_8000_0001_ECX
            CPUID_EXT3_LAHF_LM,
        },
        "Westmere E56xx/L56xx/X56xx (Nehalem-C)",
    },
    {
        "SandyBridge",
        0xd, 0x8000000A, 0,
        CPUID_VENDOR_INTEL,
        6, 42, 1,
        {
        // FEAT_1_EDX
            CPUID_SSE2 | CPUID_SSE | CPUID_FXSR | CPUID_MMX |
            CPUID_CLFLUSH | CPUID_PSE36 | CPUID_PAT | CPUID_CMOV | CPUID_MCA |
            CPUID_PGE | CPUID_MTRR | CPUID_SEP | CPUID_APIC | CPUID_CX8 |
            CPUID_MCE | CPUID_PAE | CPUID_MSR | CPUID_TSC | CPUID_PSE |
            CPUID_DE | CPUID_FP87,
        // FEAT_1_ECX
            CPUID_EXT_AVX | CPUID_EXT_XSAVE | CPUID_EXT_AES |
            CPUID_EXT_TSC_DEADLINE_TIMER | CPUID_EXT_POPCNT |
            CPUID_EXT_X2APIC | CPUID_EXT_SSE42 | CPUID_EXT_SSE41 |
            CPUID_EXT_CX16 | CPUID_EXT_SSSE3 | CPUID_EXT_PCLMULQDQ |
            CPUID_EXT_SSE3,
        // FEAT_7_0_EBX
            0,
        // FEAT_8000_0001_EDX
            CPUID_EXT2_LM | CPUID_EXT2_RDTSCP | CPUID_EXT2_NX |
            CPUID_EXT2_SYSCALL,
        // FEAT_8000_0001_ECX
            CPUID_EXT3_LAHF_LM,
        },
        "Intel Xeon E312xx (Sandy Bridge)",
    },
    {
        "Haswell",
        0xd, 0x8000000A, 0,
        CPUID_VENDOR_INTEL,
        6, 60, 1,
        {
        // FEAT_1_EDX
            CPUID_SSE2 | CPUID_SSE | CPUID_FXSR | CPUID_MMX |
            CPUID_CLFLUSH | CPUID_PSE36 | CPUID_PAT | CPUID_CMOV | CPUID_MCA |
            CPUID_PGE | CPUID_MTRR | CPUID_SEP | CPUID_APIC | CPUID_CX8 |
            CPUID_MCE | CPUID_PAE | CPUID_MSR | CPUID_TSC | CPUID_PSE |
            CPUID_DE | CPUID_FP87,
        // FEAT_1_ECX
            CPUID_EXT_AVX | CPUID_EXT_XSAVE | CPUID_EXT_AES |
            CPUID_EXT_POPCNT | CPUID_EXT_X2APIC | CPUID_EXT_SSE42 |
            CPUID_EXT_SSE41 | CPUID_EXT_CX16 | CPUID_EXT_SSSE3 |
            CPUID_EXT_PCLMULQDQ | CPUID_EXT_SSE3 |
            CPUID_EXT_TSC_DEADLINE_TIMER | CPUID_EXT_FMA | CPUID_EXT_MOVBE |
            CPUID_EXT_PCID,
        // FEAT_7_0_EBX
            CPUID_7_0_EBX_FSGSBASE | CPUID_7_0_EBX_BMI1 |
            CPUID_7_0_EBX_HLE | CPUID_7_0_EBX_AVX2 | CPUID_7_0_EBX_SMEP |
            CPUID_7_0_EBX_BMI2 | CPUID_7_0_EBX_ERMS | CPUID_7_0_EBX_INVPCID |
            CPUID_7_0_EBX_RTM,
        // FEAT_8000_0001_EDX
            CPUID_EXT2_LM | CPUID_EXT2_RDTSCP | CPUID_EXT2_NX |
            CPUID_EXT2_SYSCALL,
        // FEAT_8000_0001_ECX
            CPUID_EXT3_LAHF_LM,
        },
        "Intel Core Processor (Haswell)",
    },
    {
        "Broadwell",
        0xd, 0x8000000A, 0,
        CPUID_VENDOR_INTEL,
        6, 61, 2,
        {
        // FEAT_1_EDX
            CPUID_SSE2 | CPUID_SSE | CPUID_FXSR | CPUID_MMX |
            CPUID_CLFLUSH | CPUID_PSE36 | CPUID_PAT | CPUID_CMOV | CPUID_MCA |
            CPUID_PGE | CPUID_MTRR | CPUID_SEP | CPUID_APIC | CPUID_CX8 |
            CPUID_MCE | CPUID_PAE | CPUID_MSR | CPUID_TSC | CPUID_PSE |
            CPUID_DE | CPUID_FP87,
        // FEAT_1_ECX
            CPUID_EXT_AVX | CPUID_EXT_XSAVE | CPUID_EXT_AES |
            CPUID_EXT_POPCNT | CPUID_EXT_X2APIC | CPUID_EXT_SSE42 |
            CPUID_EXT_SSE41 | CPUID_EXT_CX16 | CPUID_EXT_SSSE3 |
            CPUID_EXT_PCLMULQDQ | CPUID_EXT_SSE3 |
            CPUID_EXT_TSC_DEADLINE_TIMER | CPUID_EXT_FMA | CPUID_EXT_MOVBE |
            CPUID_EXT_PCID,
        // FEAT_7_0_EBX
            CPUID_7_0_EBX_FSGSBASE | CPUID_7_0_EBX_BMI1 |
            CPUID_7_0_EBX_HLE | CPUID_7_0_EBX_AVX2 | CPUID_7_0_EBX_SMEP |
            CPUID_7_0_EBX_BMI2 | CPUID_7_0_EBX_ERMS | CPUID_7_0_EBX_INVPCID |
            CPUID_7_0_EBX_RTM | CPUID_7_0_EBX_RDSEED | CPUID_7_0_EBX_ADX |
            CPUID_7_0_EBX_SMAP,
        // FEAT_8000_0001_EDX
            CPUID_EXT2_LM | CPUID_EXT2_RDTSCP | CPUID_EXT2_NX |
            CPUID_EXT2_SYSCALL,
        // FEAT_8000_0001_ECX
            CPUID_EXT3_LAHF_LM | CPUID_EXT3_3DNOWPREFETCH,
        },
        "Intel Core Processor (Broadwell)",
    },
    {
        "Opteron_G1",
        5, 0x80000008, 0,
        CPUID_VENDOR_AMD,
        15, 6, 1,
        {
        // FEAT_1_EDX
            CPUID_SSE2 | CPUID_SSE | CPUID_FXSR | CPUID_MMX |
            CPUID_CLFLUSH | CPUID_PSE36 | CPUID_PAT | CPUID_CMOV | CPUID_MCA |
            CPUID_PGE | CPUID_MTRR | CPUID_SEP | CPUID_APIC | CPUID_CX8 |
            CPUID_MCE | CPUID_PAE | CPUID_MSR | CPUID_TSC | CPUID_PSE |
            CPUID_DE | CPUID_FP87,
        // FEAT_1_ECX
            CPUID_EXT_SSE3,
        // FEAT_7_0_EBX
            0,
        // FEAT_8000_0001_EDX
            CPUID_EXT2_LM | CPUID_EXT2_FXSR | CPUID_EXT2_MMX |
            CPUID_EXT2_NX | CPUID_EXT2_PSE36 | CPUID_EXT2_PAT |
            CPUID_EXT2_CMOV | CPUID_EXT2_MCA | CPUID_EXT2_PGE |
            CPUID_EXT2_MTRR | CPUID_EXT2_SYSCALL | CPUID_EXT2_APIC |
            CPUID_EXT2_CX8 | CPUID_EXT2_MCE | CPUID_EXT2_PAE | CPUID_EXT2_MSR |
            CPUID_EXT2_TSC | CPUID_EXT2_PSE | CPUID_EXT2_DE | CPUID_EXT2_FPU,
        },
        "AMD Opteron 240 (Gen 1 Class Opteron)",
    },
    {
        "Opteron_G2",
        5, 0x80000008, 0,
        CPUID_VENDOR_AMD,
        15, 6, 1,
        {
        // FEAT_1_EDX
            CPUID_SSE2 | CPUID_SSE | CPUID_FXSR | CPUID_MMX |
            CPUID_CLFLUSH | CPUID_PSE36 | CPUID_PAT | CPUID_CMOV | CPUID_MCA |
            CPUID_PGE | CPUID_MTRR | CPUID_SEP | CPUID_APIC | CPUID_CX8 |
            CPUID_MCE | CPUID_PAE | CPUID_MSR | CPUID_TSC | CPUID_PSE |
            CPUID_DE | CPUID_FP87,
        // FEAT_1_ECX
            CPUID_EXT_CX16 | CPUID_EXT_SSE3,
        // FEAT_7_0_EBX
            0,
        // FEAT_8000_0001_EDX
            CPUID_EXT2_LM | CPUID_EXT2_RDTSCP | CPUID_EXT2_FXSR |
            CPUID_EXT2_MMX | CPUID_EXT2_NX | CPUID_EXT2_PSE36 |
            CPUID_EXT2_PAT | CPUID_EXT2_CMOV | CPUID_EXT2_MCA |
            CPUID_EXT2_PGE | CPUID_EXT2_MTRR | CPUID_EXT2_SYSCALL |
            CPUID_EXT2_APIC | CPUID_EXT2_CX8 | CPUID_EXT2_MCE |
            CPUID_EXT2_PAE | CPUID_EXT2_MSR | CPUID_EXT2_TSC | CPUID_EXT2_PSE |
            CPUID_EXT2_DE | CPUID_EXT2_FPU,
        // FEAT_8000_0001_ECX
            CPUID_EXT3_SVM | CPUID_EXT3_LAHF_LM,
        },
        "AMD Opteron 22xx (Gen 2 Class Opteron)",
    },
    {
        "Opteron_G3",
        5, 0x80000008, 0,
        CPUID_VENDOR_AMD,
        15, 6, 1,
        {
        // FEAT_1_EDX
            CPUID_SSE2 | CPUID_SSE | CPUID_FXSR | CPUID_MMX |
            CPUID_CLFLUSH | CPUID_PSE36 | CPUID_PAT | CPUID_CMOV | CPUID_MCA |
            CPUID_PGE | CPUID_MTRR | CPUID_SEP | CPUID_APIC | CPUID_CX8 |
            CPUID_MCE | CPUID_PAE | CPUID_MSR | CPUID_TSC | CPUID_PSE |
            CPUID_DE | CPUID_FP87,
        // FEAT_1_ECX
            CPUID_EXT_POPCNT | CPUID_EXT_CX16 | CPUID_EXT_MONITOR |
            CPUID_EXT_SSE3,
        // FEAT_7_0_EBX
            0,
        // FEAT_8000_0001_EDX
            CPUID_EXT2_LM | CPUID_EXT2_RDTSCP | CPUID_EXT2_FXSR |
            CPUID_EXT2_MMX | CPUID_EXT2_NX | CPUID_EXT2_PSE36 |
            CPUID_EXT2_PAT | CPUID_EXT2_CMOV | CPUID_EXT2_MCA |
            CPUID_EXT2_PGE | CPUID_EXT2_MTRR | CPUID_EXT2_SYSCALL |
            CPUID_EXT2_APIC | CPUID_EXT2_CX8 | CPUID_EXT2_MCE |
            CPUID_EXT2_PAE | CPUID_EXT2_MSR | CPUID_EXT2_TSC | CPUID_EXT2_PSE |
            CPUID_EXT2_DE | CPUID_EXT2_FPU,
        // FEAT_8000_0001_ECX
            CPUID_EXT3_MISALIGNSSE | CPUID_EXT3_SSE4A |
            CPUID_EXT3_ABM | CPUID_EXT3_SVM | CPUID_EXT3_LAHF_LM,
        },
        "AMD Opteron 23xx (Gen 3 Class Opteron)",
    },
    {
        "Opteron_G4",
        0xd, 0x8000001A, 0,
        CPUID_VENDOR_AMD,
        21, 1, 2,
        {
        // FEAT_1_EDX
            CPUID_SSE2 | CPUID_SSE | CPUID_FXSR | CPUID_MMX |
            CPUID_CLFLUSH | CPUID_PSE36 | CPUID_PAT | CPUID_CMOV | CPUID_MCA |
            CPUID_PGE | CPUID_MTRR | CPUID_SEP | CPUID_APIC | CPUID_CX8 |
            CPUID_MCE | CPUID_PAE | CPUID_MSR | CPUID_TSC | CPUID_PSE |
            CPUID_DE | CPUID_FP87,
        // FEAT_1_ECX
            CPUID_EXT_AVX | CPUID_EXT_XSAVE | CPUID_EXT_AES |
            CPUID_EXT_POPCNT | CPUID_EXT_SSE42 | CPUID_EXT_SSE41 |
            CPUID_EXT_CX16 | CPUID_EXT_SSSE3 | CPUID_EXT_PCLMULQDQ |
            CPUID_EXT_SSE3,
        // FEAT_7_0_EBX
            0,
        // FEAT_8000_0001_EDX
            CPUID_EXT2_LM | CPUID_EXT2_RDTSCP |
            CPUID_EXT2_PDPE1GB | CPUID_EXT2_FXSR | CPUID_EXT2_MMX |
            CPUID_EXT2_NX | CPUID_EXT2_PSE36 | CPUID_EXT2_PAT |
            CPUID_EXT2_CMOV | CPUID_EXT2_MCA | CPUID_EXT2_PGE |
            CPUID_EXT2_MTRR | CPUID_EXT2_SYSCALL | CPUID_EXT2_APIC |
            CPUID_EXT2_CX8 | CPUID_EXT2_MCE | CPUID_EXT2_PAE | CPUID_EXT2_MSR |
            CPUID_EXT2_TSC | CPUID_EXT2_PSE | CPUID_EXT2_DE | CPUID_EXT2_FPU,
        // FEAT_8000_0001_ECX
            CPUID_EXT3_FMA4 | CPUID_EXT3_XOP |
            CPUID_EXT3_3DNOWPREFETCH | CPUID_EXT3_MISALIGNSSE |
            CPUID_EXT3_SSE4A | CPUID_EXT3_ABM | CPUID_EXT3_SVM |
            CPUID_EXT3_LAHF_LM,
        },
        "AMD Opteron 62xx class CPU",
    },
    {
        "Opteron_G5",
        0xd, 0x8000001A, 0,
        CPUID_VENDOR_AMD,
        21, 2, 0,
        {
        // FEAT_1_EDX
            CPUID_SSE2 | CPUID_SSE | CPUID_FXSR | CPUID_MMX |
            CPUID_CLFLUSH | CPUID_PSE36 | CPUID_PAT | CPUID_CMOV | CPUID_MCA |
            CPUID_PGE | CPUID_MTRR | CPUID_SEP | CPUID_APIC | CPUID_CX8 |
            CPUID_MCE | CPUID_PAE | CPUID_MSR | CPUID_TSC | CPUID_PSE |
            CPUID_DE | CPUID_FP87,
        // FEAT_1_ECX
            CPUID_EXT_F16C | CPUID_EXT_AVX | CPUID_EXT_XSAVE |
            CPUID_EXT_AES | CPUID_EXT_POPCNT | CPUID_EXT_SSE42 |
            CPUID_EXT_SSE41 | CPUID_EXT_CX16 | CPUID_EXT_FMA |
            CPUID_EXT_SSSE3 | CPUID_EXT_PCLMULQDQ | CPUID_EXT_SSE3,
        // FEAT_7_0_EBX
            0,
        // FEAT_8000_0001_EDX
            CPUID_EXT2_LM | CPUID_EXT2_RDTSCP |
            CPUID_EXT2_PDPE1GB | CPUID_EXT2_FXSR | CPUID_EXT2_MMX |
            CPUID_EXT2_NX | CPUID_EXT2_PSE36 | CPUID_EXT2_PAT |
            CPUID_EXT2_CMOV | CPUID_EXT2_MCA | CPUID_EXT2_PGE |
            CPUID_EXT2_MTRR | CPUID_EXT2_SYSCALL | CPUID_EXT2_APIC |
            CPUID_EXT2_CX8 | CPUID_EXT2_MCE | CPUID_EXT2_PAE | CPUID_EXT2_MSR |
            CPUID_EXT2_TSC | CPUID_EXT2_PSE | CPUID_EXT2_DE | CPUID_EXT2_FPU,
        // FEAT_8000_0001_ECX
            CPUID_EXT3_TBM | CPUID_EXT3_FMA4 | CPUID_EXT3_XOP |
            CPUID_EXT3_3DNOWPREFETCH | CPUID_EXT3_MISALIGNSSE |
            CPUID_EXT3_SSE4A | CPUID_EXT3_ABM | CPUID_EXT3_SVM |
            CPUID_EXT3_LAHF_LM,
        },
        "AMD Opteron 63xx class CPU",
    },
};

static uint32_t x86_cpu_get_supported_feature_word(struct uc_struct *uc, FeatureWord w);

static void report_unavailable_features(FeatureWord w, uint32_t mask)
{
    FeatureWordInfo *f = &feature_word_info[w];
    int i;

    for (i = 0; i < 32; ++i) {
        if (1 << i & mask) {
            const char *reg = get_register_name_32(f->cpuid_reg);
            assert(reg);
            fprintf(stderr, "warning: %s doesn't support requested feature: "
                "CPUID.%02XH:%s%s%s [bit %d]\n",
                "TCG",
                f->cpuid_eax, reg,
                f->feat_names[i] ? "." : "",
                f->feat_names[i] ? f->feat_names[i] : "", i);
        }
    }
}

/* Convert all '_' in a feature string option name to '-', to make feature
 * name conform to QOM property naming rule, which uses '-' instead of '_'.
 */
static inline void feat2prop(char *s)
{
    while ((s = strchr(s, '_'))) {
        *s = '-';
    }
}

/* Parse "+feature,-feature,feature=foo" CPU feature string
 */
static void x86_cpu_parse_featurestr(CPUState *cs, char *features)
{
    X86CPU *cpu = X86_CPU(cs->uc, cs);
    char *featurestr; /* Single 'key=value" string being parsed */
    FeatureWord w;
    /* Features to be added */
    FeatureWordArray plus_features = { 0 };
    /* Features to be removed */
    FeatureWordArray minus_features = { 0 };
    uint32_t numvalue;
    CPUX86State *env = &cpu->env;

    featurestr = features ? strtok(features, ",") : NULL;

    while (featurestr) {
        char *val;
        if (featurestr[0] == '+') {
            add_flagname_to_bitmaps(featurestr + 1, plus_features);
        } else if (featurestr[0] == '-') {
            add_flagname_to_bitmaps(featurestr + 1, minus_features);
        } else if ((val = strchr(featurestr, '='))) {
            *val = 0; val++;
            feat2prop(featurestr);
            if (!strcmp(featurestr, "xlevel")) {
                char *err;
                char num[32];

                numvalue = strtoul(val, &err, 0);
                if (!*val || *err) {
                    return;
                }
                if (numvalue < 0x80000000) {
                    numvalue += 0x80000000;
                }
                snprintf(num, sizeof(num), "%" PRIu32, numvalue);
            } else if (!strcmp(featurestr, "tsc-freq")) {
                int64_t tsc_freq;
                char *err;
                char num[32];

                tsc_freq = strtosz_suffix_unit(val, &err,
                                               STRTOSZ_DEFSUFFIX_B, 1000);
                if (tsc_freq < 0 || *err) {
                    return;
                }
                snprintf(num, sizeof(num), "%" PRId64, tsc_freq);
            } else if (!strcmp(featurestr, "hv-spinlocks")) {
                char *err;
                const int min = 0xFFF;
                char num[32];
                numvalue = strtoul(val, &err, 0);
                if (!*val || *err) {
                    return;
                }
                if (numvalue < (uint32_t)min) {
                    numvalue = min;
                }
                snprintf(num, sizeof(num), "%" PRId32, numvalue);
            }
        } else {
            feat2prop(featurestr);
        }
        featurestr = strtok(NULL, ",");
    }

    if (cpu->host_features) {
        for (w = 0; w < FEATURE_WORDS; w++) {
            env->features[w] =
                x86_cpu_get_supported_feature_word(env->uc, w);
        }
    }

    for (w = 0; w < FEATURE_WORDS; w++) {
        env->features[w] |= plus_features[w];
        env->features[w] &= ~minus_features[w];
    }
}

static uint32_t x86_cpu_get_supported_feature_word(struct uc_struct *uc, FeatureWord w)
{
    FeatureWordInfo *wi = &feature_word_info[w];

    if (tcg_enabled(uc)) {
        return wi->tcg_features;
    } else {
        return ~0;
    }
}

/*
 * Filters CPU feature words based on host availability of each feature.
 *
 * Returns: 0 if all flags are supported by the host, non-zero otherwise.
 */
static int x86_cpu_filter_features(X86CPU *cpu)
{
    CPUX86State *env = &cpu->env;
    FeatureWord w;
    int rv = 0;

    for (w = 0; w < FEATURE_WORDS; w++) {
        uint32_t host_feat = x86_cpu_get_supported_feature_word(env->uc, w);
        uint32_t requested_features = env->features[w];
        env->features[w] &= host_feat;
        cpu->filtered_features[w] = requested_features & ~env->features[w];
        if (cpu->filtered_features[w]) {
            if (cpu->check_cpuid || cpu->enforce_cpuid) {
                report_unavailable_features(w, cpu->filtered_features[w]);
            }
            rv = 1;
        }
    }

    return rv;
}

/* Load data from X86CPUDefinition
 */
static void x86_cpu_load_def(X86CPU *cpu, X86CPUDefinition *def)
{
    CPUX86State *env = &cpu->env;
    FeatureWord w;

    env->cpuid_xlevel2 = def->xlevel2;
    cpu->cache_info_passthrough = def->cache_info_passthrough;

    for (w = 0; w < FEATURE_WORDS; w++) {
        env->features[w] = def->features[w];
    }

    env->features[FEAT_1_ECX] |= CPUID_EXT_HYPERVISOR;
}

#if !defined(CONFIG_USER_ONLY)

void cpu_clear_apic_feature(CPUX86State *env)
{
    env->features[FEAT_1_EDX] &= ~CPUID_APIC;
}

#endif /* !CONFIG_USER_ONLY */

static void get_cpuid_vendor(CPUX86State *env, uint32_t *ebx,
                             uint32_t *ecx, uint32_t *edx)
{
    *ebx = env->cpuid_vendor1;
    *edx = env->cpuid_vendor2;
    *ecx = env->cpuid_vendor3;
}

void cpu_x86_cpuid(CPUX86State *env, uint32_t index, uint32_t count,
                   uint32_t *eax, uint32_t *ebx,
                   uint32_t *ecx, uint32_t *edx)
{
    X86CPU *cpu = x86_env_get_cpu(env);
    CPUState *cs = CPU(cpu);

    /* test if maximum index reached */
    if (index & 0x80000000) {
        if (index > env->cpuid_xlevel) {
            if (env->cpuid_xlevel2 > 0) {
                /* Handle the Centaur's CPUID instruction. */
                if (index > env->cpuid_xlevel2) {
                    index = env->cpuid_xlevel2;
                } else if (index < 0xC0000000) {
                    index = env->cpuid_xlevel;
                }
            } else {
                /* Intel documentation states that invalid EAX input will
                 * return the same information as EAX=cpuid_level
                 * (Intel SDM Vol. 2A - Instruction Set Reference - CPUID)
                 */
                index =  env->cpuid_level;
            }
        }
    } else {
        if (index > env->cpuid_level)
            index = env->cpuid_level;
    }

    switch(index) {
    case 0:
        *eax = env->cpuid_level;
        get_cpuid_vendor(env, ebx, ecx, edx);
        break;
    case 1:
        *eax = env->cpuid_version;
        *ebx = (env->cpuid_apic_id << 24) | 8 << 8; /* CLFLUSH size in quad words, Linux wants it. */
        *ecx = env->features[FEAT_1_ECX];
        *edx = env->features[FEAT_1_EDX];
        if (cs->nr_cores * cs->nr_threads > 1) {
            *ebx |= (cs->nr_cores * cs->nr_threads) << 16;
            *edx |= 1 << 28;    /* HTT bit */
        }
        break;
    case 2:
        /* cache info: needed for Pentium Pro compatibility */
        if (cpu->cache_info_passthrough) {
            host_cpuid(index, 0, eax, ebx, ecx, edx);
            break;
        }
        *eax = 1; /* Number of CPUID[EAX=2] calls required */
        *ebx = 0;
        *ecx = 0;
        *edx = (L1D_DESCRIPTOR << 16) | \
               (L1I_DESCRIPTOR <<  8) | \
               (L2_DESCRIPTOR);
        break;
    case 4:
        /* cache info: needed for Core compatibility */
        if (cpu->cache_info_passthrough) {
            host_cpuid(index, count, eax, ebx, ecx, edx);
            *eax &= ~0xFC000000;
        } else {
            *eax = 0;
            switch (count) {
            case 0: /* L1 dcache info */
                *eax |= CPUID_4_TYPE_DCACHE | \
                        CPUID_4_LEVEL(1) | \
                        CPUID_4_SELF_INIT_LEVEL;
                *ebx = (L1D_LINE_SIZE - 1) | \
                       ((L1D_PARTITIONS - 1) << 12) | \
                       ((L1D_ASSOCIATIVITY - 1) << 22);
                *ecx = L1D_SETS - 1;
                *edx = CPUID_4_NO_INVD_SHARING;
                break;
            case 1: /* L1 icache info */
                *eax |= CPUID_4_TYPE_ICACHE | \
                        CPUID_4_LEVEL(1) | \
                        CPUID_4_SELF_INIT_LEVEL;
                *ebx = (L1I_LINE_SIZE - 1) | \
                       ((L1I_PARTITIONS - 1) << 12) | \
                       ((L1I_ASSOCIATIVITY - 1) << 22);
                *ecx = L1I_SETS - 1;
                *edx = CPUID_4_NO_INVD_SHARING;
                break;
            case 2: /* L2 cache info */
                *eax |= CPUID_4_TYPE_UNIFIED | \
                        CPUID_4_LEVEL(2) | \
                        CPUID_4_SELF_INIT_LEVEL;
                if (cs->nr_threads > 1) {
                    *eax |= (cs->nr_threads - 1) << 14;
                }
                *ebx = (L2_LINE_SIZE - 1) | \
                       ((L2_PARTITIONS - 1) << 12) | \
                       ((L2_ASSOCIATIVITY - 1) << 22);
                *ecx = L2_SETS - 1;
                *edx = CPUID_4_NO_INVD_SHARING;
                break;
            default: /* end of info */
                *eax = 0;
                *ebx = 0;
                *ecx = 0;
                *edx = 0;
                break;
            }
        }

        /* QEMU gives out its own APIC IDs, never pass down bits 31..26.  */
        if ((*eax & 31) && cs->nr_cores > 1) {
            *eax |= (cs->nr_cores - 1) << 26;
        }
        break;
    case 5:
        /* mwait info: needed for Core compatibility */
        *eax = 0; /* Smallest monitor-line size in bytes */
        *ebx = 0; /* Largest monitor-line size in bytes */
        *ecx = CPUID_MWAIT_EMX | CPUID_MWAIT_IBE;
        *edx = 0;
        break;
    case 6:
        /* Thermal and Power Leaf */
        *eax = 0;
        *ebx = 0;
        *ecx = 0;
        *edx = 0;
        break;
    case 7:
        /* Structured Extended Feature Flags Enumeration Leaf */
        if (count == 0) {
            *eax = 0; /* Maximum ECX value for sub-leaves */
            *ebx = env->features[FEAT_7_0_EBX]; /* Feature flags */
            *ecx = 0; /* Reserved */
            *edx = 0; /* Reserved */
        } else {
            *eax = 0;
            *ebx = 0;
            *ecx = 0;
            *edx = 0;
        }
        break;
    case 9:
        /* Direct Cache Access Information Leaf */
        *eax = 0; /* Bits 0-31 in DCA_CAP MSR */
        *ebx = 0;
        *ecx = 0;
        *edx = 0;
        break;
    case 0xA:
        /* Architectural Performance Monitoring Leaf */
            *eax = 0;
            *ebx = 0;
            *ecx = 0;
            *edx = 0;
        break;
    case 0xD: {
        break;
    }
    case 0x80000000:
        *eax = env->cpuid_xlevel;
        *ebx = env->cpuid_vendor1;
        *edx = env->cpuid_vendor2;
        *ecx = env->cpuid_vendor3;
        break;
    case 0x80000001:
        *eax = env->cpuid_version;
        *ebx = 0;
        *ecx = env->features[FEAT_8000_0001_ECX];
        *edx = env->features[FEAT_8000_0001_EDX];

        /* The Linux kernel checks for the CMPLegacy bit and
         * discards multiple thread information if it is set.
         * So dont set it here for Intel to make Linux guests happy.
         */
        if (cs->nr_cores * cs->nr_threads > 1) {
            uint32_t tebx, tecx, tedx;
            get_cpuid_vendor(env, &tebx, &tecx, &tedx);
            if (tebx != CPUID_VENDOR_INTEL_1 ||
                tedx != CPUID_VENDOR_INTEL_2 ||
                tecx != CPUID_VENDOR_INTEL_3) {
                *ecx |= 1 << 1;    /* CmpLegacy bit */
            }
        }
        break;
    case 0x80000002:
    case 0x80000003:
    case 0x80000004:
        *eax = env->cpuid_model[(index - 0x80000002) * 4 + 0];
        *ebx = env->cpuid_model[(index - 0x80000002) * 4 + 1];
        *ecx = env->cpuid_model[(index - 0x80000002) * 4 + 2];
        *edx = env->cpuid_model[(index - 0x80000002) * 4 + 3];
        break;
    case 0x80000005:
        /* cache info (L1 cache) */
        if (cpu->cache_info_passthrough) {
            host_cpuid(index, 0, eax, ebx, ecx, edx);
            break;
        }
        *eax = (L1_DTLB_2M_ASSOC << 24) | (L1_DTLB_2M_ENTRIES << 16) | \
               (L1_ITLB_2M_ASSOC <<  8) | (L1_ITLB_2M_ENTRIES);
        *ebx = (L1_DTLB_4K_ASSOC << 24) | (L1_DTLB_4K_ENTRIES << 16) | \
               (L1_ITLB_4K_ASSOC <<  8) | (L1_ITLB_4K_ENTRIES);
        *ecx = (L1D_SIZE_KB_AMD << 24) | (L1D_ASSOCIATIVITY_AMD << 16) | \
               (L1D_LINES_PER_TAG << 8) | (L1D_LINE_SIZE);
        *edx = (L1I_SIZE_KB_AMD << 24) | (L1I_ASSOCIATIVITY_AMD << 16) | \
               (L1I_LINES_PER_TAG << 8) | (L1I_LINE_SIZE);
        break;
    case 0x80000006:
        /* cache info (L2 cache) */
        if (cpu->cache_info_passthrough) {
            host_cpuid(index, 0, eax, ebx, ecx, edx);
            break;
        }
        *eax = (AMD_ENC_ASSOC(L2_DTLB_2M_ASSOC) << 28) | \
               (L2_DTLB_2M_ENTRIES << 16) | \
               (AMD_ENC_ASSOC(L2_ITLB_2M_ASSOC) << 12) | \
               (L2_ITLB_2M_ENTRIES);
        *ebx = (AMD_ENC_ASSOC(L2_DTLB_4K_ASSOC) << 28) | \
               (L2_DTLB_4K_ENTRIES << 16) | \
               (AMD_ENC_ASSOC(L2_ITLB_4K_ASSOC) << 12) | \
               (L2_ITLB_4K_ENTRIES);
        *ecx = (L2_SIZE_KB_AMD << 16) | \
               (AMD_ENC_ASSOC(L2_ASSOCIATIVITY) << 12) | \
               (L2_LINES_PER_TAG << 8) | (L2_LINE_SIZE);
        *edx = ((L3_SIZE_KB/512) << 18) | \
               (AMD_ENC_ASSOC(L3_ASSOCIATIVITY) << 12) | \
               (L3_LINES_PER_TAG << 8) | (L3_LINE_SIZE);
        break;
    case 0x80000007:
        *eax = 0;
        *ebx = 0;
        *ecx = 0;
        *edx = env->features[FEAT_8000_0007_EDX];
        break;
    case 0x80000008:
        /* virtual & phys address size in low 2 bytes. */
/* XXX: This value must match the one used in the MMU code. */
        if (env->features[FEAT_8000_0001_EDX] & CPUID_EXT2_LM) {
            /* 64 bit processor */
/* XXX: The physical address space is limited to 42 bits in exec.c. */
            *eax = 0x00003028; /* 48 bits virtual, 40 bits physical */
        } else {
            if (env->features[FEAT_1_EDX] & CPUID_PSE36) {
                *eax = 0x00000024; /* 36 bits physical */
            } else {
                *eax = 0x00000020; /* 32 bits physical */
            }
        }
        *ebx = 0;
        *ecx = 0;
        *edx = 0;
        if (cs->nr_cores * cs->nr_threads > 1) {
            *ecx |= (cs->nr_cores * cs->nr_threads) - 1;
        }
        break;
    case 0x8000000A:
        if (env->features[FEAT_8000_0001_ECX] & CPUID_EXT3_SVM) {
            *eax = 0x00000001; /* SVM Revision */
            *ebx = 0x00000010; /* nr of ASIDs */
            *ecx = 0;
            *edx = env->features[FEAT_SVM]; /* optional features */
        } else {
            *eax = 0;
            *ebx = 0;
            *ecx = 0;
            *edx = 0;
        }
        break;
    case 0xC0000000:
        *eax = env->cpuid_xlevel2;
        *ebx = 0;
        *ecx = 0;
        *edx = 0;
        break;
    case 0xC0000001:
        /* Support for VIA CPU's CPUID instruction */
        *eax = env->cpuid_version;
        *ebx = 0;
        *ecx = 0;
        *edx = env->features[FEAT_C000_0001_EDX];
        break;
    case 0xC0000002:
    case 0xC0000003:
    case 0xC0000004:
        /* Reserved for the future, and now filled with zero */
        *eax = 0;
        *ebx = 0;
        *ecx = 0;
        *edx = 0;
        break;
    default:
        /* reserved values: zero */
        *eax = 0;
        *ebx = 0;
        *ecx = 0;
        *edx = 0;
        break;
    }
}

/* CPUClass::reset() */
static void x86_cpu_reset(CPUState *s)
{
    X86CPU *cpu = X86_CPU(s->uc, s);
    X86CPUClass *xcc = X86_CPU_GET_CLASS(s->uc, cpu);
    CPUX86State *env = &cpu->env;
    int i;

    xcc->parent_reset(s);

    memset(env, 0, offsetof(CPUX86State, cpuid_level));

    tlb_flush(s, 1);

    env->old_exception = -1;

    /* init to reset state */

#ifdef CONFIG_SOFTMMU
    env->hflags |= HF_SOFTMMU_MASK;
#endif
    env->hflags2 |= HF2_GIF_MASK;

    cpu_x86_update_cr0(env, 0x60000010);
    env->a20_mask = ~0x0;
    env->smbase = 0x30000;

    env->idt.limit = 0xffff;
    env->gdt.limit = 0xffff;
    env->ldt.limit = 0xffff;
    env->ldt.flags = DESC_P_MASK | (2 << DESC_TYPE_SHIFT);
    env->tr.limit = 0xffff;
    env->tr.flags = DESC_P_MASK | (11 << DESC_TYPE_SHIFT);

    cpu_x86_load_seg_cache(env, R_CS, 0xf000, 0xffff0000, 0xffff,
                           DESC_P_MASK | DESC_S_MASK | DESC_CS_MASK |
                           DESC_R_MASK | DESC_A_MASK);
    cpu_x86_load_seg_cache(env, R_DS, 0, 0, 0xffff,
                           DESC_P_MASK | DESC_S_MASK | DESC_W_MASK |
                           DESC_A_MASK);
    cpu_x86_load_seg_cache(env, R_ES, 0, 0, 0xffff,
                           DESC_P_MASK | DESC_S_MASK | DESC_W_MASK |
                           DESC_A_MASK);
    cpu_x86_load_seg_cache(env, R_SS, 0, 0, 0xffff,
                           DESC_P_MASK | DESC_S_MASK | DESC_W_MASK |
                           DESC_A_MASK);
    cpu_x86_load_seg_cache(env, R_FS, 0, 0, 0xffff,
                           DESC_P_MASK | DESC_S_MASK | DESC_W_MASK |
                           DESC_A_MASK);
    cpu_x86_load_seg_cache(env, R_GS, 0, 0, 0xffff,
                           DESC_P_MASK | DESC_S_MASK | DESC_W_MASK |
                           DESC_A_MASK);

    env->eip = 0xfff0;
    env->regs[R_EDX] = env->cpuid_version;

    env->eflags = 0x2;

    /* FPU init */
    for (i = 0; i < 8; i++) {
        env->fptags[i] = 1;
    }
    cpu_set_fpuc(env, 0x37f);

    env->mxcsr = 0x1f80;
    env->xstate_bv = XSTATE_FP | XSTATE_SSE;

    env->pat = 0x0007040600070406ULL;
    env->msr_ia32_misc_enable = MSR_IA32_MISC_ENABLE_DEFAULT;

    memset(env->dr, 0, sizeof(env->dr));
    env->dr[6] = DR6_FIXED_1;
    env->dr[7] = DR7_FIXED_1;
    cpu_breakpoint_remove_all(s, BP_CPU);
    cpu_watchpoint_remove_all(s, BP_CPU);

    env->xcr0 = 1;

    /*
     * SDM 11.11.5 requires:
     *  - IA32_MTRR_DEF_TYPE MSR.E = 0
     *  - IA32_MTRR_PHYSMASKn.V = 0
     * All other bits are undefined.  For simplification, zero it all.
     */
    env->mtrr_deftype = 0;
    memset(env->mtrr_var, 0, sizeof(env->mtrr_var));
    memset(env->mtrr_fixed, 0, sizeof(env->mtrr_fixed));
}

static void mce_init(X86CPU *cpu)
{
    CPUX86State *cenv = &cpu->env;
    unsigned int bank;

    if (((cenv->cpuid_version >> 8) & 0xf) >= 6
        && (cenv->features[FEAT_1_EDX] & (CPUID_MCE | CPUID_MCA)) ==
            (CPUID_MCE | CPUID_MCA)) {
        cenv->mcg_cap = MCE_CAP_DEF | MCE_BANKS_DEF;
        cenv->mcg_ctl = ~(uint64_t)0;
        for (bank = 0; bank < MCE_BANKS_DEF; bank++) {
            cenv->mce_banks[bank * 4] = ~(uint64_t)0;
        }
    }
}

#ifndef CONFIG_USER_ONLY
static void x86_cpu_apic_create(X86CPU *cpu)
{
}

static void x86_cpu_apic_realize(X86CPU *cpu)
{
}
#else
static void x86_cpu_apic_realize(X86CPU *cpu, Error **errp)
{
}
#endif

#define IS_INTEL_CPU(env) ((env)->cpuid_vendor1 == CPUID_VENDOR_INTEL_1 && \
                           (env)->cpuid_vendor2 == CPUID_VENDOR_INTEL_2 && \
                           (env)->cpuid_vendor3 == CPUID_VENDOR_INTEL_3)
#define IS_AMD_CPU(env) ((env)->cpuid_vendor1 == CPUID_VENDOR_AMD_1 && \
                         (env)->cpuid_vendor2 == CPUID_VENDOR_AMD_2 && \
                         (env)->cpuid_vendor3 == CPUID_VENDOR_AMD_3)
static int x86_cpu_realizefn(struct uc_struct *uc, CPUState *dev)
{
    CPUState *cs = CPU(dev);
    X86CPU *cpu = X86_CPU(uc, dev);
    CPUX86State *env = &cpu->env;

    if (env->features[FEAT_7_0_EBX] && env->cpuid_level < 7) {
        env->cpuid_level = 7;
    }

    /* On AMD CPUs, some CPUID[8000_0001].EDX bits must match the bits on
     * CPUID[1].EDX.
     */
    if (IS_AMD_CPU(env)) {
        env->features[FEAT_8000_0001_EDX] &= ~CPUID_EXT2_AMD_ALIASES;
        env->features[FEAT_8000_0001_EDX] |= (env->features[FEAT_1_EDX]
           & CPUID_EXT2_AMD_ALIASES);
    }

    if (x86_cpu_filter_features(cpu) && cpu->enforce_cpuid) {
        goto out;
    }

#ifndef CONFIG_USER_ONLY
    //qemu_register_reset(x86_cpu_machine_reset_cb, cpu);

    if (cpu->env.features[FEAT_1_EDX] & CPUID_APIC || smp_cpus > 1) {
        x86_cpu_apic_create(cpu);
    }
#endif

    mce_init(cpu);
    if (qemu_init_vcpu(cs))
        return -1;

    x86_cpu_apic_realize(cpu);
    cpu_reset(cs);

out:

    return 0;
}

/* Enables contiguous-apic-ID mode, for compatibility */
static bool compat_apic_id_mode;

void enable_compat_apic_id_mode(void)
{
    compat_apic_id_mode = true;
}

/* Calculates initial APIC ID for a specific CPU index
 *
 * Currently we need to be able to calculate the APIC ID from the CPU index
 * alone (without requiring a CPU object), as the QEMU<->Seabios interfaces have
 * no concept of "CPU index", and the NUMA tables on fw_cfg need the APIC ID of
 * all CPUs up to max_cpus.
 */
uint32_t x86_cpu_apic_id_from_index(unsigned int cpu_index)
{
    uint32_t correct_id;

    correct_id = x86_apicid_from_cpu_idx(smp_cores, smp_threads, cpu_index);
    if (compat_apic_id_mode) {
        if (cpu_index != correct_id) {
            //error_report("APIC IDs set in compatibility mode, "
            //        "CPU topology won't match the configuration");
        }
        return cpu_index;
    } else {
        return correct_id;
    }
}

static void x86_cpu_initfn(struct uc_struct *uc, CPUState *obj, void *opaque)
{
    //printf("... X86 initialize (object)\n");
    CPUState *cs = CPU(obj);
    X86CPU *cpu = X86_CPU(cs->uc, obj);
    X86CPUClass *xcc = &cpu->cc;
    CPUX86State *env = &cpu->env;

    cs->env_ptr = env;
    cpu_exec_init(env, opaque);

    env->cpuid_apic_id = x86_cpu_apic_id_from_index(cs->cpu_index);

    x86_cpu_load_def(cpu, xcc->cpu_def);

    /* init various static tables used in TCG mode */
    if (tcg_enabled(env->uc))
        optimize_flags_init(env->uc);
}

static int64_t x86_cpu_get_arch_id(CPUState *cs)
{
    X86CPU *cpu = X86_CPU(cs->uc, cs);
    CPUX86State *env = &cpu->env;

    return env->cpuid_apic_id;
}

static bool x86_cpu_get_paging_enabled(const CPUState *cs)
{
    X86CPU *cpu = X86_CPU(cs->uc, cs);

    return (cpu->env.cr[0] & CR0_PG_MASK) != 0;
}

static void x86_cpu_set_pc(CPUState *cs, vaddr value)
{
    X86CPU *cpu = X86_CPU(cs->uc, cs);

    cpu->env.eip = value;
}

static void x86_cpu_synchronize_from_tb(CPUState *cs, TranslationBlock *tb)
{
    X86CPU *cpu = X86_CPU(cs->uc, cs);

    cpu->env.eip = tb->pc - tb->cs_base;
}

static bool x86_cpu_has_work(CPUState *cs)
{
    X86CPU *cpu = X86_CPU(cs->uc, cs);
    CPUX86State *env = &cpu->env;

    if (cs->interrupt_request & CPU_INTERRUPT_POLL) {
#if 0
        /* do nothing */
        apic_poll_irq(cpu->apic_state);
#endif
        cpu_reset_interrupt(cs, CPU_INTERRUPT_POLL);
    }

    return ((cs->interrupt_request & CPU_INTERRUPT_HARD) &&
            (env->eflags & IF_MASK)) ||
           (cs->interrupt_request & (CPU_INTERRUPT_NMI |
                                     CPU_INTERRUPT_INIT |
                                     CPU_INTERRUPT_SIPI |
                                     CPU_INTERRUPT_MCE));
}

static void x86_cpu_common_class_init(struct uc_struct *uc, CPUClass *oc, void *data)
{
    //printf("... init X86 cpu common class\n");
    X86CPUClass *xcc = X86_CPU_CLASS(uc, oc);
    CPUClass *cc = CPU_CLASS(uc, oc);

    xcc->parent_reset = cc->reset;
    cc->reset = x86_cpu_reset;
    cc->reset_dump_flags = CPU_DUMP_FPU | CPU_DUMP_CCOP;
    cc->parse_features = x86_cpu_parse_featurestr;
    cc->has_work = x86_cpu_has_work;
    cc->do_interrupt = x86_cpu_do_interrupt;
    cc->cpu_exec_interrupt = x86_cpu_exec_interrupt;
    cc->set_pc = x86_cpu_set_pc;
    cc->synchronize_from_tb = x86_cpu_synchronize_from_tb;
    cc->get_arch_id = x86_cpu_get_arch_id;
    cc->get_paging_enabled = x86_cpu_get_paging_enabled;
#ifdef CONFIG_USER_ONLY
    cc->handle_mmu_fault = x86_cpu_handle_mmu_fault;
#else
    cc->get_memory_mapping = x86_cpu_get_memory_mapping;
    cc->get_phys_page_debug = x86_cpu_get_phys_page_debug;
#endif
#ifndef CONFIG_USER_ONLY
    cc->debug_excp_handler = breakpoint_handler;
#endif
    cc->cpu_exec_enter = x86_cpu_exec_enter;
    cc->cpu_exec_exit = x86_cpu_exec_exit;
}

X86CPU *cpu_x86_init(struct uc_struct *uc, const char *cpu_model)
{
    int i;
    X86CPU *cpu;
    CPUState *cs;
    CPUClass *cc;
    X86CPUClass *xcc;

    if (cpu_model == NULL) {
#ifdef TARGET_X86_64
        cpu_model = "qemu64";
#else
        cpu_model = "qemu32";
#endif
    }

    cpu = malloc(sizeof(*cpu));
    if (cpu == NULL) {
        return NULL;
    }
    memset(cpu, 0, sizeof(*cpu));

    cs = (CPUState *)cpu;
    cc = (CPUClass *)&cpu->cc;
    cs->cc = cc;
    cs->uc = uc;
    /* init CPUClass */
    cpu_klass_init(uc, cc);
    /* init X86CPUClass */
    x86_cpu_common_class_init(uc, cc, NULL);
    /* init X86CPUDefinition */
    xcc = &cpu->cc;
    for (i = 0; i < ARRAY_SIZE(builtin_x86_defs); i++) {
        if (strcmp(cpu_model, builtin_x86_defs[i].name) == 0) {
            xcc->cpu_def = &builtin_x86_defs[i];
            break;
        }
    }
    if (xcc->cpu_def == NULL) {
        free(cpu);
        return NULL;
    }
    /* init CPUState */
#ifdef NEED_CPU_INIT_REALIZE
    cpu_object_init(uc, cs);
#endif
    /* init X86CPU */
    x86_cpu_initfn(uc, cs, uc);
    /* realize X86CPU */
    x86_cpu_realizefn(uc, cs);
    /* realize CPUState */
#ifdef NEED_CPU_INIT_REALIZE
    cpu_object_realize(uc, cs);
#endif

    uc->cpu = (CPUState *)cpu;

    return cpu;
}
