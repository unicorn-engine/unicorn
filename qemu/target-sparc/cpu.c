/*
 * Sparc CPU init helpers
 *
 *  Copyright (c) 2003-2005 Fabrice Bellard
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

#include "cpu.h"
#include "hw/sparc/sparc.h"

//#define DEBUG_FEATURES

static int cpu_sparc_find_by_name(sparc_def_t *cpu_def, const char *cpu_model);

/* CPUClass::reset() */
static void sparc_cpu_reset(CPUState *s)
{
    SPARCCPU *cpu = SPARC_CPU(s->uc, s);
    SPARCCPUClass *scc = SPARC_CPU_GET_CLASS(s->uc, cpu);
    CPUSPARCState *env = &cpu->env;

    scc->parent_reset(s);

    memset(env, 0, offsetof(CPUSPARCState, version));
    tlb_flush(s, 1);
    env->cwp = 0;
#ifndef TARGET_SPARC64
    env->wim = 1;
#endif
    env->regwptr = env->regbase + (env->cwp * 16);
    CC_OP = CC_OP_FLAGS;
#if defined(CONFIG_USER_ONLY)
#ifdef TARGET_SPARC64
    env->cleanwin = env->nwindows - 2;
    env->cansave = env->nwindows - 2;
    env->pstate = PS_RMO | PS_PEF | PS_IE;
    env->asi = 0x82; /* Primary no-fault */
#endif
#else
#if !defined(TARGET_SPARC64)
    env->psret = 0;
    env->psrs = 1;
    env->psrps = 1;
#endif
#ifdef TARGET_SPARC64
    env->pstate = PS_PRIV|PS_RED|PS_PEF|PS_AG;
    env->hpstate = cpu_has_hypervisor(env) ? HS_PRIV : 0;
    env->tl = env->maxtl;
    cpu_tsptr(env)->tt = TT_POWER_ON_RESET;
    env->lsu = 0;
#else
    env->mmuregs[0] &= ~(MMU_E | MMU_NF);
    env->mmuregs[0] |= env->def->mmu_bm;
#endif
    env->pc = 0;
    env->npc = env->pc + 4;
#endif
    env->cache_control = 0;
}

static bool sparc_cpu_exec_interrupt(CPUState *cs, int interrupt_request)
{
    if (interrupt_request & CPU_INTERRUPT_HARD) {
        SPARCCPU *cpu = SPARC_CPU(cs->uc, cs);
        CPUSPARCState *env = &cpu->env;

        if (cpu_interrupts_enabled(env) && env->interrupt_index > 0) {
            int pil = env->interrupt_index & 0xf;
            int type = env->interrupt_index & 0xf0;

            if (type != TT_EXTINT || cpu_pil_allowed(env, pil)) {
                cs->exception_index = env->interrupt_index;
                sparc_cpu_do_interrupt(cs);
                return true;
            }
        }
    }
    return false;
}

static int cpu_sparc_register(struct uc_struct *uc, SPARCCPU *cpu, const char *cpu_model)
{
    CPUClass *cc = CPU_GET_CLASS(uc, cpu);
    CPUSPARCState *env = &cpu->env;
    char *s = g_strdup(cpu_model);
    char *featurestr, *name = strtok(s, ",");
    sparc_def_t def1, *def = &def1;
    Error *err = NULL;

    if (cpu_sparc_find_by_name(def, name) < 0) {
        g_free(s);
        return -1;
    }

    env->def = g_new0(sparc_def_t, 1);
    memcpy(env->def, def, sizeof(*def));

    featurestr = strtok(NULL, ",");
    cc->parse_features(CPU(cpu), featurestr, &err);
    g_free(s);
    if (err) {
        //error_report("%s", error_get_pretty(err));
        error_free(err);
        return -1;
    }

    env->version = def->iu_version;
    env->fsr = def->fpu_version;
    env->nwindows = def->nwindows;
#if !defined(TARGET_SPARC64)
    env->mmuregs[0] |= def->mmu_version;
    cpu_sparc_set_id(env, 0);
    env->mxccregs[7] |= def->mxcc_version;
#else
    env->mmu_version = def->mmu_version;
    env->maxtl = def->maxtl;
    env->version |= def->maxtl << 8;
    env->version |= def->nwindows - 1;
#endif
    return 0;
}

SPARCCPU *cpu_sparc_init(struct uc_struct *uc, const char *cpu_model)
{
    SPARCCPU *cpu;

    cpu = SPARC_CPU(uc, object_new(uc, TYPE_SPARC_CPU));

    if (cpu_sparc_register(uc, cpu, cpu_model) < 0) {
        object_unref(uc, OBJECT(cpu));
        return NULL;
    }

    object_property_set_bool(uc, OBJECT(cpu), true, "realized", NULL);

    return cpu;
}

void cpu_sparc_set_id(CPUSPARCState *env, unsigned int cpu)
{
#if !defined(TARGET_SPARC64)
    env->mxccregs[7] = ((cpu + 8) & 0xf) << 24;
#endif
}

static const sparc_def_t sparc_defs[] = {
#ifdef TARGET_SPARC64
    {
        "Fujitsu Sparc64",
        ((0x04ULL << 48) | (0x02ULL << 32) | (0ULL << 24)),
        0x00000000,
        mmu_us_12,
        0,0,0,0,0,0,
        CPU_DEFAULT_FEATURES,
        4,
        4,
    },
    {
        "Fujitsu Sparc64 III",
        ((0x04ULL << 48) | (0x03ULL << 32) | (0ULL << 24)),
        0x00000000,
        mmu_us_12,
        0,0,0,0,0,0,
        CPU_DEFAULT_FEATURES,
        5,
        4,
    },
    {
        "Fujitsu Sparc64 IV",
        ((0x04ULL << 48) | (0x04ULL << 32) | (0ULL << 24)),
        0x00000000,
        mmu_us_12,
        0,0,0,0,0,0,
        CPU_DEFAULT_FEATURES,
        8,
        5,
    },
    {
        "Fujitsu Sparc64 V",
        ((0x04ULL << 48) | (0x05ULL << 32) | (0x51ULL << 24)),
        0x00000000,
        mmu_us_12,
        0,0,0,0,0,0,
        CPU_DEFAULT_FEATURES,
        8,
        5,
    },
    {
        "TI UltraSparc I",
        ((0x17ULL << 48) | (0x10ULL << 32) | (0x40ULL << 24)),
        0x00000000,
        mmu_us_12,
        0,0,0,0,0,0,
        CPU_DEFAULT_FEATURES,
        8,
        5,
    },
    {
        "TI UltraSparc II",
        ((0x17ULL << 48) | (0x11ULL << 32) | (0x20ULL << 24)),
        0x00000000,
        mmu_us_12,
        0,0,0,0,0,0,
        CPU_DEFAULT_FEATURES,
        8,
        5,
    },
    {
        "TI UltraSparc IIi",
        ((0x17ULL << 48) | (0x12ULL << 32) | (0x91ULL << 24)),
        0x00000000,
        mmu_us_12,
        0,0,0,0,0,0,
        CPU_DEFAULT_FEATURES,
        8,
        5,
    },
    {
        "TI UltraSparc IIe",
        ((0x17ULL << 48) | (0x13ULL << 32) | (0x14ULL << 24)),
        0x00000000,
        mmu_us_12,
        0,0,0,0,0,0,
        CPU_DEFAULT_FEATURES,
        8,
        5,
    },
    {
        "Sun UltraSparc III",
        ((0x3eULL << 48) | (0x14ULL << 32) | (0x34ULL << 24)),
        0x00000000,
        mmu_us_12,
        0,0,0,0,0,0,
        CPU_DEFAULT_FEATURES,
        8,
        5,
    },
    {
        "Sun UltraSparc III Cu",
        ((0x3eULL << 48) | (0x15ULL << 32) | (0x41ULL << 24)),
        0x00000000,
        mmu_us_3,
        0,0,0,0,0,0,
        CPU_DEFAULT_FEATURES,
        8,
        5,
    },
    {
        "Sun UltraSparc IIIi",
        ((0x3eULL << 48) | (0x16ULL << 32) | (0x34ULL << 24)),
        0x00000000,
        mmu_us_12,
        0,0,0,0,0,0,
        CPU_DEFAULT_FEATURES,
        8,
        5,
    },
    {
        "Sun UltraSparc IV",
        ((0x3eULL << 48) | (0x18ULL << 32) | (0x31ULL << 24)),
        0x00000000,
        mmu_us_4,
        0,0,0,0,0,0,
        CPU_DEFAULT_FEATURES,
        8,
        5,
    },
    {
        "Sun UltraSparc IV+",
        ((0x3eULL << 48) | (0x19ULL << 32) | (0x22ULL << 24)),
        0x00000000,
        mmu_us_12,
        0,0,0,0,0,0,
        CPU_DEFAULT_FEATURES | CPU_FEATURE_CMT,
        8,
        5,
    },
    {
        "Sun UltraSparc IIIi+",
        ((0x3eULL << 48) | (0x22ULL << 32) | (0ULL << 24)),
        0x00000000,
        mmu_us_3,
        0,0,0,0,0,0,
        CPU_DEFAULT_FEATURES,
        8,
        5,
    },
    {
        "Sun UltraSparc T1",
        /* defined in sparc_ifu_fdp.v and ctu.h */
        ((0x3eULL << 48) | (0x23ULL << 32) | (0x02ULL << 24)),
        0x00000000,
        mmu_sun4v,
        0,0,0,0,0,0,
        CPU_DEFAULT_FEATURES | CPU_FEATURE_HYPV | CPU_FEATURE_CMT
          | CPU_FEATURE_GL,
        8,
        6,
    },
    {
        "Sun UltraSparc T2",
        /* defined in tlu_asi_ctl.v and n2_revid_cust.v */
        ((0x3eULL << 48) | (0x24ULL << 32) | (0x02ULL << 24)),
        0x00000000,
        mmu_sun4v,
        0,0,0,0,0,0,
        CPU_DEFAULT_FEATURES | CPU_FEATURE_HYPV | CPU_FEATURE_CMT
          | CPU_FEATURE_GL,
        8,
        6,
    },
    {
        "NEC UltraSparc I",
        ((0x22ULL << 48) | (0x10ULL << 32) | (0x40ULL << 24)),
        0x00000000,
        mmu_us_12,
        0,0,0,0,0,0,
        CPU_DEFAULT_FEATURES,
        8,
        5,
    },
#else
    {
        "Fujitsu MB86904",
        0x04 << 24, /* Impl 0, ver 4 */
        4 << 17, /* FPU version 4 (Meiko) */
        0x04 << 24, /* Impl 0, ver 4 */
        0x00004000,
        0x00ffffc0,
        0x000000ff,
        0x00016fff,
        0x00ffffff,
        0,
        CPU_DEFAULT_FEATURES,
        8,
        0,
    },
    {
        "Fujitsu MB86907",
        0x05 << 24, /* Impl 0, ver 5 */
        4 << 17, /* FPU version 4 (Meiko) */
        0x05 << 24, /* Impl 0, ver 5 */
        0x00004000,
        0xffffffc0,
        0x000000ff,
        0x00016fff,
        0xffffffff,
        0,
        CPU_DEFAULT_FEATURES,
        8,
        0,
    },
    {
        "TI MicroSparc I",
        0x41000000,
        4 << 17,
        0x41000000,
        0x00004000,
        0x007ffff0,
        0x0000003f,
        0x00016fff,
        0x0000003f,
        0,
        CPU_FEATURE_FLOAT | CPU_FEATURE_SWAP | CPU_FEATURE_MUL |
          CPU_FEATURE_DIV | CPU_FEATURE_FLUSH | CPU_FEATURE_FSQRT |
          CPU_FEATURE_FMUL,
        7,
        0,
    },
    {
        "TI MicroSparc II",
        0x42000000,
        4 << 17,
        0x02000000,
        0x00004000,
        0x00ffffc0,
        0x000000ff,
        0x00016fff,
        0x00ffffff,
        0,
        CPU_DEFAULT_FEATURES,
        8,
        0,
    },
    {
        "TI MicroSparc IIep",
        0x42000000,
        4 << 17,
        0x04000000,
        0x00004000,
        0x00ffffc0,
        0x000000ff,
        0x00016bff,
        0x00ffffff,
        0,
        CPU_DEFAULT_FEATURES,
        8,
        0,
    },
    {
        "TI SuperSparc 40", /* STP1020NPGA */
        0x41000000, /* SuperSPARC 2.x */
        0 << 17,
        0x00000800, /* SuperSPARC 2.x, no MXCC */
        0x00002000,
        0xffffffc0,
        0x0000ffff,
        0xffffffff,
        0xffffffff,
        0,
        CPU_DEFAULT_FEATURES,
        8,
        0,
    },
    {
        "TI SuperSparc 50", /* STP1020PGA */
        0x40000000, /* SuperSPARC 3.x */
        0 << 17,
        0x01000800, /* SuperSPARC 3.x, no MXCC */
        0x00002000,
        0xffffffc0,
        0x0000ffff,
        0xffffffff,
        0xffffffff,
        0,
        CPU_DEFAULT_FEATURES,
        8,
        0,
    },
    {
        "TI SuperSparc 51",
        0x40000000, /* SuperSPARC 3.x */
        0 << 17,
        0x01000000, /* SuperSPARC 3.x, MXCC */
        0x00002000,
        0xffffffc0,
        0x0000ffff,
        0xffffffff,
        0xffffffff,
        0x00000104,
        CPU_DEFAULT_FEATURES,
        8,
        0,
    },
    {
        "TI SuperSparc 60", /* STP1020APGA */
        0x40000000, /* SuperSPARC 3.x */
        0 << 17,
        0x01000800, /* SuperSPARC 3.x, no MXCC */
        0x00002000,
        0xffffffc0,
        0x0000ffff,
        0xffffffff,
        0xffffffff,
        0,
        CPU_DEFAULT_FEATURES,
        8,
        0,
    },
    {
        "TI SuperSparc 61",
        0x44000000, /* SuperSPARC 3.x */
        0 << 17,
        0x01000000, /* SuperSPARC 3.x, MXCC */
        0x00002000,
        0xffffffc0,
        0x0000ffff,
        0xffffffff,
        0xffffffff,
        0x00000104,
        CPU_DEFAULT_FEATURES,
        8,
        0,
    },
    {
        "TI SuperSparc II",
        0x40000000, /* SuperSPARC II 1.x */
        0 << 17,
        0x08000000, /* SuperSPARC II 1.x, MXCC */
        0x00002000,
        0xffffffc0,
        0x0000ffff,
        0xffffffff,
        0xffffffff,
        0x00000104,
        CPU_DEFAULT_FEATURES,
        8,
        0,
    },
    {
        "LEON2",
        0xf2000000,
        4 << 17, /* FPU version 4 (Meiko) */
        0xf2000000,
        0x00004000,
        0x007ffff0,
        0x0000003f,
        0xffffffff,
        0xffffffff,
        0,
        CPU_DEFAULT_FEATURES | CPU_FEATURE_TA0_SHUTDOWN,
        8,
        0,
    },
    {
        "LEON3",
        0xf3000000,
        4 << 17, /* FPU version 4 (Meiko) */
        0xf3000000,
        0x00000000,
        0xfffffffc,
        0x000000ff,
        0xffffffff,
        0xffffffff,
        0,
        CPU_DEFAULT_FEATURES | CPU_FEATURE_TA0_SHUTDOWN |
          CPU_FEATURE_ASR17 | CPU_FEATURE_CACHE_CTRL | CPU_FEATURE_POWERDOWN |
          CPU_FEATURE_CASA,
        8,
        0,
    },
#endif
};

static const char * const feature_name[] = {
    "float",
    "float128",
    "swap",
    "mul",
    "div",
    "flush",
    "fsqrt",
    "fmul",
    "vis1",
    "vis2",
    "fsmuld",
    "hypv",
    "cmt",
    "gl",
};

#if 0
static void print_features(FILE *f, fprintf_function cpu_fprintf,
                           uint32_t features, const char *prefix)
{
    unsigned int i;

    for (i = 0; i < ARRAY_SIZE(feature_name); i++) {
        if (feature_name[i] && (features & (1 << i))) {
            if (prefix) {
                (*cpu_fprintf)(f, "%s", prefix);
            }
            (*cpu_fprintf)(f, "%s ", feature_name[i]);
        }
    }
}
#endif

static void add_flagname_to_bitmaps(const char *flagname, uint32_t *features)
{
    unsigned int i;

    for (i = 0; i < ARRAY_SIZE(feature_name); i++) {
        if (feature_name[i] && !strcmp(flagname, feature_name[i])) {
            *features |= 1 << i;
            return;
        }
    }
    //error_report("CPU feature %s not found", flagname);
}

static int cpu_sparc_find_by_name(sparc_def_t *cpu_def, const char *name)
{
    unsigned int i;
    const sparc_def_t *def = NULL;

    for (i = 0; i < ARRAY_SIZE(sparc_defs); i++) {
        if (strcasecmp(name, sparc_defs[i].name) == 0) {
            def = &sparc_defs[i];
        }
    }
    if (!def) {
        return -1;
    }
    memcpy(cpu_def, def, sizeof(*def));
    return 0;
}

static void sparc_cpu_parse_features(CPUState *cs, char *features,
                                     Error **errp)
{
    SPARCCPU *cpu = SPARC_CPU(cs->uc, cs);
    sparc_def_t *cpu_def = cpu->env.def;
    char *featurestr;
    uint32_t plus_features = 0;
    uint32_t minus_features = 0;
    uint64_t iu_version;
    uint32_t fpu_version, mmu_version, nwindows;

    featurestr = features ? strtok(features, ",") : NULL;
    while (featurestr) {
        char *val;

        if (featurestr[0] == '+') {
            add_flagname_to_bitmaps(featurestr + 1, &plus_features);
        } else if (featurestr[0] == '-') {
            add_flagname_to_bitmaps(featurestr + 1, &minus_features);
        } else if ((val = strchr(featurestr, '='))) {
            *val = 0; val++;
            if (!strcmp(featurestr, "iu_version")) {
                char *err;

                iu_version = strtoll(val, &err, 0);
                if (!*val || *err) {
                    error_setg(errp, "bad numerical value %s", val);
                    return;
                }
                cpu_def->iu_version = iu_version;
#ifdef DEBUG_FEATURES
                fprintf(stderr, "iu_version %" PRIx64 "\n", iu_version);
#endif
            } else if (!strcmp(featurestr, "fpu_version")) {
                char *err;

                fpu_version = strtol(val, &err, 0);
                if (!*val || *err) {
                    error_setg(errp, "bad numerical value %s", val);
                    return;
                }
                cpu_def->fpu_version = fpu_version;
#ifdef DEBUG_FEATURES
                fprintf(stderr, "fpu_version %x\n", fpu_version);
#endif
            } else if (!strcmp(featurestr, "mmu_version")) {
                char *err;

                mmu_version = strtol(val, &err, 0);
                if (!*val || *err) {
                    error_setg(errp, "bad numerical value %s", val);
                    return;
                }
                cpu_def->mmu_version = mmu_version;
#ifdef DEBUG_FEATURES
                fprintf(stderr, "mmu_version %x\n", mmu_version);
#endif
            } else if (!strcmp(featurestr, "nwindows")) {
                char *err;

                nwindows = strtol(val, &err, 0);
                if (!*val || *err || nwindows > MAX_NWINDOWS ||
                    nwindows < MIN_NWINDOWS) {
                    error_setg(errp, "bad numerical value %s", val);
                    return;
                }
                cpu_def->nwindows = nwindows;
#ifdef DEBUG_FEATURES
                fprintf(stderr, "nwindows %d\n", nwindows);
#endif
            } else {
                error_setg(errp, "unrecognized feature %s", featurestr);
                return;
            }
        } else {
            error_setg(errp, "feature string `%s' not in format "
                             "(+feature|-feature|feature=xyz)", featurestr);
            return;
        }
        featurestr = strtok(NULL, ",");
    }
    cpu_def->features |= plus_features;
    cpu_def->features &= ~minus_features;
#ifdef DEBUG_FEATURES
    print_features(stderr, fprintf, cpu_def->features, NULL);
#endif
}

#if 0
void sparc_cpu_list(FILE *f, fprintf_function cpu_fprintf)
{
    unsigned int i;

    for (i = 0; i < ARRAY_SIZE(sparc_defs); i++) {
        (*cpu_fprintf)(f, "Sparc %16s IU " TARGET_FMT_lx
                       " FPU %08x MMU %08x NWINS %d ",
                       sparc_defs[i].name,
                       sparc_defs[i].iu_version,
                       sparc_defs[i].fpu_version,
                       sparc_defs[i].mmu_version,
                       sparc_defs[i].nwindows);
        print_features(f, cpu_fprintf, CPU_DEFAULT_FEATURES &
                       ~sparc_defs[i].features, "-");
        print_features(f, cpu_fprintf, ~CPU_DEFAULT_FEATURES &
                       sparc_defs[i].features, "+");
        (*cpu_fprintf)(f, "\n");
    }
    (*cpu_fprintf)(f, "Default CPU feature flags (use '-' to remove): ");
    print_features(f, cpu_fprintf, CPU_DEFAULT_FEATURES, NULL);
    (*cpu_fprintf)(f, "\n");
    (*cpu_fprintf)(f, "Available CPU feature flags (use '+' to add): ");
    print_features(f, cpu_fprintf, ~CPU_DEFAULT_FEATURES, NULL);
    (*cpu_fprintf)(f, "\n");
    (*cpu_fprintf)(f, "Numerical features (use '=' to set): iu_version "
                   "fpu_version mmu_version nwindows\n");
}

static void cpu_print_cc(FILE *f, fprintf_function cpu_fprintf,
                         uint32_t cc)
{
    cpu_fprintf(f, "%c%c%c%c", cc & PSR_NEG ? 'N' : '-',
                cc & PSR_ZERO ? 'Z' : '-', cc & PSR_OVF ? 'V' : '-',
                cc & PSR_CARRY ? 'C' : '-');
}

#ifdef TARGET_SPARC64
#define REGS_PER_LINE 4
#else
#define REGS_PER_LINE 8
#endif

void sparc_cpu_dump_state(CPUState *cs, FILE *f, fprintf_function cpu_fprintf,
                          int flags)
{
    SPARCCPU *cpu = SPARC_CPU(cs);
    CPUSPARCState *env = &cpu->env;
    int i, x;

    cpu_fprintf(f, "pc: " TARGET_FMT_lx "  npc: " TARGET_FMT_lx "\n", env->pc,
                env->npc);

    for (i = 0; i < 8; i++) {
        if (i % REGS_PER_LINE == 0) {
            cpu_fprintf(f, "%%g%d-%d:", i, i + REGS_PER_LINE - 1);
        }
        cpu_fprintf(f, " " TARGET_FMT_lx, env->gregs[i]);
        if (i % REGS_PER_LINE == REGS_PER_LINE - 1) {
            cpu_fprintf(f, "\n");
        }
    }
    for (x = 0; x < 3; x++) {
        for (i = 0; i < 8; i++) {
            if (i % REGS_PER_LINE == 0) {
                cpu_fprintf(f, "%%%c%d-%d: ",
                            x == 0 ? 'o' : (x == 1 ? 'l' : 'i'),
                            i, i + REGS_PER_LINE - 1);
            }
            cpu_fprintf(f, TARGET_FMT_lx " ", env->regwptr[i + x * 8]);
            if (i % REGS_PER_LINE == REGS_PER_LINE - 1) {
                cpu_fprintf(f, "\n");
            }
        }
    }

    for (i = 0; i < TARGET_DPREGS; i++) {
        if ((i & 3) == 0) {
            cpu_fprintf(f, "%%f%02d: ", i * 2);
        }
        cpu_fprintf(f, " %016" PRIx64, env->fpr[i].ll);
        if ((i & 3) == 3) {
            cpu_fprintf(f, "\n");
        }
    }
#ifdef TARGET_SPARC64
    cpu_fprintf(f, "pstate: %08x ccr: %02x (icc: ", env->pstate,
                (unsigned)cpu_get_ccr(env));
    cpu_print_cc(f, cpu_fprintf, cpu_get_ccr(env) << PSR_CARRY_SHIFT);
    cpu_fprintf(f, " xcc: ");
    cpu_print_cc(f, cpu_fprintf, cpu_get_ccr(env) << (PSR_CARRY_SHIFT - 4));
    cpu_fprintf(f, ") asi: %02x tl: %d pil: %x\n", env->asi, env->tl,
                env->psrpil);
    cpu_fprintf(f, "cansave: %d canrestore: %d otherwin: %d wstate: %d "
                "cleanwin: %d cwp: %d\n",
                env->cansave, env->canrestore, env->otherwin, env->wstate,
                env->cleanwin, env->nwindows - 1 - env->cwp);
    cpu_fprintf(f, "fsr: " TARGET_FMT_lx " y: " TARGET_FMT_lx " fprs: "
                TARGET_FMT_lx "\n", env->fsr, env->y, env->fprs);
#else
    cpu_fprintf(f, "psr: %08x (icc: ", cpu_get_psr(env));
    cpu_print_cc(f, cpu_fprintf, cpu_get_psr(env));
    cpu_fprintf(f, " SPE: %c%c%c) wim: %08x\n", env->psrs ? 'S' : '-',
                env->psrps ? 'P' : '-', env->psret ? 'E' : '-',
                env->wim);
    cpu_fprintf(f, "fsr: " TARGET_FMT_lx " y: " TARGET_FMT_lx "\n",
                env->fsr, env->y);
#endif
    cpu_fprintf(f, "\n");
}
#endif

static void sparc_cpu_set_pc(CPUState *cs, vaddr value)
{
    SPARCCPU *cpu = SPARC_CPU(cs->uc, cs);

    cpu->env.pc = value;
    cpu->env.npc = value + 4;
}

static void sparc_cpu_synchronize_from_tb(CPUState *cs, TranslationBlock *tb)
{
    SPARCCPU *cpu = SPARC_CPU(cs->uc, cs);

    cpu->env.pc = tb->pc;
    cpu->env.npc = tb->cs_base;
}

static bool sparc_cpu_has_work(CPUState *cs)
{
    SPARCCPU *cpu = SPARC_CPU(cs->uc, cs);
    CPUSPARCState *env = &cpu->env;

    return (cs->interrupt_request & CPU_INTERRUPT_HARD) &&
        cpu_interrupts_enabled(env);
}

static int sparc_cpu_realizefn(struct uc_struct *uc, DeviceState *dev, Error **errp)
{
    SPARCCPUClass *scc = SPARC_CPU_GET_CLASS(uc, dev);
#if defined(CONFIG_USER_ONLY)
    SPARCCPU *cpu = SPARC_CPU(uc, dev);
    CPUSPARCState *env = &cpu->env;

    if ((env->def->features & CPU_FEATURE_FLOAT)) {
        env->def->features |= CPU_FEATURE_FLOAT128;
    }
#endif

    qemu_init_vcpu(CPU(dev));

    scc->parent_realize(uc, dev, errp);

    return 0;
}

static void sparc_cpu_initfn(struct uc_struct *uc, Object *obj, void *opaque)
{
    CPUState *cs = CPU(obj);
    SPARCCPU *cpu = SPARC_CPU(uc, obj);
    CPUSPARCState *env = &cpu->env;

    cs->env_ptr = env;
    cpu_exec_init(env, opaque);

    if (tcg_enabled(uc)) {
        gen_intermediate_code_init(env);
    }
}

static void sparc_cpu_uninitfn(struct uc_struct *uc, Object *obj, void *opaque)
{
    SPARCCPU *cpu = SPARC_CPU(uc, obj);
    CPUSPARCState *env = &cpu->env;

    g_free(env->def);
}

static void sparc_cpu_class_init(struct uc_struct *uc, ObjectClass *oc, void *data)
{
    SPARCCPUClass *scc = SPARC_CPU_CLASS(uc, oc);
    CPUClass *cc = CPU_CLASS(uc, oc);
    DeviceClass *dc = DEVICE_CLASS(uc, oc);

    scc->parent_realize = dc->realize;
    dc->realize = sparc_cpu_realizefn;

    scc->parent_reset = cc->reset;
    cc->reset = sparc_cpu_reset;

    cc->parse_features = sparc_cpu_parse_features;
    cc->has_work = sparc_cpu_has_work;
    cc->do_interrupt = sparc_cpu_do_interrupt;
    cc->cpu_exec_interrupt = sparc_cpu_exec_interrupt;
    //cc->dump_state = sparc_cpu_dump_state;
#if !defined(TARGET_SPARC64) && !defined(CONFIG_USER_ONLY)
    cc->memory_rw_debug = sparc_cpu_memory_rw_debug;
#endif
    cc->set_pc = sparc_cpu_set_pc;
    cc->synchronize_from_tb = sparc_cpu_synchronize_from_tb;
#ifdef CONFIG_USER_ONLY
    cc->handle_mmu_fault = sparc_cpu_handle_mmu_fault;
#else
    cc->do_unassigned_access = sparc_cpu_unassigned_access;
    cc->do_unaligned_access = sparc_cpu_do_unaligned_access;
    cc->get_phys_page_debug = sparc_cpu_get_phys_page_debug;
#endif
}

void sparc_cpu_register_types(void *opaque)
{
    const TypeInfo sparc_cpu_type_info = {
        TYPE_SPARC_CPU,
        TYPE_CPU,
        
        sizeof(SPARCCPUClass),
        sizeof(SPARCCPU),
        opaque,
        
        sparc_cpu_initfn,
        NULL,
        sparc_cpu_uninitfn,
        
        NULL,

        sparc_cpu_class_init,
        NULL,
        NULL,

        false,
    };

    //printf(">>> sparc_cpu_register_types\n");
    type_register_static(opaque, &sparc_cpu_type_info);
}
