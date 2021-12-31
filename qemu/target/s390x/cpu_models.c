/*
 * CPU models for s390x
 *
 * Copyright 2016 IBM Corp.
 *
 * Author(s): David Hildenbrand <dahi@linux.vnet.ibm.com>
 *
 * This work is licensed under the terms of the GNU GPL, version 2 or (at
 * your option) any later version. See the COPYING file in the top-level
 * directory.
 */

#include "qemu/osdep.h"
#include "cpu.h"
#include "internal.h"
#include "sysemu/tcg.h"
#include "qemu-common.h"
//#include "hw/pci/pci.h"

#define CPUDEF_INIT(_type, _gen, _ec_ga, _mha_pow, _hmfai, _name, _desc) \
    {                                                                    \
        .name = _name,                                                   \
        .type = _type,                                                   \
        .gen = _gen,                                                     \
        .ec_ga = _ec_ga,                                                 \
        .mha_pow = _mha_pow,                                             \
        .hmfai = _hmfai,                                                 \
        .desc = _desc,                                                   \
        .base_init = { S390_FEAT_LIST_GEN ## _gen ## _GA ## _ec_ga ## _BASE },  \
        .default_init = { S390_FEAT_LIST_GEN ## _gen ## _GA ## _ec_ga ## _DEFAULT },  \
        .full_init = { S390_FEAT_LIST_GEN ## _gen ## _GA ## _ec_ga ## _FULL },  \
    }

/*
 * CPU definition list in order of release. Up to generation 14 base features
 * of a following release have been a superset of the previous release. With
 * generation 15 one base feature and one optional feature have been deprecated.
 */
static S390CPUDef s390_cpu_defs[] = {
    CPUDEF_INIT(0x2064, 7, 1, 38, 0x00000000U, "z900", "IBM zSeries 900 GA1"),
    CPUDEF_INIT(0x2064, 7, 2, 38, 0x00000000U, "z900.2", "IBM zSeries 900 GA2"),
    CPUDEF_INIT(0x2064, 7, 3, 38, 0x00000000U, "z900.3", "IBM zSeries 900 GA3"),
    CPUDEF_INIT(0x2066, 7, 3, 38, 0x00000000U, "z800", "IBM zSeries 800 GA1"),
    CPUDEF_INIT(0x2084, 8, 1, 38, 0x00000000U, "z990", "IBM zSeries 990 GA1"),
    CPUDEF_INIT(0x2084, 8, 2, 38, 0x00000000U, "z990.2", "IBM zSeries 990 GA2"),
    CPUDEF_INIT(0x2084, 8, 3, 38, 0x00000000U, "z990.3", "IBM zSeries 990 GA3"),
    CPUDEF_INIT(0x2086, 8, 3, 38, 0x00000000U, "z890", "IBM zSeries 880 GA1"),
    CPUDEF_INIT(0x2084, 8, 4, 38, 0x00000000U, "z990.4", "IBM zSeries 990 GA4"),
    CPUDEF_INIT(0x2086, 8, 4, 38, 0x00000000U, "z890.2", "IBM zSeries 880 GA2"),
    CPUDEF_INIT(0x2084, 8, 5, 38, 0x00000000U, "z990.5", "IBM zSeries 990 GA5"),
    CPUDEF_INIT(0x2086, 8, 5, 38, 0x00000000U, "z890.3", "IBM zSeries 880 GA3"),
    CPUDEF_INIT(0x2094, 9, 1, 40, 0x00000000U, "z9EC", "IBM System z9 EC GA1"),
    CPUDEF_INIT(0x2094, 9, 2, 40, 0x00000000U, "z9EC.2", "IBM System z9 EC GA2"),
    CPUDEF_INIT(0x2096, 9, 2, 40, 0x00000000U, "z9BC", "IBM System z9 BC GA1"),
    CPUDEF_INIT(0x2094, 9, 3, 40, 0x00000000U, "z9EC.3", "IBM System z9 EC GA3"),
    CPUDEF_INIT(0x2096, 9, 3, 40, 0x00000000U, "z9BC.2", "IBM System z9 BC GA2"),
    CPUDEF_INIT(0x2097, 10, 1, 43, 0x00000000U, "z10EC", "IBM System z10 EC GA1"),
    CPUDEF_INIT(0x2097, 10, 2, 43, 0x00000000U, "z10EC.2", "IBM System z10 EC GA2"),
    CPUDEF_INIT(0x2098, 10, 2, 43, 0x00000000U, "z10BC", "IBM System z10 BC GA1"),
    CPUDEF_INIT(0x2097, 10, 3, 43, 0x00000000U, "z10EC.3", "IBM System z10 EC GA3"),
    CPUDEF_INIT(0x2098, 10, 3, 43, 0x00000000U, "z10BC.2", "IBM System z10 BC GA2"),
    CPUDEF_INIT(0x2817, 11, 1, 44, 0x08000000U, "z196", "IBM zEnterprise 196 GA1"),
    CPUDEF_INIT(0x2817, 11, 2, 44, 0x08000000U, "z196.2", "IBM zEnterprise 196 GA2"),
    CPUDEF_INIT(0x2818, 11, 2, 44, 0x08000000U, "z114", "IBM zEnterprise 114 GA1"),
    CPUDEF_INIT(0x2827, 12, 1, 44, 0x08000000U, "zEC12", "IBM zEnterprise EC12 GA1"),
    CPUDEF_INIT(0x2827, 12, 2, 44, 0x08000000U, "zEC12.2", "IBM zEnterprise EC12 GA2"),
    CPUDEF_INIT(0x2828, 12, 2, 44, 0x08000000U, "zBC12", "IBM zEnterprise BC12 GA1"),
    CPUDEF_INIT(0x2964, 13, 1, 47, 0x08000000U, "z13", "IBM z13 GA1"),
    CPUDEF_INIT(0x2964, 13, 2, 47, 0x08000000U, "z13.2", "IBM z13 GA2"),
    CPUDEF_INIT(0x2965, 13, 2, 47, 0x08000000U, "z13s", "IBM z13s GA1"),
    CPUDEF_INIT(0x3906, 14, 1, 47, 0x08000000U, "z14", "IBM z14 GA1"),
    CPUDEF_INIT(0x3906, 14, 2, 47, 0x08000000U, "z14.2", "IBM z14 GA2"),
    CPUDEF_INIT(0x3907, 14, 1, 47, 0x08000000U, "z14ZR1", "IBM z14 Model ZR1 GA1"),
    CPUDEF_INIT(0x8561, 15, 1, 47, 0x08000000U, "gen15a", "IBM z15 GA1"),
    CPUDEF_INIT(0x8562, 15, 1, 47, 0x08000000U, "gen15b", "IBM 8562 GA1"),
};

#define QEMU_MAX_CPU_TYPE 0x2964
#define QEMU_MAX_CPU_GEN 13
#define QEMU_MAX_CPU_EC_GA 2
static const S390FeatInit qemu_max_cpu_feat_init = { S390_FEAT_LIST_QEMU_MAX };
static S390FeatBitmap qemu_max_cpu_feat;

/* features part of a base model but not relevant for finding a base model */
S390FeatBitmap ignored_base_feat;

void s390_cpudef_featoff(uint8_t gen, uint8_t ec_ga, S390Feat feat)
{
    const S390CPUDef *def;

    def = s390_find_cpu_def(0, gen, ec_ga, NULL);
    clear_bit(feat, (unsigned long *)&def->default_feat);
}

void s390_cpudef_featoff_greater(uint8_t gen, uint8_t ec_ga, S390Feat feat)
{
    int i;

    for (i = 0; i < ARRAY_SIZE(s390_cpu_defs); i++) {
        const S390CPUDef *def = &s390_cpu_defs[i];

        if (def->gen < gen) {
            continue;
        }
        if (def->gen == gen && def->ec_ga < ec_ga) {
            continue;
        }

        clear_bit(feat, (unsigned long *)&def->default_feat);
    }
}

void s390_cpudef_group_featoff_greater(uint8_t gen, uint8_t ec_ga,
                                       S390FeatGroup group)
{
    const S390FeatGroupDef *group_def = s390_feat_group_def(group);
    S390FeatBitmap group_def_off;
    int i;

    bitmap_complement(group_def_off, group_def->feat, S390_FEAT_MAX);

    for (i = 0; i < ARRAY_SIZE(s390_cpu_defs); i++) {
        const S390CPUDef *cpu_def = &s390_cpu_defs[i];

        if (cpu_def->gen < gen) {
            continue;
        }
        if (cpu_def->gen == gen && cpu_def->ec_ga < ec_ga) {
            continue;
        }

        bitmap_and((unsigned long *)&cpu_def->default_feat,
                   cpu_def->default_feat, group_def_off, S390_FEAT_MAX);
    }
}

uint32_t s390_get_hmfai(void)
{
    static S390CPU *cpu;

    if (!cpu) {
        cpu = S390_CPU(qemu_get_cpu(NULL, 0));
    }

    if (!cpu || !cpu->model) {
        return 0;
    }
    return cpu->model->def->hmfai;
}

uint8_t s390_get_mha_pow(void)
{
    static S390CPU *cpu;

    if (!cpu) {
        cpu = S390_CPU(qemu_get_cpu(NULL, 0));
    }

    if (!cpu || !cpu->model) {
        return 0;
    }
    return cpu->model->def->mha_pow;
}

uint32_t s390_get_ibc_val(void)
{
    uint16_t unblocked_ibc, lowest_ibc;
    static S390CPU *cpu;

    if (!cpu) {
        cpu = S390_CPU(qemu_get_cpu(NULL, 0));
    }

    if (!cpu || !cpu->model) {
        return 0;
    }
    unblocked_ibc = s390_ibc_from_cpu_model(cpu->model);
    lowest_ibc = cpu->model->lowest_ibc;
    /* the lowest_ibc always has to be <= unblocked_ibc */
    if (!lowest_ibc || lowest_ibc > unblocked_ibc) {
        return 0;
    }
    return ((uint32_t) lowest_ibc << 16) | unblocked_ibc;
}

void s390_get_feat_block(struct uc_struct *uc, S390FeatType type, uint8_t *data)
{
    S390CPU *cpu = S390_CPU(qemu_get_cpu(uc, 0));
    s390_fill_feat_block(cpu->model->features, type, data);
}

bool s390_has_feat(struct uc_struct *uc, S390Feat feat)
{
    S390CPU *cpu = S390_CPU(qemu_get_cpu(uc, 0));
    if (!cpu->model) {
        if (feat == S390_FEAT_ZPCI) {
            return true;
        }
        return false;
    }
    return test_bit(feat, cpu->model->features);
}

uint8_t s390_get_gen_for_cpu_type(uint16_t type)
{
    int i;

    for (i = 0; i < ARRAY_SIZE(s390_cpu_defs); i++) {
        if (s390_cpu_defs[i].type == type) {
            return s390_cpu_defs[i].gen;
        }
    }
    return 0;
}

const S390CPUDef *s390_find_cpu_def(uint16_t type, uint8_t gen, uint8_t ec_ga,
                                    S390FeatBitmap features)
{
    const S390CPUDef *last_compatible = NULL;
    const S390CPUDef *matching_cpu_type = NULL;
    int i;

    if (!gen) {
        ec_ga = 0;
    }
    if (!gen && type) {
        gen = s390_get_gen_for_cpu_type(type);
    }

    for (i = 0; i < ARRAY_SIZE(s390_cpu_defs); i++) {
        const S390CPUDef *def = &s390_cpu_defs[i];
        S390FeatBitmap missing;

        /* don't even try newer generations if we know the generation */
        if (gen) {
            if (def->gen > gen) {
                break;
            } else if (def->gen == gen && ec_ga && def->ec_ga > ec_ga) {
                break;
            }
        }

        if (features) {
            /* see if the model satisfies the minimum features */
            bitmap_andnot(missing, def->base_feat, features, S390_FEAT_MAX);
            /*
             * Ignore certain features that are in the base model, but not
             * relevant for the search (esp. MSA subfunctions).
             */
            bitmap_andnot(missing, missing, ignored_base_feat, S390_FEAT_MAX);
            if (!bitmap_empty(missing, S390_FEAT_MAX)) {
                break;
            }
        }

        /* stop the search if we found the exact model */
        if (def->type == type && def->ec_ga == ec_ga) {
            return def;
        }
        /* remember if we've at least seen one with the same cpu type */
        if (def->type == type) {
            matching_cpu_type = def;
        }
        last_compatible = def;
    }
    /* prefer the model with the same cpu type, esp. don't take the BC for EC */
    if (matching_cpu_type) {
        return matching_cpu_type;
    }
    return last_compatible;
}

static S390CPUModel *get_max_cpu_model(void);

static S390CPUModel *get_max_cpu_model(void)
{
    static S390CPUModel max_model;
    static bool cached;

    if (cached) {
        return &max_model;
    }

    max_model.def = s390_find_cpu_def(QEMU_MAX_CPU_TYPE, QEMU_MAX_CPU_GEN,
            QEMU_MAX_CPU_EC_GA, NULL);
    bitmap_copy(max_model.features, qemu_max_cpu_feat, S390_FEAT_MAX);
    cached = true;
    return &max_model;
}

static inline void apply_cpu_model(const S390CPUModel *model)
{
    static S390CPUModel applied_model;
    static bool applied;

    /*
     * We have the same model for all VCPUs. KVM can only be configured before
     * any VCPUs are defined in KVM.
     */
    if (applied) {
        if (model && memcmp(&applied_model, model, sizeof(S390CPUModel))) {
            // error_setg(errp, "Mixed CPU models are not supported on s390x.");
        }
        return;
    }

    applied = true;
    if (model) {
        applied_model = *model;
    }
}

void s390_realize_cpu_model(CPUState *cs)
{
    S390CPU *cpu = S390_CPU(cs);
    const S390CPUModel *max_model;

    if (!cpu->model) {
        /* no host model support -> perform compatibility stuff */
        apply_cpu_model(NULL);
        return;
    }

    max_model = get_max_cpu_model();
    if (!max_model) {
        //error_prepend(errp, "CPU models are not available: ");
        return;
    }

    /* copy over properties that can vary */
    cpu->model->lowest_ibc = max_model->lowest_ibc;
    cpu->model->cpu_id = max_model->cpu_id;
    cpu->model->cpu_id_format = max_model->cpu_id_format;
    cpu->model->cpu_ver = max_model->cpu_ver;

    apply_cpu_model(cpu->model);

    cpu->env.cpuid = s390_cpuid_from_cpu_model(cpu->model);
    /* basic mode, write the cpu address into the first 4 bit of the ID */
    cpu->env.cpuid = deposit64(cpu->env.cpuid, 54, 4, cpu->env.core_id);
}

static void s390_cpu_model_initfn(CPUState *obj)
{
    S390CPU *cpu = S390_CPU(obj);
    S390CPUClass *xcc = S390_CPU_GET_CLASS(cpu);

    cpu->model = g_malloc0(sizeof(*cpu->model));
    /* copy the model, so we can modify it */
    cpu->model->def = xcc->cpu_def;
    if (xcc->is_static) {
        /* base model - features will never change */
        bitmap_copy(cpu->model->features, cpu->model->def->base_feat,
                    S390_FEAT_MAX);
    } else {
        /* latest model - features can change */
        bitmap_copy(cpu->model->features,
                    cpu->model->def->default_feat, S390_FEAT_MAX);
    }
}

static S390CPUDef s390_qemu_cpu_def;
static S390CPUModel s390_qemu_cpu_model;

/* Set the qemu CPU model (on machine initialization). Must not be called
 * once CPUs have been created.
 */
void s390_set_qemu_cpu_model(uint16_t type, uint8_t gen, uint8_t ec_ga,
                             const S390FeatInit feat_init)
{
    const S390CPUDef *def = s390_find_cpu_def(type, gen, ec_ga, NULL);

    g_assert(def);
    //g_assert(QTAILQ_EMPTY_RCU(&cpus));

    /* TCG emulates some features that can usually not be enabled with
     * the emulated machine generation. Make sure they can be enabled
     * when using the QEMU model by adding them to full_feat. We have
     * to copy the definition to do that.
     */
    memcpy(&s390_qemu_cpu_def, def, sizeof(s390_qemu_cpu_def));
    bitmap_or(s390_qemu_cpu_def.full_feat, s390_qemu_cpu_def.full_feat,
              qemu_max_cpu_feat, S390_FEAT_MAX);

    /* build the CPU model */
    s390_qemu_cpu_model.def = &s390_qemu_cpu_def;
    bitmap_zero(s390_qemu_cpu_model.features, S390_FEAT_MAX);
    s390_init_feat_bitmap(feat_init, s390_qemu_cpu_model.features);
}

static void s390_qemu_cpu_model_initfn(CPUState *obj)
{
    S390CPU *cpu = S390_CPU(obj);

    cpu->model = g_malloc0(sizeof(*cpu->model));
    /* copy the CPU model so we can modify it */
    memcpy(cpu->model, &s390_qemu_cpu_model, sizeof(*cpu->model));
}

static void s390_max_cpu_model_initfn(CPUState *obj)
{
    const S390CPUModel *max_model;
    S390CPU *cpu = S390_CPU(obj);

    max_model = get_max_cpu_model();

    cpu->model = g_new(S390CPUModel, 1);
    /* copy the CPU model so we can modify it */
    memcpy(cpu->model, max_model, sizeof(*cpu->model));
}

void s390_cpu_model_finalize(CPUState *obj)
{
    S390CPU *cpu = S390_CPU(obj);

    g_free(cpu->model);
    g_free(cpu->ss.keydata);
    cpu->model = NULL;
}

static void s390_base_cpu_model_class_init(struct uc_struct *uc, CPUClass *oc, void *data)
{
    S390CPUClass *xcc = S390_CPU_CLASS(oc);

    /* all base models are migration safe */
    xcc->cpu_def = (const S390CPUDef *) data;
    xcc->is_static = true;
    // xcc->desc = xcc->cpu_def->desc;
}

static void s390_cpu_model_class_init(struct uc_struct *uc, CPUClass *oc, void *data)
{
    S390CPUClass *xcc = S390_CPU_CLASS(oc);

    /* model that can change between QEMU versions */
    xcc->cpu_def = (const S390CPUDef *) data;
    // xcc->is_migration_safe = true;
    // xcc->desc = xcc->cpu_def->desc;
}

static void s390_qemu_cpu_model_class_init(struct uc_struct *uc, CPUClass *oc, void *data)
{
    //S390CPUClass *xcc = S390_CPU_CLASS(oc);

    //xcc->desc = g_strdup_printf("QEMU Virtual CPU version %s",
    //                            qemu_hw_version());
}

static void s390_max_cpu_model_class_init(struct uc_struct *uc, CPUClass *oc, void *data)
{
    //S390CPUClass *xcc = S390_CPU_CLASS(oc);

    /*
     * The "max" model is neither static nor migration safe. Under KVM
     * it represents the "host" model. Under TCG it represents some kind of
     * "qemu" CPU model without compat handling and maybe with some additional
     * CPU features that are not yet unlocked in the "qemu" model.
     */
    //xcc->desc =
    //    "Enables all features supported by the accelerator in the current host";
}

static void init_ignored_base_feat(void)
{
    static const int feats[] = {
         /* MSA subfunctions that could not be available on certain machines */
         S390_FEAT_KMAC_DEA,
         S390_FEAT_KMAC_TDEA_128,
         S390_FEAT_KMAC_TDEA_192,
         S390_FEAT_KMC_DEA,
         S390_FEAT_KMC_TDEA_128,
         S390_FEAT_KMC_TDEA_192,
         S390_FEAT_KM_DEA,
         S390_FEAT_KM_TDEA_128,
         S390_FEAT_KM_TDEA_192,
         S390_FEAT_KIMD_SHA_1,
         S390_FEAT_KLMD_SHA_1,
         /* CSSKE is deprecated on newer generations */
         S390_FEAT_CONDITIONAL_SSKE,
    };
    int i;

    for (i = 0; i < ARRAY_SIZE(feats); i++) {
        set_bit(feats[i], ignored_base_feat);
    }
}

void s390_init_cpu_model(uc_engine *uc, uc_cpu_s390x cpu_model)
{
    static const S390FeatInit qemu_latest_init = { S390_FEAT_LIST_QEMU_LATEST };
    int i;

    init_ignored_base_feat();

    /* init all bitmaps from gnerated data initially */
    s390_init_feat_bitmap(qemu_max_cpu_feat_init, qemu_max_cpu_feat);
    for (i = 0; i < ARRAY_SIZE(s390_cpu_defs); i++) {
        s390_init_feat_bitmap(s390_cpu_defs[i].base_init,
                              s390_cpu_defs[i].base_feat);
        s390_init_feat_bitmap(s390_cpu_defs[i].default_init,
                              s390_cpu_defs[i].default_feat);
        s390_init_feat_bitmap(s390_cpu_defs[i].full_init,
                              s390_cpu_defs[i].full_feat);
    }

    /* initialize the qemu model with latest definition */
    s390_set_qemu_cpu_model(QEMU_MAX_CPU_TYPE, QEMU_MAX_CPU_GEN,
                            QEMU_MAX_CPU_EC_GA, qemu_latest_init);

    if (cpu_model < ARRAY_SIZE(s390_cpu_defs)) {
        s390_base_cpu_model_class_init(uc, uc->cpu->cc, (void *) &s390_cpu_defs[cpu_model]);
        s390_cpu_model_class_init(uc, uc->cpu->cc, (void *) &s390_cpu_defs[cpu_model]);
        s390_cpu_model_initfn(uc->cpu);
    } else if (cpu_model == UC_CPU_S390X_MAX) {
        s390_max_cpu_model_class_init(uc, uc->cpu->cc, NULL);
        s390_max_cpu_model_initfn(uc->cpu);
    } else if (cpu_model == UC_CPU_S390X_QEMU) {
        s390_qemu_cpu_model_class_init(uc, uc->cpu->cc, NULL);
        s390_qemu_cpu_model_initfn(uc->cpu);
    }

}
