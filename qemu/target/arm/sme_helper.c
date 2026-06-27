/*
 * ARM SME operations.
 */

#include "qemu/osdep.h"
#include "cpu.h"
#include "internals.h"
#include "tcg/tcg-gvec-desc.h"
#include "exec/helper-proto.h"
#include "exec/exec-all.h"
#include "exec/cpu_ldst.h"
#include "qemu/int128.h"
#include "fpu/softfloat.h"

#ifdef HOST_WORDS_BIGENDIAN
#define H1(x)   ((x) ^ 7)
#define H1_2(x) ((x) ^ 6)
#define H1_4(x) ((x) ^ 4)
#define H2(x)   ((x) ^ 3)
#else
#define H1(x)   (x)
#define H1_2(x) (x)
#define H1_4(x) (x)
#define H2(x)   (x)
#endif

void HELPER(sme_zero)(CPUARMState *env, uint32_t imm, uint32_t svl)
{
    uint32_t i;

    if (imm == 0xff) {
        memset(env->zarray, 0, sizeof(env->zarray));
        return;
    }

    for (i = 0; i < svl; i++) {
        if (imm & (1 << (i % 8))) {
            memset(&env->zarray[i], 0, svl);
        }
    }
}

#define tile_vslice_index(i) ((i) * sizeof(ARMVectorReg))
#define tile_vslice_offset(byteoff) ((byteoff) * sizeof(ARMVectorReg))

#define DO_MOVA_C(NAME, TYPE, H)                                      \
void HELPER(NAME)(void *za, void *vn, void *vg, uint32_t desc)        \
{                                                                     \
    int i, oprsz = simd_oprsz(desc);                                  \
    char *za_b = za;                                                  \
    char *vn_b = vn;                                                  \
    char *vg_b = vg;                                                  \
                                                                      \
    for (i = 0; i < oprsz; ) {                                        \
        uint16_t pg = *(uint16_t *)(vg_b + H1_2(i >> 3));             \
        do {                                                          \
            if (pg & 1) {                                             \
                *(TYPE *)(za_b + tile_vslice_offset(i)) =             \
                    *(TYPE *)(vn_b + H(i));                           \
            }                                                         \
            i += sizeof(TYPE);                                        \
            pg >>= sizeof(TYPE);                                      \
        } while (i & 15);                                             \
    }                                                                 \
}

DO_MOVA_C(sme_mova_cz_b, uint8_t, H1)
DO_MOVA_C(sme_mova_cz_h, uint16_t, H1_2)
DO_MOVA_C(sme_mova_cz_s, uint32_t, H1_4)

void HELPER(sme_mova_cz_d)(void *za, void *vn, void *vg, uint32_t desc)
{
    int i, oprsz = simd_oprsz(desc) / 8;
    uint8_t *pg = vg;
    uint64_t *n = vn;
    char *za_b = za;

    for (i = 0; i < oprsz; i++) {
        if (pg[H1(i)] & 1) {
            *(uint64_t *)(za_b + tile_vslice_index(i) * sizeof(uint64_t)) =
                n[i];
        }
    }
}

void HELPER(sme_mova_cz_q)(void *za, void *vn, void *vg, uint32_t desc)
{
    int i, oprsz = simd_oprsz(desc) / 16;
    uint16_t *pg = vg;
    Int128 *n = vn;
    char *za_b = za;

    for (i = 0; i < oprsz; i++) {
        if (pg[H2(i)] & 1) {
            *(Int128 *)(za_b + tile_vslice_index(i) * sizeof(Int128)) = n[i];
        }
    }
}

#undef DO_MOVA_C

#define DO_MOVA_Z(NAME, TYPE, H)                                      \
void HELPER(NAME)(void *vd, void *za, void *vg, uint32_t desc)        \
{                                                                     \
    int i, oprsz = simd_oprsz(desc);                                  \
    char *vd_b = vd;                                                  \
    char *za_b = za;                                                  \
    char *vg_b = vg;                                                  \
                                                                      \
    for (i = 0; i < oprsz; ) {                                        \
        uint16_t pg = *(uint16_t *)(vg_b + H1_2(i >> 3));             \
        do {                                                          \
            if (pg & 1) {                                             \
                *(TYPE *)(vd_b + H(i)) =                              \
                    *(TYPE *)(za_b + tile_vslice_offset(i));          \
            }                                                         \
            i += sizeof(TYPE);                                        \
            pg >>= sizeof(TYPE);                                      \
        } while (i & 15);                                             \
    }                                                                 \
}

DO_MOVA_Z(sme_mova_zc_b, uint8_t, H1)
DO_MOVA_Z(sme_mova_zc_h, uint16_t, H1_2)
DO_MOVA_Z(sme_mova_zc_s, uint32_t, H1_4)

void HELPER(sme_mova_zc_d)(void *vd, void *za, void *vg, uint32_t desc)
{
    int i, oprsz = simd_oprsz(desc) / 8;
    uint8_t *pg = vg;
    uint64_t *d = vd;
    char *za_b = za;

    for (i = 0; i < oprsz; i++) {
        if (pg[H1(i)] & 1) {
            d[i] =
                *(uint64_t *)(za_b + tile_vslice_index(i) * sizeof(uint64_t));
        }
    }
}

void HELPER(sme_mova_zc_q)(void *vd, void *za, void *vg, uint32_t desc)
{
    int i, oprsz = simd_oprsz(desc) / 16;
    uint16_t *pg = vg;
    Int128 *d = vd;
    char *za_b = za;

    for (i = 0; i < oprsz; i++) {
        if (pg[H2(i)] & 1) {
            d[i] = *(Int128 *)(za_b + tile_vslice_index(i) * sizeof(Int128));
        }
    }
}

static inline void *sme_ldst1_za_ptr(void *za, intptr_t off, int esz,
                                     bool vertical)
{
    if (vertical) {
        return (char *)za + tile_vslice_offset(off);
    }

    switch (esz) {
    case MO_8:
        return (char *)za + H1(off);
    case MO_16:
        return (char *)za + H1_2(off);
    case MO_32:
        return (char *)za + H1_4(off);
    default:
        return (char *)za + off;
    }
}

static uint64_t sme_ldst1_load(CPUARMState *env, target_ulong addr,
                               int size, bool be)
{
    uint64_t ret = 0;
    int i;

    if (be) {
        for (i = 0; i < size; i++) {
            ret = (ret << 8) | cpu_ldub_data_ra(env, addr + i, GETPC());
        }
    } else {
        for (i = 0; i < size; i++) {
            ret |= (uint64_t)cpu_ldub_data_ra(env, addr + i, GETPC()) <<
                   (i * 8);
        }
    }
    return ret;
}

static void sme_ldst1_store(CPUARMState *env, target_ulong addr,
                            uint64_t value, int size, bool be)
{
    int i;

    if (be) {
        for (i = 0; i < size; i++) {
            int shift = (size - 1 - i) * 8;

            cpu_stb_data_ra(env, addr + i, value >> shift, GETPC());
        }
    } else {
        for (i = 0; i < size; i++) {
            cpu_stb_data_ra(env, addr + i, value >> (i * 8), GETPC());
        }
    }
}

static void sme_ldst1_clear(void *za, intptr_t off, int esz, bool vertical)
{
    memset(sme_ldst1_za_ptr(za, off, esz, vertical), 0, 1 << esz);
}

static void sme_ld1_element(CPUARMState *env, void *za, target_ulong addr,
                            intptr_t off, int esz, bool be, bool vertical)
{
    void *ptr = sme_ldst1_za_ptr(za, off, esz, vertical);

    switch (esz) {
    case MO_8:
        *(uint8_t *)ptr = sme_ldst1_load(env, addr, 1, be);
        break;
    case MO_16:
        *(uint16_t *)ptr = sme_ldst1_load(env, addr, 2, be);
        break;
    case MO_32:
        *(uint32_t *)ptr = sme_ldst1_load(env, addr, 4, be);
        break;
    case MO_64:
        *(uint64_t *)ptr = sme_ldst1_load(env, addr, 8, be);
        break;
    case MO_128:
    {
        uint64_t val0 = sme_ldst1_load(env, addr, 8, be);
        uint64_t val1 = sme_ldst1_load(env, addr + 8, 8, be);
        uint64_t *dst = ptr;

        dst[0] = be ? val1 : val0;
        dst[1] = be ? val0 : val1;
        break;
    }
    default:
        g_assert_not_reached();
    }
}

static void sme_st1_element(CPUARMState *env, void *za, target_ulong addr,
                            intptr_t off, int esz, bool be, bool vertical)
{
    void *ptr = sme_ldst1_za_ptr(za, off, esz, vertical);
    uint64_t val;

    switch (esz) {
    case MO_8:
        val = *(uint8_t *)ptr;
        sme_ldst1_store(env, addr, val, 1, be);
        break;
    case MO_16:
        val = *(uint16_t *)ptr;
        sme_ldst1_store(env, addr, val, 2, be);
        break;
    case MO_32:
        val = *(uint32_t *)ptr;
        sme_ldst1_store(env, addr, val, 4, be);
        break;
    case MO_64:
        val = *(uint64_t *)ptr;
        sme_ldst1_store(env, addr, val, 8, be);
        break;
    case MO_128:
    {
        uint64_t *src = ptr;

        sme_ldst1_store(env, addr, src[be], 8, be);
        sme_ldst1_store(env, addr + 8, src[!be], 8, be);
        break;
    }
    default:
        g_assert_not_reached();
    }
}

static bool sme_ldst1_active(uint64_t *pg, intptr_t off)
{
    return (pg[off >> 6] >> (off & 63)) & 1;
}

static void sme_ldst1_probe_addr(CPUARMState *env, target_ulong addr,
                                 int size, MMUAccessType access_type,
                                 int mmu_idx, uintptr_t ra)
{
    struct uc_struct *uc = env->uc;

    while (size > 0) {
        target_ulong page_left = -(addr | TARGET_PAGE_MASK);
        int probe_size = MIN(size, (int)page_left);
        target_ulong paddr;
        MemoryRegion *mr;

        if (!tlb_vaddr_to_paddr(env, addr, access_type, mmu_idx, &paddr)) {
            uc->invalid_addr = addr;
            uc->invalid_error = access_type == MMU_DATA_STORE ?
                                UC_ERR_MMU_WRITE : UC_ERR_MMU_READ;
            cpu_exit(uc->cpu);
            cpu_loop_exit_restore(env_cpu(env), ra);
        }

        mr = uc->memory_mapping(uc, paddr);
        if (mr == NULL) {
            uc->invalid_addr = paddr;
            uc->invalid_error = access_type == MMU_DATA_STORE ?
                                UC_ERR_WRITE_UNMAPPED :
                                UC_ERR_READ_UNMAPPED;
            cpu_exit(uc->cpu);
            cpu_loop_exit_restore(env_cpu(env), ra);
        }
        if (access_type == MMU_DATA_STORE) {
            if (!(mr->perms & UC_PROT_WRITE)) {
                uc->invalid_addr = paddr;
                uc->invalid_error = UC_ERR_WRITE_PROT;
                cpu_exit(uc->cpu);
                cpu_loop_exit_restore(env_cpu(env), ra);
            }
        } else if (!(mr->perms & UC_PROT_READ)) {
            uc->invalid_addr = paddr;
            uc->invalid_error = UC_ERR_READ_PROT;
            cpu_exit(uc->cpu);
            cpu_loop_exit_restore(env_cpu(env), ra);
        }

        probe_access(env, addr, probe_size, access_type, mmu_idx, ra);
        addr += probe_size;
        size -= probe_size;
    }
}

static int sme_allocation_tag_from_addr(target_ulong ptr)
{
    return extract64(ptr, 56, 4);
}

static target_ulong sme_allocation_tag_clean_addr(target_ulong ptr)
{
    return ptr & ~MAKE_64BIT_MASK(56, 8);
}

static target_ulong sme_ldst1_mte_addr(CPUARMState *env, target_ulong addr,
                                       uint32_t mtedesc)
{
    int bit55 = extract64(addr, 55, 1);

    if (!tbi_check(mtedesc, bit55)) {
        return addr;
    }
    if (tcma_check(mtedesc, bit55, sme_allocation_tag_from_addr(addr))) {
        return sme_allocation_tag_clean_addr(useronly_clean_ptr(addr));
    }
    return mte_check(env, mtedesc, addr, GETPC());
}

static target_ulong sme_ldst1_clean_addr(target_ulong addr, uint32_t mtedesc)
{
    int bit55 = extract64(addr, 55, 1);

    if (!mtedesc || !tbi_check(mtedesc, bit55)) {
        return addr;
    }
    return sme_allocation_tag_clean_addr(useronly_clean_ptr(addr));
}

static void do_sme_ldst1(CPUARMState *env, void *za, void *vg,
                         target_ulong addr, uint32_t desc, int esz,
                         bool be, bool vertical, bool store, bool mte)
{
    intptr_t off, oprsz = simd_oprsz(desc);
    uint64_t *pg = vg;
    int esize = 1 << esz;
    uint32_t mtedesc = mte ? extract32(desc, SIMD_DATA_SHIFT,
                                       SIMD_DATA_BITS) : 0;
    int mmu_idx = mte ? FIELD_EX32(mtedesc, MTEDESC, MIDX) :
                        extract32(desc, SIMD_DATA_SHIFT,
                                  R_MTEDESC_MIDX_LENGTH);
    MMUAccessType access_type = store ? MMU_DATA_STORE : MMU_DATA_LOAD;

    for (off = 0; off < oprsz; off += esize) {
        if (sme_ldst1_active(pg, off)) {
            target_ulong elem_addr = sme_ldst1_clean_addr(addr + off,
                                                          mtedesc);

            sme_ldst1_probe_addr(env, elem_addr, esize, access_type, mmu_idx,
                                 GETPC());
        }
    }

    if (mtedesc) {
        for (off = 0; off < oprsz; off += esize) {
            if (sme_ldst1_active(pg, off)) {
                (void)sme_ldst1_mte_addr(env, addr + off, mtedesc);
            }
        }
    }

    for (off = 0; off < oprsz; off += esize) {
        if (store) {
            if (sme_ldst1_active(pg, off)) {
                target_ulong elem_addr = sme_ldst1_clean_addr(addr + off,
                                                              mtedesc);

                sme_st1_element(env, za, elem_addr, off, esz, be, vertical);
            }
        } else {
            sme_ldst1_clear(za, off, esz, vertical);
            if (sme_ldst1_active(pg, off)) {
                target_ulong elem_addr = sme_ldst1_clean_addr(addr + off,
                                                              mtedesc);

                sme_ld1_element(env, za, elem_addr, off, esz, be, vertical);
            }
        }
    }
}

#define DO_SME_LDST1(NAME, ESZ, BE, VERTICAL, STORE, MTE)               \
void HELPER(NAME)(CPUARMState *env, void *za, void *vg,                 \
                  target_ulong addr, uint32_t desc)                     \
{                                                                       \
    do_sme_ldst1(env, za, vg, addr, desc, ESZ, BE, VERTICAL, STORE,     \
                 MTE);                                                  \
}

DO_SME_LDST1(sme_ld1b_h, MO_8, false, false, false, false)
DO_SME_LDST1(sme_ld1b_v, MO_8, false, true, false, false)
DO_SME_LDST1(sme_ld1h_le_h, MO_16, false, false, false, false)
DO_SME_LDST1(sme_ld1h_le_v, MO_16, false, true, false, false)
DO_SME_LDST1(sme_ld1h_be_h, MO_16, true, false, false, false)
DO_SME_LDST1(sme_ld1h_be_v, MO_16, true, true, false, false)
DO_SME_LDST1(sme_ld1s_le_h, MO_32, false, false, false, false)
DO_SME_LDST1(sme_ld1s_le_v, MO_32, false, true, false, false)
DO_SME_LDST1(sme_ld1s_be_h, MO_32, true, false, false, false)
DO_SME_LDST1(sme_ld1s_be_v, MO_32, true, true, false, false)
DO_SME_LDST1(sme_ld1d_le_h, MO_64, false, false, false, false)
DO_SME_LDST1(sme_ld1d_le_v, MO_64, false, true, false, false)
DO_SME_LDST1(sme_ld1d_be_h, MO_64, true, false, false, false)
DO_SME_LDST1(sme_ld1d_be_v, MO_64, true, true, false, false)
DO_SME_LDST1(sme_ld1q_le_h, MO_128, false, false, false, false)
DO_SME_LDST1(sme_ld1q_le_v, MO_128, false, true, false, false)
DO_SME_LDST1(sme_ld1q_be_h, MO_128, true, false, false, false)
DO_SME_LDST1(sme_ld1q_be_v, MO_128, true, true, false, false)

DO_SME_LDST1(sme_ld1b_h_mte, MO_8, false, false, false, true)
DO_SME_LDST1(sme_ld1b_v_mte, MO_8, false, true, false, true)
DO_SME_LDST1(sme_ld1h_le_h_mte, MO_16, false, false, false, true)
DO_SME_LDST1(sme_ld1h_le_v_mte, MO_16, false, true, false, true)
DO_SME_LDST1(sme_ld1h_be_h_mte, MO_16, true, false, false, true)
DO_SME_LDST1(sme_ld1h_be_v_mte, MO_16, true, true, false, true)
DO_SME_LDST1(sme_ld1s_le_h_mte, MO_32, false, false, false, true)
DO_SME_LDST1(sme_ld1s_le_v_mte, MO_32, false, true, false, true)
DO_SME_LDST1(sme_ld1s_be_h_mte, MO_32, true, false, false, true)
DO_SME_LDST1(sme_ld1s_be_v_mte, MO_32, true, true, false, true)
DO_SME_LDST1(sme_ld1d_le_h_mte, MO_64, false, false, false, true)
DO_SME_LDST1(sme_ld1d_le_v_mte, MO_64, false, true, false, true)
DO_SME_LDST1(sme_ld1d_be_h_mte, MO_64, true, false, false, true)
DO_SME_LDST1(sme_ld1d_be_v_mte, MO_64, true, true, false, true)
DO_SME_LDST1(sme_ld1q_le_h_mte, MO_128, false, false, false, true)
DO_SME_LDST1(sme_ld1q_le_v_mte, MO_128, false, true, false, true)
DO_SME_LDST1(sme_ld1q_be_h_mte, MO_128, true, false, false, true)
DO_SME_LDST1(sme_ld1q_be_v_mte, MO_128, true, true, false, true)

DO_SME_LDST1(sme_st1b_h, MO_8, false, false, true, false)
DO_SME_LDST1(sme_st1b_v, MO_8, false, true, true, false)
DO_SME_LDST1(sme_st1h_le_h, MO_16, false, false, true, false)
DO_SME_LDST1(sme_st1h_le_v, MO_16, false, true, true, false)
DO_SME_LDST1(sme_st1h_be_h, MO_16, true, false, true, false)
DO_SME_LDST1(sme_st1h_be_v, MO_16, true, true, true, false)
DO_SME_LDST1(sme_st1s_le_h, MO_32, false, false, true, false)
DO_SME_LDST1(sme_st1s_le_v, MO_32, false, true, true, false)
DO_SME_LDST1(sme_st1s_be_h, MO_32, true, false, true, false)
DO_SME_LDST1(sme_st1s_be_v, MO_32, true, true, true, false)
DO_SME_LDST1(sme_st1d_le_h, MO_64, false, false, true, false)
DO_SME_LDST1(sme_st1d_le_v, MO_64, false, true, true, false)
DO_SME_LDST1(sme_st1d_be_h, MO_64, true, false, true, false)
DO_SME_LDST1(sme_st1d_be_v, MO_64, true, true, true, false)
DO_SME_LDST1(sme_st1q_le_h, MO_128, false, false, true, false)
DO_SME_LDST1(sme_st1q_le_v, MO_128, false, true, true, false)
DO_SME_LDST1(sme_st1q_be_h, MO_128, true, false, true, false)
DO_SME_LDST1(sme_st1q_be_v, MO_128, true, true, true, false)

DO_SME_LDST1(sme_st1b_h_mte, MO_8, false, false, true, true)
DO_SME_LDST1(sme_st1b_v_mte, MO_8, false, true, true, true)
DO_SME_LDST1(sme_st1h_le_h_mte, MO_16, false, false, true, true)
DO_SME_LDST1(sme_st1h_le_v_mte, MO_16, false, true, true, true)
DO_SME_LDST1(sme_st1h_be_h_mte, MO_16, true, false, true, true)
DO_SME_LDST1(sme_st1h_be_v_mte, MO_16, true, true, true, true)
DO_SME_LDST1(sme_st1s_le_h_mte, MO_32, false, false, true, true)
DO_SME_LDST1(sme_st1s_le_v_mte, MO_32, false, true, true, true)
DO_SME_LDST1(sme_st1s_be_h_mte, MO_32, true, false, true, true)
DO_SME_LDST1(sme_st1s_be_v_mte, MO_32, true, true, true, true)
DO_SME_LDST1(sme_st1d_le_h_mte, MO_64, false, false, true, true)
DO_SME_LDST1(sme_st1d_le_v_mte, MO_64, false, true, true, true)
DO_SME_LDST1(sme_st1d_be_h_mte, MO_64, true, false, true, true)
DO_SME_LDST1(sme_st1d_be_v_mte, MO_64, true, true, true, true)
DO_SME_LDST1(sme_st1q_le_h_mte, MO_128, false, false, true, true)
DO_SME_LDST1(sme_st1q_le_v_mte, MO_128, false, true, true, true)
DO_SME_LDST1(sme_st1q_be_h_mte, MO_128, true, false, true, true)
DO_SME_LDST1(sme_st1q_be_v_mte, MO_128, true, true, true, true)

#undef DO_SME_LDST1

void HELPER(sme_addha_s)(void *vza, void *vzn, void *vpn, void *vpm,
                         uint32_t desc)
{
    intptr_t row, col, oprsz = simd_oprsz(desc) / sizeof(uint32_t);
    char *za = vza;
    char *zn = vzn;
    uint64_t *pn = vpn;
    uint64_t *pm = vpm;

    for (row = 0; row < oprsz; ) {
        uint64_t pa = pn[row >> 4];
        do {
            if (pa & 1) {
                char *za_row = za + tile_vslice_offset(row * sizeof(uint32_t));

                for (col = 0; col < oprsz; ) {
                    uint64_t pb = pm[col >> 4];
                    do {
                        if (pb & 1) {
                            uint32_t *cell =
                                (uint32_t *)(za_row +
                                             H1_4(col * sizeof(uint32_t)));
                            uint32_t *src =
                                (uint32_t *)(zn +
                                             H1_4(col * sizeof(uint32_t)));

                            *cell += *src;
                        }
                        pb >>= 4;
                    } while (++col & 15);
                }
            }
            pa >>= 4;
        } while (++row & 15);
    }
}

void HELPER(sme_addha_d)(void *vza, void *vzn, void *vpn, void *vpm,
                         uint32_t desc)
{
    intptr_t row, col, oprsz = simd_oprsz(desc) / sizeof(uint64_t);
    char *za = vza;
    uint64_t *zn = vzn;
    uint8_t *pn = vpn;
    uint8_t *pm = vpm;

    for (row = 0; row < oprsz; row++) {
        if (pn[H1(row)] & 1) {
            char *za_row = za + tile_vslice_offset(row * sizeof(uint64_t));

            for (col = 0; col < oprsz; col++) {
                if (pm[H1(col)] & 1) {
                    uint64_t *cell =
                        (uint64_t *)(za_row + col * sizeof(uint64_t));

                    *cell += zn[col];
                }
            }
        }
    }
}

void HELPER(sme_addva_s)(void *vza, void *vzn, void *vpn, void *vpm,
                         uint32_t desc)
{
    intptr_t row, col, oprsz = simd_oprsz(desc) / sizeof(uint32_t);
    char *za = vza;
    char *zn = vzn;
    uint64_t *pn = vpn;
    uint64_t *pm = vpm;

    for (row = 0; row < oprsz; ) {
        uint64_t pa = pn[row >> 4];
        do {
            if (pa & 1) {
                char *za_row = za + tile_vslice_offset(row * sizeof(uint32_t));
                uint32_t src =
                    *(uint32_t *)(zn + H1_4(row * sizeof(uint32_t)));

                for (col = 0; col < oprsz; ) {
                    uint64_t pb = pm[col >> 4];
                    do {
                        if (pb & 1) {
                            uint32_t *cell =
                                (uint32_t *)(za_row +
                                             H1_4(col * sizeof(uint32_t)));

                            *cell += src;
                        }
                        pb >>= 4;
                    } while (++col & 15);
                }
            }
            pa >>= 4;
        } while (++row & 15);
    }
}

void HELPER(sme_addva_d)(void *vza, void *vzn, void *vpn, void *vpm,
                         uint32_t desc)
{
    intptr_t row, col, oprsz = simd_oprsz(desc) / sizeof(uint64_t);
    char *za = vza;
    uint64_t *zn = vzn;
    uint8_t *pn = vpn;
    uint8_t *pm = vpm;

    for (row = 0; row < oprsz; row++) {
        if (pn[H1(row)] & 1) {
            char *za_row = za + tile_vslice_offset(row * sizeof(uint64_t));
            uint64_t src = zn[row];

            for (col = 0; col < oprsz; col++) {
                if (pm[H1(col)] & 1) {
                    uint64_t *cell =
                        (uint64_t *)(za_row + col * sizeof(uint64_t));

                    *cell += src;
                }
            }
        }
    }
}

void HELPER(sme_fmopa_s)(void *vza, void *vzn, void *vzm, void *vpn,
                         void *vpm, void *vst, uint32_t desc)
{
    intptr_t row, col, oprsz = simd_maxsz(desc);
    uint32_t neg = simd_data(desc) << 31;
    uint16_t *pn = vpn;
    uint16_t *pm = vpm;
    char *za = vza;
    char *zn = vzn;
    char *zm = vzm;
    float_status fpst = *(float_status *)vst;

    set_default_nan_mode(true, &fpst);

    for (row = 0; row < oprsz;) {
        uint16_t pa = pn[H2(row >> 4)];

        do {
            if (pa & 1) {
                char *za_row = za + tile_vslice_offset(row);
                uint32_t n = *(uint32_t *)(zn + H1_4(row)) ^ neg;

                for (col = 0; col < oprsz;) {
                    uint16_t pb = pm[H2(col >> 4)];

                    do {
                        if (pb & 1) {
                            uint32_t *a = (uint32_t *)(za_row + H1_4(col));
                            uint32_t *m = (uint32_t *)(zm + H1_4(col));

                            *a = float32_muladd(n, *m, *a, 0, &fpst);
                        }
                        col += sizeof(uint32_t);
                        pb >>= sizeof(uint32_t);
                    } while (col & 15);
                }
            }
            row += sizeof(uint32_t);
            pa >>= sizeof(uint32_t);
        } while (row & 15);
    }
}

void HELPER(sme_fmopa_d)(void *vza, void *vzn, void *vzm, void *vpn,
                         void *vpm, void *vst, uint32_t desc)
{
    intptr_t row, col, oprsz = simd_oprsz(desc) / sizeof(uint64_t);
    uint64_t neg = (uint64_t)simd_data(desc) << 63;
    uint64_t *za = vza;
    uint64_t *zn = vzn;
    uint64_t *zm = vzm;
    uint8_t *pn = vpn;
    uint8_t *pm = vpm;
    float_status fpst = *(float_status *)vst;

    set_default_nan_mode(true, &fpst);

    for (row = 0; row < oprsz; row++) {
        if (pn[H1(row)] & 1) {
            uint64_t *za_row = &za[tile_vslice_index(row)];
            uint64_t n = zn[row] ^ neg;

            for (col = 0; col < oprsz; col++) {
                if (pm[H1(col)] & 1) {
                    uint64_t *a = &za_row[col];

                    *a = float64_muladd(n, zm[col], *a, 0, &fpst);
                }
            }
        }
    }
}

static uint32_t sme_f16mop_adj_pair(uint32_t pair, uint32_t pg, uint32_t neg)
{
    pair ^= neg;
    if (!(pg & 1)) {
        pair &= 0xffff0000u;
    }
    if (!(pg & 4)) {
        pair &= 0x0000ffffu;
    }
    return pair;
}

static float32 sme_f16_dotadd(float32 sum, uint32_t e1, uint32_t e2,
                              float_status *s_f16, float_status *s_std,
                              float_status *s_odd)
{
    float16 h1r = e1 & 0xffff;
    float16 h1c = e1 >> 16;
    float16 h2r = e2 & 0xffff;
    float16 h2c = e2 >> 16;
    float32 t32;

    if (float16_is_any_nan(h1r) || float16_is_any_nan(h1c) ||
        float16_is_any_nan(h2r) || float16_is_any_nan(h2c)) {
        float16 t16;

        if (float16_is_signaling_nan(h1r, s_f16)) {
            t16 = h1r;
        } else if (float16_is_signaling_nan(h1c, s_f16)) {
            t16 = h1c;
        } else if (float16_is_signaling_nan(h2r, s_f16)) {
            t16 = h2r;
        } else if (float16_is_signaling_nan(h2c, s_f16)) {
            t16 = h2c;
        } else if (float16_is_any_nan(h1r)) {
            t16 = h1r;
        } else if (float16_is_any_nan(h1c)) {
            t16 = h1c;
        } else if (float16_is_any_nan(h2r)) {
            t16 = h2r;
        } else {
            t16 = h2c;
        }
        t32 = float16_to_float32(t16, true, s_f16);
    } else {
        float64 e1r = float16_to_float64(h1r, true, s_f16);
        float64 e1c = float16_to_float64(h1c, true, s_f16);
        float64 e2r = float16_to_float64(h2r, true, s_f16);
        float64 e2c = float16_to_float64(h2c, true, s_f16);
        float64 t64;

        t64 = float64_mul(e1r, e2r, s_odd);
        t64 = float64r32_muladd(e1c, e2c, t64, 0, s_std);
        t32 = float64_to_float32(t64, s_std);
    }

    return float32_add(sum, t32, s_std);
}

void HELPER(sme_fmopa_h)(void *vza, void *vzn, void *vzm, void *vpn,
                         void *vpm, CPUARMState *env, uint32_t desc)
{
    intptr_t row, col, oprsz = simd_maxsz(desc);
    uint32_t neg = simd_data(desc) * 0x80008000u;
    uint16_t *pn = vpn;
    uint16_t *pm = vpm;
    char *za = vza;
    char *zn = vzn;
    char *zm = vzm;
    float_status fpst_odd;
    float_status fpst_std;
    float_status fpst_f16;

    fpst_f16 = env->vfp.fp_status_f16;
    fpst_std = env->vfp.fp_status;
    set_default_nan_mode(true, &fpst_std);
    set_default_nan_mode(true, &fpst_f16);
    fpst_odd = fpst_std;
    set_float_rounding_mode(float_round_to_odd, &fpst_odd);

    for (row = 0; row < oprsz;) {
        uint16_t prow = pn[H2(row >> 4)];

        do {
            char *za_row = za + tile_vslice_offset(row);
            uint32_t n = *(uint32_t *)(zn + H1_4(row));

            n = sme_f16mop_adj_pair(n, prow, neg);

            for (col = 0; col < oprsz;) {
                uint16_t pcol = pm[H2(col >> 4)];

                do {
                    if (prow & pcol & 0x5) {
                        uint32_t *a = (uint32_t *)(za_row + H1_4(col));
                        uint32_t m = *(uint32_t *)(zm + H1_4(col));

                        m = sme_f16mop_adj_pair(m, pcol, 0);
                        *a = sme_f16_dotadd(*a, n, m,
                                            &fpst_f16, &fpst_std,
                                            &fpst_odd);
                    }
                    col += sizeof(uint32_t);
                    pcol >>= sizeof(uint32_t);
                } while (col & 15);
            }
            row += sizeof(uint32_t);
            prow >>= sizeof(uint32_t);
        } while (row & 15);
    }
}

static float32 sme_bfdotadd(float32 sum, uint32_t e1, uint32_t e2)
{
    float_status bf_status = {
        .tininess_before_rounding = float_tininess_before_rounding,
        .float_rounding_mode = float_round_to_odd_inf,
        .flush_to_zero = true,
        .flush_inputs_to_zero = true,
        .default_nan_mode = true,
    };
    float32 t1;
    float32 t2;

    t1 = float32_mul(e1 << 16, e2 << 16, &bf_status);
    t2 = float32_mul(e1 & 0xffff0000u, e2 & 0xffff0000u, &bf_status);
    t1 = float32_add(t1, t2, &bf_status);
    return float32_add(sum, t1, &bf_status);
}

void HELPER(sme_bfmopa)(void *vza, void *vzn, void *vzm, void *vpn,
                        void *vpm, uint32_t desc)
{
    intptr_t row, col, oprsz = simd_maxsz(desc);
    uint32_t neg = simd_data(desc) * 0x80008000u;
    uint16_t *pn = vpn;
    uint16_t *pm = vpm;
    char *za = vza;
    char *zn = vzn;
    char *zm = vzm;

    for (row = 0; row < oprsz;) {
        uint16_t prow = pn[H2(row >> 4)];

        do {
            char *za_row = za + tile_vslice_offset(row);
            uint32_t n = *(uint32_t *)(zn + H1_4(row));

            n = sme_f16mop_adj_pair(n, prow, neg);

            for (col = 0; col < oprsz;) {
                uint16_t pcol = pm[H2(col >> 4)];

                do {
                    if (prow & pcol & 0x5) {
                        uint32_t *a = (uint32_t *)(za_row + H1_4(col));
                        uint32_t m = *(uint32_t *)(zm + H1_4(col));

                        m = sme_f16mop_adj_pair(m, pcol, 0);
                        *a = sme_bfdotadd(*a, n, m);
                    }
                    col += sizeof(uint32_t);
                    pcol >>= sizeof(uint32_t);
                } while (col & 15);
            }
            row += sizeof(uint32_t);
            prow >>= sizeof(uint32_t);
        } while (row & 15);
    }
}

static uint64_t sme_expand_pred_b(uint8_t pred)
{
    uint64_t ret = 0;
    int i;

    for (i = 0; i < 8; i++) {
        if (pred & (1U << i)) {
            ret |= 0xffULL << (i * 8);
        }
    }
    return ret;
}

static uint64_t sme_expand_pred_h(uint8_t pred)
{
    uint64_t ret = 0;
    int i;

    for (i = 0; i < 4; i++) {
        if (pred & (1U << (i * 2))) {
            ret |= 0xffffULL << (i * 16);
        }
    }
    return ret;
}

typedef uint64_t SMEIntOuterProductFn(uint64_t n, uint64_t m, uint64_t a,
                                      uint8_t pred, bool subtract);

static void do_sme_int_outer_product(void *vza, void *vzn, void *vzm,
                                     void *vpn, void *vpm, uint32_t desc,
                                     SMEIntOuterProductFn *fn)
{
    intptr_t row, col, oprsz = simd_oprsz(desc) / sizeof(uint64_t);
    bool subtract = simd_data(desc);
    uint64_t *za = vza;
    uint64_t *zn = vzn;
    uint64_t *zm = vzm;
    uint8_t *pn = vpn;
    uint8_t *pm = vpm;

    for (row = 0; row < oprsz; row++) {
        uint8_t pa = pn[H1(row)];
        uint64_t *za_row = &za[tile_vslice_index(row)];
        uint64_t n = zn[row];

        for (col = 0; col < oprsz; col++) {
            uint8_t pb = pm[H1(col)];
            uint64_t *cell = &za_row[col];

            *cell = fn(n, zm[col], *cell, pa & pb, subtract);
        }
    }
}

#define DO_SME_IMOPA_S(NAME, NTYPE, MTYPE)                              \
static uint64_t NAME(uint64_t n, uint64_t m, uint64_t a,                \
                     uint8_t pred, bool subtract)                       \
{                                                                       \
    uint32_t sum0 = 0;                                                  \
    uint32_t sum1 = 0;                                                  \
                                                                        \
    n &= sme_expand_pred_b(pred);                                       \
    sum0 += (NTYPE)(n >> 0) * (MTYPE)(m >> 0);                          \
    sum0 += (NTYPE)(n >> 8) * (MTYPE)(m >> 8);                          \
    sum0 += (NTYPE)(n >> 16) * (MTYPE)(m >> 16);                        \
    sum0 += (NTYPE)(n >> 24) * (MTYPE)(m >> 24);                        \
    sum1 += (NTYPE)(n >> 32) * (MTYPE)(m >> 32);                        \
    sum1 += (NTYPE)(n >> 40) * (MTYPE)(m >> 40);                        \
    sum1 += (NTYPE)(n >> 48) * (MTYPE)(m >> 48);                        \
    sum1 += (NTYPE)(n >> 56) * (MTYPE)(m >> 56);                        \
    if (subtract) {                                                     \
        sum0 = (uint32_t)a - sum0;                                      \
        sum1 = (uint32_t)(a >> 32) - sum1;                              \
    } else {                                                            \
        sum0 = (uint32_t)a + sum0;                                      \
        sum1 = (uint32_t)(a >> 32) + sum1;                              \
    }                                                                   \
    return ((uint64_t)sum1 << 32) | sum0;                               \
}

#define DO_SME_IMOPA_D(NAME, NTYPE, MTYPE)                              \
static uint64_t NAME(uint64_t n, uint64_t m, uint64_t a,                \
                     uint8_t pred, bool subtract)                       \
{                                                                       \
    uint64_t sum = 0;                                                   \
                                                                        \
    n &= sme_expand_pred_h(pred);                                       \
    sum += (int64_t)(NTYPE)(n >> 0) * (MTYPE)(m >> 0);                  \
    sum += (int64_t)(NTYPE)(n >> 16) * (MTYPE)(m >> 16);                \
    sum += (int64_t)(NTYPE)(n >> 32) * (MTYPE)(m >> 32);                \
    sum += (int64_t)(NTYPE)(n >> 48) * (MTYPE)(m >> 48);                \
    return subtract ? a - sum : a + sum;                                \
}

DO_SME_IMOPA_S(sme_smopa_s_op, int8_t, int8_t)
DO_SME_IMOPA_S(sme_umopa_s_op, uint8_t, uint8_t)
DO_SME_IMOPA_S(sme_sumopa_s_op, int8_t, uint8_t)
DO_SME_IMOPA_S(sme_usmopa_s_op, uint8_t, int8_t)
DO_SME_IMOPA_D(sme_smopa_d_op, int16_t, int16_t)
DO_SME_IMOPA_D(sme_umopa_d_op, uint16_t, uint16_t)
DO_SME_IMOPA_D(sme_sumopa_d_op, int16_t, uint16_t)
DO_SME_IMOPA_D(sme_usmopa_d_op, uint16_t, int16_t)

#define DO_SME_IMOPA_HELPER(NAME)                                       \
void HELPER(NAME)(void *vza, void *vzn, void *vzm, void *vpn,           \
                  void *vpm, uint32_t desc)                             \
{                                                                       \
    do_sme_int_outer_product(vza, vzn, vzm, vpn, vpm, desc, NAME##_op); \
}

DO_SME_IMOPA_HELPER(sme_smopa_s)
DO_SME_IMOPA_HELPER(sme_umopa_s)
DO_SME_IMOPA_HELPER(sme_sumopa_s)
DO_SME_IMOPA_HELPER(sme_usmopa_s)
DO_SME_IMOPA_HELPER(sme_smopa_d)
DO_SME_IMOPA_HELPER(sme_umopa_d)
DO_SME_IMOPA_HELPER(sme_sumopa_d)
DO_SME_IMOPA_HELPER(sme_usmopa_d)

#undef DO_SME_IMOPA_HELPER
#undef DO_SME_IMOPA_D
#undef DO_SME_IMOPA_S

#undef DO_MOVA_Z
#undef tile_vslice_index
#undef tile_vslice_offset
#undef H1
#undef H1_2
#undef H1_4
#undef H2
