/*
 *  s390x crypto helpers
 *
 *  Copyright (c) 2017 Red Hat Inc
 *
 *  Authors:
 *   David Hildenbrand <david@redhat.com>
 *
 * This work is licensed under the terms of the GNU GPL, version 2 or later.
 * See the COPYING file in the top-level directory.
 */

#include "qemu/osdep.h"
#include "internal.h"
#include "tcg_s390x.h"
#include "exec/helper-proto.h"
#include "exec/exec-all.h"
#include "exec/cpu_ldst.h"

uint32_t HELPER(msa)(CPUS390XState *env, uint32_t r1, uint32_t r2, uint32_t r3,
                     uint32_t type)
{
    const uintptr_t ra = GETPC();
    const uint8_t mod = env->regs[0] & 0x80ULL;
    const uint8_t fc = env->regs[0] & 0x7fULL;
    uint8_t subfunc[16] = { 0 };
    uint64_t param_addr;
    int i;

    switch (type) {
    case S390_FEAT_TYPE_KMAC:
    case S390_FEAT_TYPE_KIMD:
    case S390_FEAT_TYPE_KLMD:
    case S390_FEAT_TYPE_PCKMO:
    case S390_FEAT_TYPE_PCC:
        if (mod) {
            tcg_s390_program_interrupt(env, PGM_SPECIFICATION, ra);
        }
        break;
    }

    s390_get_feat_block(env->uc, type, subfunc);
    if (!test_be_bit(fc, subfunc)) {
        tcg_s390_program_interrupt(env, PGM_SPECIFICATION, ra);
    }

    switch (fc) {
    case 0: /* query subfunction */
        for (i = 0; i < 16; i++) {
            param_addr = wrap_address(env, env->regs[1] + i);
            cpu_stb_data_ra(env, param_addr, subfunc[i], ra);
        }
        break;
    default:
        /* we don't implement any other subfunction yet */
        g_assert_not_reached();
    }

    return 0;
}
