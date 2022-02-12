/*
 * Variable page size handling
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

#include "qemu/osdep.h"
#include "qemu-common.h"

#define IN_EXEC_VARY 1

#include "exec/exec-all.h"

#include <uc_priv.h>

bool set_preferred_target_page_bits(struct uc_struct *uc, int bits)
{
    /*
     * The target page size is the lowest common denominator for all
     * the CPUs in the system, so we can only make it smaller, never
     * larger. And we can't make it smaller once we've committed to
     * a particular size.
     */
#ifdef TARGET_PAGE_BITS_VARY
    //assert(bits >= TARGET_PAGE_BITS_MIN);
    if (uc->init_target_page == NULL) {
        uc->init_target_page = calloc(1, sizeof(TargetPageBits));
    } else {
        return false;
    }

    if (bits < TARGET_PAGE_BITS_MIN) {
        return false;
    }

    if (uc->init_target_page->bits == 0 || uc->init_target_page->bits > bits) {
        if (uc->init_target_page->decided) {
            return false;
        }
        uc->init_target_page->bits = bits;
    }
#endif
    return true;
}

void finalize_target_page_bits(struct uc_struct *uc)
{
#ifdef TARGET_PAGE_BITS_VARY
    if (uc->init_target_page == NULL) {
        uc->init_target_page = calloc(1, sizeof(TargetPageBits));
    } else {
        return;
    }

    if (uc->target_bits != 0) {
        uc->init_target_page->bits = uc->target_bits;
    }

    if (uc->init_target_page->bits == 0) {
        uc->init_target_page->bits = TARGET_PAGE_BITS_MIN;
    }
    uc->init_target_page->mask = ((target_ulong)-1) << uc->init_target_page->bits;
    uc->init_target_page->decided = true;

    /*
     * For the benefit of an -flto build, prevent the compiler from
     * hoisting a read from target_page before we finish initializing.
     */
    barrier();
#endif
}
