/*
 * pagesize.c - query the host about its page size
 *
 * Copyright (C) 2017, Emilio G. Cota <cota@braap.org>
 * License: GNU GPL, version 2 or later.
 *   See the COPYING file in the top-level directory.
 */

#include "qemu/osdep.h"

#include <uc_priv.h>

void init_real_host_page_size(struct uc_struct *uc)
{
    uc->qemu_real_host_page_size = getpagesize();
}
