/* GLIB sliced memory - fast concurrent memory chunk allocator
 * Copyright (C) 2005 Tim Janik
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, see <http://www.gnu.org/licenses/>.
 */
/* MT safe */

#include <string.h>

#include "gtypes.h"
#include "gslice.h"
#include "gmem.h"               /* gslice.h */

/**
 * g_slice_alloc:
 * @block_size: the number of bytes to allocate
 *
 * Allocates a block of memory from the slice allocator.
 * The block address handed out can be expected to be aligned
 * to at least 1 * sizeof (void*),
 * though in general slices are 2 * sizeof (void*) bytes aligned,
 * if a malloc() fallback implementation is used instead,
 * the alignment may be reduced in a libc dependent fashion.
 * Note that the underlying slice allocation mechanism can
 * be changed with the [`G_SLICE=always-malloc`][G_SLICE]
 * environment variable.
 *
 * Returns: a pointer to the allocated memory block, which will be %NULL if and
 *    only if @mem_size is 0
 *
 * Since: 2.10
 */
gpointer g_slice_alloc (gsize mem_size)
{
    return g_malloc (mem_size);
}

/**
 * g_slice_alloc0:
 * @block_size: the number of bytes to allocate
 *
 * Allocates a block of memory via g_slice_alloc() and initializes
 * the returned memory to 0. Note that the underlying slice allocation
 * mechanism can be changed with the [`G_SLICE=always-malloc`][G_SLICE]
 * environment variable.
 *
 * Returns: a pointer to the allocated block, which will be %NULL if and only
 *    if @mem_size is 0
 *
 * Since: 2.10
 */
gpointer g_slice_alloc0 (gsize mem_size)
{
    gpointer mem = g_slice_alloc (mem_size);
    if (mem)
        memset (mem, 0, mem_size);
    return mem;
}

/**
 * g_slice_free1:
 * @block_size: the size of the block
 * @mem_block: a pointer to the block to free
 *
 * Frees a block of memory.
 *
 * The memory must have been allocated via g_slice_alloc() or
 * g_slice_alloc0() and the @block_size has to match the size
 * specified upon allocation. Note that the exact release behaviour
 * can be changed with the [`G_DEBUG=gc-friendly`][G_DEBUG] environment
 * variable, also see [`G_SLICE`][G_SLICE] for related debugging options.
 *
 * If @mem_block is %NULL, this function does nothing.
 *
 * Since: 2.10
 */
void g_slice_free1 (gsize mem_size, gpointer mem_block)
{
    g_free (mem_block);
}
