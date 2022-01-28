/* GLIB - Library of useful routines for C programming
 * Copyright (C) 1995-1997  Peter Mattis, Spencer Kimball and Josh MacDonald
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

/*
 * Modified by the GLib Team and others 1997-2000.  See the AUTHORS
 * file for a list of people on the GLib Team.  See the ChangeLog
 * files for a list of changes.  These files are distributed with
 * GLib at ftp://ftp.gtk.org/pub/gtk/. 
 */

/* 
 * MT safe
 */

#include "gtypes.h"
#include "gmem.h"

#include <stdlib.h>

#include "gslice.h"

#define SIZE_OVERFLOWS(a,b) (((b) > 0 && (a) > G_MAXSIZE / (b)))


/**
 * g_try_malloc:
 * @n_bytes: number of bytes to allocate.
 * 
 * Attempts to allocate @n_bytes, and returns %NULL on failure.
 * Contrast with g_malloc(), which aborts the program on failure.
 * 
 * Returns: the allocated memory, or %NULL.
 */
gpointer g_try_malloc (gsize n_bytes)
{
    gpointer mem;

    if (n_bytes)
        mem = malloc (n_bytes);
    else
        mem = NULL;

    return mem;
}

/**
 * g_try_malloc_n:
 * @n_blocks: the number of blocks to allocate
 * @n_block_bytes: the size of each block in bytes
 * 
 * This function is similar to g_try_malloc(), allocating (@n_blocks * @n_block_bytes) bytes,
 * but care is taken to detect possible overflow during multiplication.
 * 
 * Since: 2.24
 * Returns: the allocated memory, or %NULL.
 */
gpointer g_try_malloc_n (gsize n_blocks, gsize n_block_bytes)
{
    if (SIZE_OVERFLOWS (n_blocks, n_block_bytes))
        return NULL;

    return g_try_malloc (n_blocks * n_block_bytes);
}

/**
 * g_malloc:
 * @n_bytes: the number of bytes to allocate
 * 
 * Allocates @n_bytes bytes of memory.
 * If @n_bytes is 0 it returns %NULL.
 * 
 * Returns: a pointer to the allocated memory
 */
gpointer g_malloc (gsize n_bytes)
{
    if (n_bytes) {
        gpointer mem;

        mem = malloc (n_bytes);
        if (mem)
            return mem;

        //g_error ("%s: failed to allocate %"G_GSIZE_FORMAT" bytes",
        //         G_STRLOC, n_bytes);
    }

    return NULL;
}

/**
 * g_malloc_n:
 * @n_blocks: the number of blocks to allocate
 * @n_block_bytes: the size of each block in bytes
 * 
 * This function is similar to g_malloc(), allocating (@n_blocks * @n_block_bytes) bytes,
 * but care is taken to detect possible overflow during multiplication.
 * 
 * Since: 2.24
 * Returns: a pointer to the allocated memory
 */
gpointer g_malloc_n (gsize n_blocks, gsize n_block_bytes)
{
    if (SIZE_OVERFLOWS (n_blocks, n_block_bytes)) {
        //g_error ("%s: overflow allocating %"G_GSIZE_FORMAT"*%"G_GSIZE_FORMAT" bytes",
        //         G_STRLOC, n_blocks, n_block_bytes);
    }

    return g_malloc (n_blocks * n_block_bytes);
}

/**
 * g_malloc0:
 * @n_bytes: the number of bytes to allocate
 * 
 * Allocates @n_bytes bytes of memory, initialized to 0's.
 * If @n_bytes is 0 it returns %NULL.
 * 
 * Returns: a pointer to the allocated memory
 */
gpointer g_malloc0 (gsize n_bytes)
{
    if (n_bytes) {
        gpointer mem;

        mem = calloc (1, n_bytes);
        if (mem)
            return mem;

        //g_error ("%s: failed to allocate %"G_GSIZE_FORMAT" bytes",
        //         G_STRLOC, n_bytes);
    }

    return NULL;
}

/**
 * g_malloc0_n:
 * @n_blocks: the number of blocks to allocate
 * @n_block_bytes: the size of each block in bytes
 * 
 * This function is similar to g_malloc0(), allocating (@n_blocks * @n_block_bytes) bytes,
 * but care is taken to detect possible overflow during multiplication.
 * 
 * Since: 2.24
 * Returns: a pointer to the allocated memory
 */
gpointer g_malloc0_n (gsize n_blocks, gsize n_block_bytes)
{
    if (SIZE_OVERFLOWS (n_blocks, n_block_bytes)) {
        //g_error ("%s: overflow allocating %"G_GSIZE_FORMAT"*%"G_GSIZE_FORMAT" bytes",
        //         G_STRLOC, n_blocks, n_block_bytes);
    }

    return g_malloc0 (n_blocks * n_block_bytes);
}

/**
 * g_try_malloc0:
 * @n_bytes: number of bytes to allocate
 * 
 * Attempts to allocate @n_bytes, initialized to 0's, and returns %NULL on
 * failure. Contrast with g_malloc0(), which aborts the program on failure.
 * 
 * Since: 2.8
 * Returns: the allocated memory, or %NULL
 */
gpointer g_try_malloc0 (gsize n_bytes)
{
    gpointer mem;

    if (n_bytes)
        mem = calloc (1, n_bytes);
    else
        mem = NULL;

    return mem;
}

/**
 * g_realloc:
 * @mem: (nullable): the memory to reallocate
 * @n_bytes: new size of the memory in bytes
 * 
 * Reallocates the memory pointed to by @mem, so that it now has space for
 * @n_bytes bytes of memory. It returns the new address of the memory, which may
 * have been moved. @mem may be %NULL, in which case it's considered to
 * have zero-length. @n_bytes may be 0, in which case %NULL will be returned
 * and @mem will be freed unless it is %NULL.
 * 
 * Returns: the new address of the allocated memory
 */
gpointer g_realloc (gpointer mem, gsize    n_bytes)
{
    gpointer newmem;

    if (n_bytes) {
        newmem = realloc (mem, n_bytes);
        if (newmem)
            return newmem;

        //g_error("%s: failed to allocate %"G_GSIZE_FORMAT" bytes", G_STRLOC, n_bytes);
    }

    free (mem);

    return NULL;
}

/**
 * g_realloc_n:
 * @mem: (nullable): the memory to reallocate
 * @n_blocks: the number of blocks to allocate
 * @n_block_bytes: the size of each block in bytes
 * 
 * This function is similar to g_realloc(), allocating (@n_blocks * @n_block_bytes) bytes,
 * but care is taken to detect possible overflow during multiplication.
 * 
 * Since: 2.24
 * Returns: the new address of the allocated memory
 */
gpointer g_realloc_n (gpointer mem, gsize n_blocks, gsize n_block_bytes)
{
    if (SIZE_OVERFLOWS (n_blocks, n_block_bytes)) {
        //g_error ("%s: overflow allocating %"G_GSIZE_FORMAT"*%"G_GSIZE_FORMAT" bytes",
        //         G_STRLOC, n_blocks, n_block_bytes);
    }

    return g_realloc (mem, n_blocks * n_block_bytes);
}

/**
 * g_free:
 * @mem: (nullable): the memory to free
 * 
 * Frees the memory pointed to by @mem.
 *
 * If @mem is %NULL it simply returns, so there is no need to check @mem
 * against %NULL before calling this function.
 */
void g_free (gpointer mem)
{
    free (mem);
}
