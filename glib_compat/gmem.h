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
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.	 See the GNU
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

#ifndef __G_MEM_H__
#define __G_MEM_H__

#include <limits.h>
#include "gmacros.h"

#define G_MAXSIZE ULONG_MAX

/* Optimise: avoid the call to the (slower) _n function if we can
 * determine at compile-time that no overflow happens.
 */
#if defined (__GNUC__) && (__GNUC__ >= 2) && defined (__OPTIMIZE__)
#  define _G_NEW(struct_type, n_structs, func) \
    (struct_type *) (G_GNUC_EXTENSION ({			\
                gsize __n = (gsize) (n_structs);			\
                gsize __s = sizeof (struct_type);			\
                gpointer __p;						\
                if (__s == 1)						\
                __p = g_##func (__n);				\
                else if (__builtin_constant_p (__n) &&		\
                        (__s == 0 || __n <= G_MAXSIZE / __s))	\
                        __p = g_##func (__n * __s);				\
                        else							\
                        __p = g_##func##_n (__n, __s);			\
                        __p;							\
                        }))
#  define _G_RENEW(struct_type, mem, n_structs, func) \
    (struct_type *) (G_GNUC_EXTENSION ({			\
                gsize __n = (gsize) (n_structs);			\
                gsize __s = sizeof (struct_type);			\
                gpointer __p = (gpointer) (mem);			\
                if (__s == 1)						\
                __p = g_##func (__p, __n);				\
                else if (__builtin_constant_p (__n) &&		\
                        (__s == 0 || __n <= G_MAXSIZE / __s))	\
                        __p = g_##func (__p, __n * __s);			\
                        else							\
                        __p = g_##func##_n (__p, __n, __s);			\
                        __p;							\
                        }))

#else
/* Unoptimised version: always call the _n() function. */
#define _G_NEW(struct_type, n_structs, func) \
    ((struct_type *) g_##func##_n ((n_structs), sizeof (struct_type)))
#define _G_RENEW(struct_type, mem, n_structs, func) \
    ((struct_type *) g_##func##_n (mem, (n_structs), sizeof (struct_type)))

#endif

gpointer g_try_malloc     (gsize	 n_bytes);

gpointer g_try_malloc0    (gsize	 n_bytes);

gpointer g_try_malloc_n   (gsize	 n_blocks, gsize	 n_block_bytes);

gpointer g_malloc0_n      (gsize	 n_blocks, gsize	 n_block_bytes);

gpointer g_realloc_n      (gpointer	 mem, gsize	 n_blocks, gsize	 n_block_bytes);

gpointer g_malloc_n       (gsize	 n_blocks, gsize	 n_block_bytes);

gpointer g_malloc0        (gsize	 n_bytes);

gpointer g_malloc         (gsize	 n_bytes);

void	 g_free	          (gpointer	 mem);

/**
 * g_try_new:
 * @struct_type: the type of the elements to allocate
 * @n_structs: the number of elements to allocate
 * 
 * Attempts to allocate @n_structs elements of type @struct_type, and returns
 * %NULL on failure. Contrast with g_new(), which aborts the program on failure.
 * The returned pointer is cast to a pointer to the given type.
 * The function returns %NULL when @n_structs is 0 of if an overflow occurs.
 * 
 * Since: 2.8
 * Returns: a pointer to the allocated memory, cast to a pointer to @struct_type
 */
#define g_try_new(struct_type, n_structs)		_G_NEW (struct_type, n_structs, try_malloc)
#define g_new0(struct_type, n_structs)			_G_NEW (struct_type, n_structs, malloc0)
#define g_new(struct_type, n_structs)			_G_NEW (struct_type, n_structs, malloc)
#define g_renew(struct_type, mem, n_structs)	_G_RENEW (struct_type, mem, n_structs, realloc)

#endif /* __G_MEM_H__ */
