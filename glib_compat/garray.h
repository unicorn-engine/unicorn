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

#ifndef __G_ARRAY_H__
#define __G_ARRAY_H__

#include "gtypes.h"

typedef struct _GBytes      GBytes;
typedef struct _GArray		GArray;
typedef struct _GByteArray	GByteArray;
typedef struct _GPtrArray	GPtrArray;

struct _GArray
{
    gchar *data;
    guint len;
};

struct _GByteArray
{
    guint8 *data;
    guint	  len;
};

struct _GPtrArray
{
    gpointer *pdata;
    guint	    len;
};

/* Resizable arrays. remove fills any cleared spot and shortens the
 * array, while preserving the order. remove_fast will distort the
 * order by moving the last element to the position of the removed.
 */

#define g_array_append_val(a,v)	  g_array_append_vals (a, &(v), 1)
#define g_array_index(a,t,i)      (((t*) (void *) (a)->data) [(i)])

GArray* g_array_append_vals (GArray *array,
        gconstpointer data,
        guint         len);

GArray* g_array_new (gboolean zero_terminated, gboolean clear_, guint element_size);
GArray* g_array_sized_new (gboolean zero_terminated,
        gboolean clear_,
        guint    element_size,
        guint    reserved_size);

gchar*  g_array_free(GArray *array, gboolean free_segment);
GArray* g_array_set_size(GArray *array, guint length);
GArray*
g_array_remove_range (GArray *farray,
        guint   index_,
        guint   length);

void g_ptr_array_set_free_func (GPtrArray *array,
        GDestroyNotify element_free_func);

/* Resizable pointer array.  This interface is much less complicated
 * than the above.  Add appends a pointer.  Remove fills any cleared 
 * spot and shortens the array. remove_fast will again distort order.  
 */
#define    g_ptr_array_index(array,index_) ((array)->pdata)[index_]
GPtrArray* g_ptr_array_new_with_free_func (GDestroyNotify element_free_func);
void       g_ptr_array_add(GPtrArray *array, gpointer data);
GPtrArray* g_ptr_array_sized_new (guint reserved_size);
GPtrArray* g_ptr_array_remove_range (GPtrArray *array, guint index_, guint length);

/* Byte arrays, an array of guint8.  Implemented as a GArray,
 * but type-safe.
 */
GByteArray* g_byte_array_sized_new(guint reserved_size);
guint8*     g_byte_array_free(GByteArray *array, gboolean free_segment);
GByteArray* g_byte_array_append(GByteArray *array, const guint8 *data, guint len);
GByteArray* g_byte_array_set_size(GByteArray *array, guint length);

#endif /* __G_ARRAY_H__ */
