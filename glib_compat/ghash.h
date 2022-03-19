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

#ifndef __G_HASH_H__
#define __G_HASH_H__

#include "gtypes.h"

typedef struct _GHashTable GHashTable;

typedef gboolean (*GHRFunc) (gpointer key, gpointer value, gpointer user_data);

struct _GHashTableIter
{
    /*< private >*/
    gpointer      dummy1;
    gpointer      dummy2;
    gpointer      dummy3;
    int           dummy4;
    gboolean      dummy5;
    gpointer      dummy6;
};

GHashTable* g_hash_table_new (GHashFunc hash_func, GEqualFunc key_equal_func);

GHashTable* g_hash_table_new_full (GHashFunc hash_func,
        GEqualFunc      key_equal_func,
        GDestroyNotify  key_destroy_func,
        GDestroyNotify  value_destroy_func);

void g_hash_table_destroy (GHashTable *hash_table);

gboolean g_hash_table_insert (GHashTable *hash_table, gpointer key, gpointer value);

void g_hash_table_replace (GHashTable *hash_table, gpointer key, gpointer value);

gboolean g_hash_table_remove (GHashTable *hash_table, gconstpointer key);

void g_hash_table_remove_all (GHashTable *hash_table);

gpointer g_hash_table_lookup (GHashTable *hash_table, gconstpointer key);

void g_hash_table_foreach (GHashTable *hash_table, GHFunc func, gpointer user_data);

guint g_hash_table_size (GHashTable *hash_table);

GHashTable* g_hash_table_ref (GHashTable *hash_table);

void g_hash_table_unref (GHashTable *hash_table);

/* Hash Functions
 */
gboolean g_int_equal (gconstpointer v1, gconstpointer v2);
guint    g_int_hash (gconstpointer v);

#endif /* __G_HASH_H__ */
