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

#ifndef __G_TREE_H__
#define __G_TREE_H__

typedef struct _GTree GTree;

typedef gboolean (*GTraverseFunc) (gpointer key, gpointer value, gpointer data);

/* Balanced binary trees
 */
GTree*   g_tree_new (GCompareFunc key_compare_func);

GTree*   g_tree_new_full (GCompareDataFunc  key_compare_func,
        gpointer          key_compare_data,
        GDestroyNotify    key_destroy_func,
        GDestroyNotify    value_destroy_func);

GTree*   g_tree_ref (GTree *tree);

void     g_tree_destroy (GTree *tree);

void     g_tree_insert (GTree *tree, gpointer key, gpointer value);

void g_tree_remove_all (GTree *tree);

gboolean g_tree_remove (GTree *tree, gconstpointer key);

gpointer g_tree_lookup (GTree *tree, gconstpointer key);

void     g_tree_foreach (GTree *tree, GTraverseFunc	func, gpointer user_data);

gint     g_tree_nnodes (GTree *tree);

#endif /* __G_TREE_H__ */
