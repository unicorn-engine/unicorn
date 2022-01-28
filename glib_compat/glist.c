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
#include "glist.h"
#include "gslice.h"
#include "gmessages.h"

#define _g_list_alloc()         g_slice_new (GList)
#define _g_list_alloc0()        g_slice_new0 (GList)
#define _g_list_free1(list)     g_slice_free (GList, list)

/**
 * g_list_alloc:
 *
 * Allocates space for one #GList element. It is called by
 * g_list_append(), g_list_prepend(), g_list_insert() and
 * g_list_insert_sorted() and so is rarely used on its own.
 *
 * Returns: a pointer to the newly-allocated #GList element
 **/
GList *g_list_alloc (void)
{
    return _g_list_alloc0 ();
}

static inline GList *_g_list_remove_link (GList *list, GList *link)
{
    if (link == NULL)
        return list;

    if (link->prev)
    {
        if (link->prev->next == link)
            link->prev->next = link->next;
        //else
        //  g_warning ("corrupted double-linked list detected");
    }
    if (link->next)
    {
        if (link->next->prev == link)
            link->next->prev = link->prev;
        //else
        //  g_warning ("corrupted double-linked list detected");
    }

    if (link == list)
        list = list->next;

    link->next = NULL;
    link->prev = NULL;

    return list;
}

/**
 * g_list_delete_link:
 * @list: a #GList, this must point to the top of the list
 * @link_: node to delete from @list
 *
 * Removes the node link_ from the list and frees it. 
 * Compare this to g_list_remove_link() which removes the node 
 * without freeing it.
 *
 * Returns: the (possibly changed) start of the #GList
 */
GList *g_list_delete_link (GList *list, GList *link_)
{
    list = _g_list_remove_link (list, link_);
    _g_list_free1 (link_);

    return list;
}

/**
 * g_list_insert_before:
 * @list: a pointer to a #GList, this must point to the top of the list
 * @sibling: the list element before which the new element 
 *     is inserted or %NULL to insert at the end of the list
 * @data: the data for the new element
 *
 * Inserts a new element into the list before the given position.
 *
 * Returns: the (possibly changed) start of the #GList
 */
GList *g_list_insert_before (GList *list, GList *sibling, gpointer data)
{
    if (list == NULL)
    {
        list = g_list_alloc ();
        list->data = data;
        g_return_val_if_fail (sibling == NULL, list);
        return list;
    }
    else if (sibling != NULL)
    {
        GList *node;

        node = _g_list_alloc ();
        node->data = data;
        node->prev = sibling->prev;
        node->next = sibling;
        sibling->prev = node;
        if (node->prev != NULL)
        {
            node->prev->next = node;
            return list;
        }
        else
        {
            g_return_val_if_fail (sibling == list, node);
            return node;
        }
    }
    else
    {
        GList *last;

        for (last = list; last->next != NULL; last = last->next) {}

        last->next = _g_list_alloc ();
        last->next->data = data;
        last->next->prev = last;
        last->next->next = NULL;

        return list;
    }
}

