/*
glib_compat.h replacement functionality for glib code used in qemu
Copyright (C) 2016 Chris Eagle cseagle at gmail dot com

This program is free software; you can redistribute it and/or
modify it under the terms of the GNU General Public License
as published by the Free Software Foundation; either version 2
of the License, or (at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program; if not, write to the Free Software
Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
*/

#ifndef __GLIB_COMPAT_H
#define __GLIB_COMPAT_H

#include "unicorn/platform.h"
#include <stdarg.h>
#include <stdlib.h>
#include <assert.h>

#define G_MAXUINT UINT_MAX
#define G_MAXINT  INT_MAX

#include "gtestutils.h"
#include "gtypes.h"
#include "garray.h"
#include "gtree.h"
#include "ghash.h"
#include "gmem.h"
#include "gslice.h"
#include "gmessages.h"
#include "gpattern.h"
#include "grand.h"
#include "glist.h"
#include "gnode.h"

typedef gint (*GCompareDataFunc)(gconstpointer a,
                gconstpointer b,
                gpointer user_data);
typedef void (*GFunc)(gpointer data, gpointer user_data);
typedef gint (*GCompareFunc)(gconstpointer v1, gconstpointer v2);

guint g_str_hash(gconstpointer v);
gboolean g_str_equal(gconstpointer v1, gconstpointer v2);
guint g_int_hash(gconstpointer v);

gboolean g_int_equal(gconstpointer v1, gconstpointer v2);

int g_strcmp0(const char *str1, const char *str2);

GList *g_list_first(GList *list);
void g_list_foreach(GList *list, GFunc func, gpointer user_data);
void g_list_free(GList *list);
GList *g_list_insert_sorted(GList *list, gpointer data, GCompareFunc compare);
#define g_list_next(list) (list->next)
GList *g_list_prepend(GList *list, gpointer data);
GList *g_list_remove_link(GList *list, GList *llink);
GList *g_list_sort(GList *list, GCompareFunc compare);

typedef struct _GSList {
  gpointer data;
  struct _GSList *next;
} GSList;

GSList *g_slist_append(GSList *list, gpointer data);
void g_slist_foreach(GSList *list, GFunc func, gpointer user_data);
void g_slist_free(GSList *list);
GSList *g_slist_prepend(GSList *list, gpointer data);
GSList *g_slist_sort(GSList *list, GCompareFunc compare);
GSList *g_slist_find_custom(GSList *list, gconstpointer data, GCompareFunc func);

/* replacement for g_malloc dependency */
void g_free(gpointer ptr);
gpointer g_realloc(gpointer ptr, size_t size);

char *g_strdup(const char *str);
char *g_strdup_printf(const char *format, ...);
char *g_strdup_vprintf(const char *format, va_list ap);
char *g_strndup(const char *str, size_t n);
void g_strfreev(char **v);
gpointer g_memdup(gconstpointer mem, size_t byte_size);
gpointer g_new_(size_t sz, size_t n_structs);
gpointer g_new0_(size_t sz, size_t n_structs);
gpointer g_renew_(size_t sz, gpointer mem, size_t n_structs);

gchar** g_strsplit (const gchar *string,
            const gchar *delimiter,
            gint         max_tokens);

#endif
