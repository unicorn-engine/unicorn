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

#ifndef TRUE
#define TRUE 1
#endif

#ifndef FALSE
#define FALSE 0
#endif

#define g_assert(expr) assert(expr)
#define g_assert_not_reached() assert(0)

/* typedefs for glib related types that may still be referenced */
typedef void* gpointer;
typedef const void *gconstpointer;
typedef int gint;
typedef uint32_t guint32;
typedef uint64_t guint64;
typedef unsigned int guint;
typedef char gchar;
typedef int gboolean;
typedef unsigned long gulong;
typedef unsigned long gsize;

typedef gint (*GCompareDataFunc)(gconstpointer a,
                gconstpointer b,
                gpointer user_data);
typedef void (*GFunc)(gpointer data, gpointer user_data);
typedef gint (*GCompareFunc)(gconstpointer v1, gconstpointer v2);
typedef void (*GDestroyNotify)(gpointer data);

guint g_str_hash(gconstpointer v);
gboolean g_str_equal(gconstpointer v1, gconstpointer v2);
guint g_int_hash(gconstpointer v);

gboolean g_int_equal(gconstpointer v1, gconstpointer v2);

typedef struct _GList {
  gpointer data;
  struct _GList *next;
  struct _GList *prev;
} GList;

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


typedef guint (*GHashFunc)(gconstpointer key);
typedef gboolean (*GEqualFunc)(gconstpointer a, gconstpointer b);
typedef void (*GHFunc)(gpointer key, gpointer value, gpointer user_data);
typedef gboolean (*GHRFunc)(gpointer key, gpointer value, gpointer user_data);

typedef struct _GHashTable GHashTable;

void g_hash_table_destroy(GHashTable *hash_table);
gpointer g_hash_table_find(GHashTable *hash_table, GHRFunc predicate, gpointer user_data);
void g_hash_table_foreach(GHashTable *hash_table, GHFunc func, gpointer user_data);
void g_hash_table_insert(GHashTable *hash_table, gpointer key, gpointer value);
gpointer g_hash_table_lookup(GHashTable *hash_table, gconstpointer key);
GHashTable *g_hash_table_new(GHashFunc hash_func, GEqualFunc key_equal_func);
GHashTable *g_hash_table_new_full(GHashFunc hash_func, GEqualFunc key_equal_func, 
                                  GDestroyNotify key_destroy_func, GDestroyNotify value_destroy_func);
void g_hash_table_remove_all(GHashTable *hash_table);
gboolean g_hash_table_remove(GHashTable *hash_table, gconstpointer key);
void g_hash_table_unref(GHashTable *hash_table);
GHashTable *g_hash_table_ref(GHashTable *hash_table);
guint g_hash_table_size(GHashTable *hash_table);

/* replacement for g_malloc dependency */
void g_free(gpointer ptr);
gpointer g_malloc(size_t size);
gpointer g_malloc0(size_t size);
gpointer g_try_malloc0(size_t size);
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
gchar* g_strconcat (const gchar *string1, ...);
gchar** g_strsplit (const gchar *string,
            const gchar *delimiter,
            gint         max_tokens);


#define g_new(struct_type, n_structs) ((struct_type*)g_new_(sizeof(struct_type), n_structs))
#define g_new0(struct_type, n_structs) ((struct_type*)g_new0_(sizeof(struct_type), n_structs))
#define g_renew(struct_type, mem, n_structs) ((struct_type*)g_renew_(sizeof(struct_type), mem, n_structs))

#endif
