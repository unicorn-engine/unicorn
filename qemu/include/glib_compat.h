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

#include <stdint.h>
#include <stdarg.h>
#include <stdlib.h>
#include <assert.h>

#ifndef TRUE
#define TRUE 1
#endif

#ifndef FALSE
#define FALSE 1
#endif

#define g_assert(expr) assert(expr)
#define g_assert_not_reached() assert(0)

/* typedefs for glib related types that may still be referenced */
typedef void* gpointer;
typedef const void *gconstpointer;
typedef int gint;
typedef unsigned int guint;
typedef char gchar;
typedef int gboolean;

typedef void (*GFunc)(void* data, void* user_data);
typedef gint (*GCompareFunc)(const void *v1, const void *v2);
typedef void (*GDestroyNotify)(void *data);

guint g_direct_hash(const void *v);
guint g_str_hash(const void *v);
int g_str_equal(const void *v1, const void *v2);
guint g_int_hash(const void *v);
int g_int_equal(const void *v1, const void *v2);

typedef struct _GList {
  void *data;
  struct _GList *next;
  struct _GList *prev;
} GList;

GList *g_list_first(GList *list);
void g_list_foreach(GList *list, GFunc func, void* user_data);
void g_list_free(GList *list);
GList *g_list_insert_sorted(GList *list, void* data, GCompareFunc compare);
#define g_list_next(list) (list->next)
GList *g_list_prepend(GList *list, void* data);
GList *g_list_remove_link(GList *list, GList *llink);
GList *g_list_sort(GList *list, GCompareFunc compare);

typedef struct _GSList {
  void *data;
  struct _GSList *next;
} GSList;

GSList *g_slist_append(GSList *list, void* data);
void g_slist_foreach(GSList *list, GFunc func, void* user_data);
void g_slist_free(GSList *list);
GSList *g_slist_prepend(GSList *list, void* data);
GSList *g_slist_sort(GSList *list, GCompareFunc compare);

typedef guint (*GHashFunc)(const void *key);
typedef int (*GEqualFunc)(const void *a, const void *b);
typedef void (*GHFunc)(void* key, void* value, void* user_data);
typedef int (*GHRFunc)(void* key, void* value, void* user_data);

typedef struct _GHashTable GHashTable;

void g_hash_table_destroy(GHashTable *hash_table);
void* g_hash_table_find(GHashTable *hash_table, GHRFunc predicate, void* user_data);
void g_hash_table_foreach(GHashTable *hash_table, GHFunc func, void* user_data);
int g_hash_table_insert(GHashTable *hash_table, void* key, void* value);
void* g_hash_table_lookup(GHashTable *hash_table, const void* key);
GHashTable *g_hash_table_new(GHashFunc hash_func, GEqualFunc key_equal_func);
GHashTable *g_hash_table_new_full(GHashFunc hash_func, GEqualFunc key_equal_func, 
                                  GDestroyNotify key_destroy_func, GDestroyNotify value_destroy_func);
void g_hash_table_remove_all(GHashTable *hash_table);
int g_hash_table_remove(GHashTable *hash_table, const void* key);
void g_hash_table_unref(GHashTable *hash_table);
GHashTable *g_hash_table_ref(GHashTable *hash_table);
guint g_hash_table_size(GHashTable *hash_table);

/* replacement for g_malloc dependency */
void g_free(void *ptr);
void *g_malloc(size_t size);
void *g_malloc0(size_t size);
void *g_try_malloc0(size_t size);
void *g_realloc(void *ptr, size_t size);
char *g_strdup(const char *str);
char *g_strdup_printf(const char *format, ...);
char *g_strdup_vprintf(const char *format, va_list ap);
char *g_strndup(const char *str, size_t n);
void g_strfreev(char **v);
void *g_memdup(const void *mem, size_t byte_size);
void *g_new_(size_t sz, size_t n_structs);
void *g_new0_(size_t sz, size_t n_structs);
void *g_renew_(size_t sz, void *mem, size_t n_structs);
char *g_strconcat(const char *string1, ...);

char **g_strsplit(const char *string, const char *delimiter, int max_tokens);

#define g_new(struct_type, n_structs) ((struct_type*)g_new_(sizeof(struct_type), n_structs))
#define g_new0(struct_type, n_structs) ((struct_type*)g_new0_(sizeof(struct_type), n_structs))
#define g_renew(struct_type, mem, n_structs) ((struct_type*)g_renew_(sizeof(struct_type), mem, n_structs))

#ifdef _WIN32
char *g_win32_error_message(int error);
#endif

#endif
