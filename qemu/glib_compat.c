/*
glib_compat.c replacement functionality for glib code used in qemu
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

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <string.h>
#include <stdlib.h>
#include <stdio.h>

#include "glib_compat.h"

#undef __HAVE_64_BIT_PTRS

#ifdef _WIN64
    #define __HAVE_64_BIT_PTRS
#endif

#ifdef __GNUC__
#if defined(__x86_64__) || defined(__ppc64__) || defined(__aarch64__)
    #define __HAVE_64_BIT_PTRS
#endif
#endif

/* All functions below added to eliminate GLIB dependency */

/* hashing and equality functions */

/*
   Too many pointers are multiples of 8/16 so I rotate the low bits out
   otherwise we get too many collisions at multiples of 8/16
   This may be marginally better than what glib does in their direct_hash
   but someone with some chops in this space should fix if it needs improving
*/
guint g_direct_hash(gconstpointer v)
{
#ifdef __HAVE_64_BIT_PTRS
   uint64_t hash = (uint64_t)v;
   hash = (hash >> 4) | (hash << 60);
   hash = hash ^ (hash >> 32);
   return (guint)hash;
#else
   guint hash = (guint)v;
   hash = (hash >> 3) | (hash << 29);
   return hash;
#endif
}

/*
   djb2+ string hashing
   see: http://www.cse.yorku.ca/~oz/hash.html
*/
guint g_str_hash(gconstpointer v)
{
   const char *s = (const char*)v;
   guint hash = 5381;
   while (*s) {
      hash = ((hash << 5) + hash) ^ (int)*s;      
      s++;
   }
   return hash;
}

gboolean g_str_equal(gconstpointer v1, gconstpointer v2)
{
   return strcmp((const char*)v1, (const char*)v2) == 0;
}

/*
  Bob Jenkins integer hash algorithm
  see: http://burtleburtle.net/bob/hash/integer.html
*/
guint g_int_hash(gconstpointer v)
{
   guint hash = *(const guint*)v;
   hash = (hash + 0x7ed55d16) + (hash << 12);
   hash = (hash ^ 0xc761c23c) ^ (hash >> 19);
   hash = (hash + 0x165667b1) + (hash << 5);
   hash = (hash + 0xd3a2646c) ^ (hash << 9);
   hash = (hash + 0xfd7046c5) + (hash << 3);
   hash = (hash ^ 0xb55a4f09) ^ (hash >> 16);
   return hash;
}

gboolean g_int_equal(gconstpointer v1, gconstpointer v2)
{
   return *(const int*)v1 == *(const int*)v2;
}

/* Doubly-linked list */

GList *g_list_first(GList *list)
{
   if (list == NULL) return NULL;
   while (list->prev) list = list->prev;
   return list;
}

void g_list_foreach(GList *list, GFunc func, gpointer user_data)
{
   GList *lp;
   for (lp = list; lp; lp = lp->next) {
      (*func)(lp->data, user_data);
   }
}

void g_list_free(GList *list)
{
   GList *lp, *next, *prev = NULL;
   if (list) prev = list->prev;
   for (lp = list; lp; lp = next) {
      next = lp->next;
      free(lp);
   }
   for (lp = prev; lp; lp = prev) {
      prev = lp->prev;
      free(lp);
   }
}

GList *g_list_insert_sorted(GList *list, gpointer data, GCompareFunc compare)
{
   GList *i;
   GList *n = (GList*)g_malloc(sizeof(GList));
   n->data = data;
   if (list == NULL) {
      n->next = n->prev = NULL;
      return n;
   }
   for (i = list; i; i = i->next) {
      n->prev = i->prev;
      if ((*compare)(data, i->data) <= 0) {
         n->next = i;
         i->prev = n;
         if (i == list) return n;
         else return list;
      }
   }
   n->prev = n->prev->next;
   n->next = NULL;
   n->prev->next = n;
   return list;
}

GList *g_list_prepend(GList *list, gpointer data)
{
   GList *n = (GList*)g_malloc(sizeof(GList));
   n->next = list;
   n->prev = NULL;
   n->data = data;
   return n;
}

GList *g_list_remove_link(GList *list, GList *llink)
{
   if (llink) {
      if (llink == list) list = list->next;
      if (llink->prev) llink->prev->next = llink->next;
      if (llink->next) llink->next->prev = llink->prev;
   }
   return list;
}

GList *g_list_sort(GList *list, GCompareFunc compare)
{
   GList *i, *it, *j;
   /* base case for singletons or empty lists */
   if (list == NULL || list->next == NULL) return list;
   i = list;
   j = i->next;
   /* i walks half as fast as j, ends up in middle */
   while (j) {
      j = j->next;
      if (j) {
         i = i->next;
         j = j->next;
      }
   }
   /* split the list midway */
   j = i->next;
   j->prev = NULL;  /* make j the head of its own list */
   i->next = NULL;
   /* will never have NULL return from either call below */
   i = g_list_sort(list, compare);
   j = g_list_sort(j, compare);
   if ((*compare)(i->data, j->data) <= 0) {
      list = i;
      i = i->next;
   } else {
      list = j;
      j = j->next;
   }
   it = list;
   while (i && j) {
      if ((*compare)(i->data, j->data) <= 0) {
         it->next = i;
         i = i->next;
      } else {
         it->next = j;
         j = j->next;
      }
      it = it->next;
   }
   if (i) it->next = i;
   else it->next = j;
   return list;
}

/* END of g_list related functions */

/* Singly-linked list */

GSList *g_slist_append(GSList *list, gpointer data)
{
   GSList *head = list;
   if (list) {
      while (list->next) list = list->next;
      list->next = (GSList*)g_malloc(sizeof(GSList));
      list = list->next;
   } else {
      head = list = (GSList*)g_malloc(sizeof(GSList));
   }
   list->data = data;
   list->next = NULL;
   return head;   
}

void g_slist_foreach(GSList *list, GFunc func, gpointer user_data)
{
   GSList *lp;
   for (lp = list; lp; lp = lp->next) {
      (*func)(lp->data, user_data);
   }
}

void g_slist_free(GSList *list)
{
   GSList *lp, *next;
   for (lp = list; lp; lp = next) {
      next = lp->next;
      free(lp);
   }
}

GSList *g_slist_prepend(GSList *list, gpointer data)
{
   GSList *head = (GSList*)g_malloc(sizeof(GSList));
   head->next = list;
   head->data = data;
   return head;   
}

GSList *g_slist_sort(GSList *list, GCompareFunc compare)
{
   GSList *i, *it, *j;
   /* base case for singletons or empty lists */
   if (list == NULL || list->next == NULL) return list;
   i = list;
   j = i->next;
   /* i walks half as fast as j, ends up in middle */
   while (j) {
      j = j->next;
      if (j) {
         i = i->next;
         j = j->next;
      }
   }
   /* split the list midway */
   j = i->next;
   i->next = NULL;
   /* will never have NULL return from either call below */
   i = g_slist_sort(list, compare);
   j = g_slist_sort(j, compare);
   if ((*compare)(i->data, j->data) <= 0) {
      list = i;
      i = i->next;
   } else {
      list = j;
      j = j->next;
   }
   it = list;
   while (i && j) {
      if ((*compare)(i->data, j->data) <= 0) {
         it->next = i;
         i = i->next;
      } else {
         it->next = j;
         j = j->next;
      }
      it = it->next;
   }
   if (i) it->next = i;
   else it->next = j;
   return list;
}

/* END of g_slist related functions */


/* Hash table */

typedef struct _KeyValue {
   gpointer key;
   gpointer value;
} KeyValue;

struct _GHashTable {
   GHashFunc hash_func;
   GEqualFunc key_equal_func;
   GDestroyNotify key_destroy_func;
   GDestroyNotify value_destroy_func;
   volatile gint refcount;
   gint size;
   guint num_entries;
   GSList **buckets;
};

void g_hash_table_destroy(GHashTable *hash_table)
{
   if (hash_table == NULL) return;
   g_hash_table_remove_all(hash_table);
   g_hash_table_unref(hash_table);
}

gpointer g_hash_table_find(GHashTable *hash_table, GHRFunc predicate, gpointer user_data)
{
   if (hash_table == NULL) return NULL;
   guint i;
   for (i = 0; i < hash_table->size; i++) {
      GSList *lp;
      for (lp = hash_table->buckets[i]; lp; lp = lp->next) {
         KeyValue *kv = (KeyValue*)(lp->data);
         if ((*predicate)(kv->key, kv->value, user_data)) return kv->value;
      }
   }
   return NULL;
}

void g_hash_table_foreach(GHashTable *hash_table, GHFunc func, gpointer user_data)
{
   if (hash_table == NULL) return;
   guint i;
   for (i = 0; i < hash_table->size; i++) {
      GSList *lp;
      for (lp = hash_table->buckets[i]; lp; lp = lp->next) {
         KeyValue *kv = (KeyValue*)(lp->data);
         (*func)(kv->key, kv->value, user_data);
      }
   }
}

gboolean g_hash_table_insert(GHashTable *hash_table, gpointer key, gpointer value)
{
   if (hash_table == NULL) return TRUE;
   GSList *lp;
   guint hash = (*hash_table->hash_func)(key);
   guint bnum = hash % hash_table->size;
   for (lp = hash_table->buckets[bnum]; lp; lp = lp->next) {
      KeyValue *kv = (KeyValue*)(lp->data);
      int match = hash_table->key_equal_func ? (*hash_table->key_equal_func)(kv->key, key) : (kv->key == key);
      if (match) {
         /* replace */
         kv->value = value;
         return FALSE;
      }
   }
   /* new key */
   KeyValue *pair = (KeyValue*)g_malloc(sizeof(KeyValue));
   pair->key = key;
   pair->value = value;
   hash_table->buckets[bnum] = g_slist_prepend(hash_table->buckets[bnum], pair);
   hash_table->num_entries++;
   /* grow and rehash at num_entries / size == ??? */
   return TRUE;
}

gpointer g_hash_table_lookup(GHashTable *hash_table, gconstpointer key)
{
   if (hash_table == NULL) return NULL;
   GSList *lp;
   guint hash = (*hash_table->hash_func)(key);
   guint bnum = hash % hash_table->size;
   for (lp = hash_table->buckets[bnum]; lp; lp = lp->next) {
      KeyValue *kv = (KeyValue*)(lp->data);
      int match = hash_table->key_equal_func ? (*hash_table->key_equal_func)(kv->key, key) : (kv->key == key);
      if (match) {
         return kv->value;
      }
   }
   return NULL;
}

GHashTable *g_hash_table_new(GHashFunc hash_func, GEqualFunc key_equal_func)
{
   return g_hash_table_new_full(hash_func, key_equal_func, NULL, NULL);
}

GHashTable *g_hash_table_new_full(GHashFunc hash_func, GEqualFunc key_equal_func, 
                                  GDestroyNotify key_destroy_func, GDestroyNotify value_destroy_func)
{
   GHashTable *ht = (GHashTable*)g_malloc(sizeof(GHashTable));
   ht->hash_func = hash_func ? hash_func : g_direct_hash;
   ht->key_equal_func = key_equal_func;
   ht->key_destroy_func = key_destroy_func;
   ht->value_destroy_func = value_destroy_func;
   g_hash_table_ref(ht);
   ht->size = 512;
   ht->num_entries = 0;
   ht->buckets = (GSList **)g_new0_(sizeof(GSList*), ht->size);
   return ht;
}

void g_hash_table_remove_all(GHashTable *hash_table)
{
   if (hash_table == NULL) return;
   guint i;
   for (i = 0; i < hash_table->size; i++) {
      GSList *lp;
      for (lp = hash_table->buckets[i]; lp; lp = lp->next) {
         KeyValue *kv = (KeyValue*)lp->data;
         if (hash_table->key_destroy_func) (*hash_table->key_destroy_func)(kv->key);
         if (hash_table->value_destroy_func) (*hash_table->value_destroy_func)(kv->value);
         free(lp->data);
      }
      g_slist_free(hash_table->buckets[i]);
      hash_table->buckets[i] = NULL;
   }
   hash_table->num_entries = 0;
}

gboolean g_hash_table_remove(GHashTable *hash_table, gconstpointer key)
{
   GSList *lp, *prev = NULL;
   if (hash_table == NULL) return FALSE;
   guint hash = (*hash_table->hash_func)(key);
   guint bnum = hash % hash_table->size;
   for (lp = hash_table->buckets[bnum]; lp; lp = lp->next) {
      KeyValue *kv = (KeyValue*)(lp->data);
      int match = hash_table->key_equal_func ? (*hash_table->key_equal_func)(kv->key, key) : (kv->key == key);
      if (match) {
         if (hash_table->key_destroy_func) (*hash_table->key_destroy_func)(kv->key);
         if (hash_table->value_destroy_func) (*hash_table->value_destroy_func)(kv->value);
         free(kv);
         if (prev == NULL) {
            hash_table->buckets[bnum] = lp->next;
         } else {
            prev->next = lp->next;
         }
         free(lp);
         return TRUE;
      }
      prev = lp;
   }
   return FALSE;
}

void g_hash_table_unref(GHashTable *hash_table)
{
   if (hash_table == NULL) return;
   if (hash_table->refcount == 0) return;
   hash_table->refcount--;
   if (hash_table->refcount == 0) {
      free(hash_table->buckets);
      free(hash_table);
   }
}

GHashTable *g_hash_table_ref(GHashTable *hash_table)
{
   if (hash_table == NULL) return NULL;
   hash_table->refcount++;
   return hash_table;
}

guint g_hash_table_size(GHashTable *hash_table)
{
   return hash_table ? hash_table->num_entries : 0;
}

/* END of g_hash_table related functions */

/* general g_XXX substitutes */

void g_free(gpointer ptr)
{
   free(ptr);
}

gpointer g_malloc(size_t size)
{
   if (size == 0) return NULL;
   void *res = malloc(size);
   if (res == NULL) exit(1);
   return res;
}

gpointer g_malloc0(size_t size)
{
   if (size == 0) return NULL;
   void *res = calloc(size, 1);
   if (res == NULL) exit(1);
   return res;
}

gpointer g_try_malloc0(size_t size)
{
   if (size == 0) return NULL;
   return calloc(size, 1);
}

gpointer g_realloc(gpointer ptr, size_t size)
{
   if (size == 0) {
      free(ptr);
      return NULL;
   }
   void *res = realloc(ptr, size);
   if (res == NULL) exit(1);
   return res;
}

char *g_strdup(const char *str)
{
   return str ? strdup(str) : NULL;
}

char *g_strdup_printf(const char *format, ...)
{
   va_list ap;
   char *res;
   va_start(ap, format);
   res = g_strdup_vprintf(format, ap);
   va_end(ap);
   return res;
}

char *g_strdup_vprintf(const char *format, va_list ap)
{
   char *str_res = NULL;
   vasprintf(&str_res, format, ap);
   return str_res;
}

char *g_strndup(const char *str, size_t n)
{
   /* try to mimic glib's g_strndup */
   char *res = calloc(n + 1, 1);
   strncpy(res, str, n);
   return res;
}

void g_strfreev(char **str_array)
{
   char **p = str_array;
   if (p) {
      while (*p) {
         free(*p++);
      }
   }
   free(str_array);
}

gpointer g_memdup(gconstpointer mem, size_t byte_size)
{
   if (mem) {
      void *res = g_malloc(byte_size);
      memcpy(res, mem, byte_size);
      return res;
   }
   return NULL; 
}

gpointer g_new_(size_t sz, size_t n_structs)
{
   size_t need = sz * n_structs;
   if ((need / sz) != n_structs) return NULL;
   return g_malloc(need);
}

gpointer g_new0_(size_t sz, size_t n_structs)
{
   size_t need = sz * n_structs;
   if ((need / sz) != n_structs) return NULL;
   return g_malloc0(need);
}

gpointer g_renew_(size_t sz, gpointer mem, size_t n_structs)
{
   size_t need = sz * n_structs;
   if ((need / sz) != n_structs) return NULL;
   return g_realloc(mem, need);
}

char *g_strconcat (const char *string1, ...)
{
   va_list ap;
   char *res;
   size_t sz = strlen(string1);
   va_start(ap, string1);
   while (1) {
      char *arg = va_arg(ap, char*);
      if (arg == NULL) break;
      sz += strlen(arg);
   }
   va_end(ap);
   res = g_malloc(sz + 1);
   strcpy(res, string1);
   va_start(ap, string1);
   while (1) {
      char *arg = va_arg(ap, char*);
      if (arg == NULL) break;
      strcat(res, arg);
   }
   va_end(ap);
   return res;
}

char **g_strsplit(const char *string, const char *delimiter, int max_tokens)
{
   char **res;
   if (string == NULL || *string == 0) {
      res = (char**)g_malloc(sizeof(char*));
      *res = NULL;
   } else {
      uint32_t ntokens, i, max = (uint32_t) max_tokens;
      if (max == 0) max--;
      int dlen = strlen(delimiter);
      const char *p = string, *b;
      for (ntokens = 1; ntokens < max; ntokens++) {
         p = strstr(p, delimiter);
         if (p == NULL) break;
         p += dlen;
      }
      res = (char**)g_new_(sizeof(char*), ntokens + 1);
      p = string;
      for (b = p, i = 0; i < ntokens; b = p, i++) {
         int len;
         if (i == (ntokens - 1)) {
            /* last piece special handling */
            res[i] = strdup(b);
         } else {
            p = strstr(b, delimiter);
            len = p - b;
            res[i] = (char*)g_malloc(len + 1);
            memcpy(res[i], b, len);
            res[i][len] = 0;
            p += dlen;
         }
      }
      res[ntokens] = NULL;      
   }
   return res;
}

#ifdef _WIN32

#include <windows.h>

char *g_win32_error_message(int error)
{
   char *msg;
   char *winMsg = NULL;
   if (error == 0) {
      return (char*)g_malloc0(1);
   }
   
   FormatMessage(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
                 NULL, error, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), (LPSTR)&msg, 0, NULL);

   /* give the caller something they can just free */   
   msg = strdup(winMsg);
   /* Free the allocated message. */
   HeapFree(GetProcessHeap(), 0, winMsg);
   
   return msg;   
}

#endif
