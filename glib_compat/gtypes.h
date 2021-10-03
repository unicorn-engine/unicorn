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

#ifndef __G_TYPES_H__
#define __G_TYPES_H__

#include <stddef.h>
#include <stdint.h>
#include <float.h>

#ifndef TRUE
#define TRUE 1
#endif

#ifndef FALSE
#define FALSE 0
#endif

#define MAX(a, b)  (((a) > (b)) ? (a) : (b))

/* typedefs for glib related types that may still be referenced */
typedef void* gpointer;

typedef const void *gconstpointer;

typedef int gint;
typedef uint8_t guint8;
typedef int8_t gint8;
typedef uint16_t guint16;
typedef int16_t gint16;
typedef uint32_t guint32;
typedef int32_t gint32;
typedef uint64_t guint64;
typedef int64_t gint64;
typedef unsigned int guint;
typedef char gchar;
typedef int gboolean;
typedef unsigned long gulong;
typedef unsigned long gsize;

typedef gint            grefcount;

typedef volatile gint   gatomicrefcount;

typedef void            (*GDestroyNotify) (gpointer data);

typedef gint            (*GCompareFunc) (gconstpointer a, gconstpointer b);

typedef gint            (*GCompareDataFunc) (gconstpointer a, gconstpointer b, gpointer user_data);

typedef guint           (*GHashFunc) (gconstpointer key);

typedef gboolean        (*GEqualFunc) (gconstpointer a, gconstpointer b);

typedef void            (*GHFunc) (gpointer key, gpointer value, gpointer user_data);

typedef gpointer	(*GCopyFunc) (gconstpointer src, gpointer data);

#endif /* __G_TYPES_H__ */
