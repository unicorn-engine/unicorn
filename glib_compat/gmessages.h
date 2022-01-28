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

#ifndef __G_MESSAGES_H__
#define __G_MESSAGES_H__

#include "gmacros.h"

#define g_return_val_if_fail(expr,val) G_STMT_START{ (void)0; }G_STMT_END
#define g_return_if_fail(expr) G_STMT_START{ (void)0; }G_STMT_END
#define g_return_if_reached() G_STMT_START{ return; }G_STMT_END
#define g_return_val_if_reached(val) G_STMT_START{ return (val); }G_STMT_END

#endif /* __G_MESSAGES_H__ */
