/* GLib testing utilities
 * Copyright (C) 2007 Imendio AB
 * Authors: Tim Janik, Sven Herzberg
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

#include "gtestutils.h"
#include <stdlib.h>
#include <stdio.h>

void
g_assertion_message_expr (const char     *file,
                          int             line,
                          const char     *expr)
{
  if (!expr)
    printf("%s:%d code should not be reached", file, line);
  else
    printf("%s:%d assertion failed: %s", file, line, expr);

  abort();
}
