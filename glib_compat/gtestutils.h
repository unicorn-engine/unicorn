/* GLib testing utilities
 * Copyright (C) 2007 Imendio AB
 * Authors: Tim Janik
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

#ifndef __G_TEST_UTILS_H__
#define __G_TEST_UTILS_H__


#if !(defined (G_STMT_START) && defined (G_STMT_END))
#define G_STMT_START  do
#if defined (_MSC_VER) && (_MSC_VER >= 1500)
#define G_STMT_END \
    __pragma(warning(push)) \
    __pragma(warning(disable:4127)) \
    while(0) \
    __pragma(warning(pop))
#else
#define G_STMT_END    while (0)
#endif
#endif

#if     __GNUC__ > 2 || (__GNUC__ == 2 && __GNUC_MINOR__ > 4)
#define G_GNUC_NORETURN                         \
  __attribute__((__noreturn__))
#else   /* !__GNUC__ */
/* NOTE: MSVC has __declspec(noreturn) but unlike GCC __attribute__,
 * __declspec can only be placed at the start of the function prototype
 * and not at the end, so we can't use it without breaking API.
 */
#define G_GNUC_NORETURN
#endif  /* !__GNUC__ */

void    g_assertion_message_expr        (const char     *file,
                                         int             line,
                                         const char     *expr) G_GNUC_NORETURN;

#define g_assert_not_reached()          G_STMT_START { g_assertion_message_expr (__FILE__, __LINE__, NULL); } G_STMT_END
#define g_assert(expr)                  G_STMT_START { \
                                             if (expr) ; else \
                                               g_assertion_message_expr (__FILE__, __LINE__, #expr); \
                                        } G_STMT_END

#endif /* __G_TEST_UTILS_H__ */
