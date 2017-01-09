/*
 * Commandline option parsing functions
 *
 * Copyright (c) 2003-2008 Fabrice Bellard
 * Copyright (c) 2009 Kevin Wolf <kwolf@redhat.com>
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
 * THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */

#include <stdio.h>
#include <string.h>

#include "qemu-common.h"
#include "qapi/qmp/qerror.h"
#include "qemu/option.h"

void parse_option_size(const char *name, const char *value,
                       uint64_t *ret, Error **errp)
{
    char *postfix;
    double sizef;

    if (value != NULL) {
        sizef = strtod(value, &postfix);
        switch (*postfix) {
        case 'T':
            sizef *= 1024;
            /* fall through */
        case 'G':
            sizef *= 1024;
            /* fall through */
        case 'M':
            sizef *= 1024;
            /* fall through */
        case 'K':
        case 'k':
            sizef *= 1024;
            /* fall through */
        case 'b':
        case '\0':
            *ret = (uint64_t) sizef;
            break;
        default:
            error_set(errp, QERR_INVALID_PARAMETER_VALUE, name, "a size");
#if 0 /* conversion from qerror_report() to error_set() broke this: */
            error_printf_unless_qmp("You may use k, M, G or T suffixes for "
                    "kilobytes, megabytes, gigabytes and terabytes.\n");
#endif
            return;
        }
    } else {
        error_set(errp, QERR_INVALID_PARAMETER_VALUE, name, "a size");
    }
}
