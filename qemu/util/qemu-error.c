/*
 * Error reporting
 *
 * Copyright (C) 2010 Red Hat Inc.
 *
 * Authors:
 *  Markus Armbruster <armbru@redhat.com>,
 *
 * This work is licensed under the terms of the GNU GPL, version 2 or later.
 * See the COPYING file in the top-level directory.
 */

#include <stdio.h>
#include <stdarg.h>
#include <string.h>

static const char *progname;

/*
 * Set the program name for error_print_loc().
 */
void error_set_progname(const char *argv0)
{
    const char *p = strrchr(argv0, '/');
    progname = p ? p + 1 : argv0;
}

const char *error_get_progname(void)
{
    return progname;
}

/*
 * Print current location to current monitor if we have one, else to stderr.
 */
static void error_print_loc(void)
{
}

/*
 * Print an error message to current monitor if we have one, else to stderr.
 * Format arguments like vsprintf().  The result should not contain
 * newlines.
 * Prepend the current location and append a newline.
 * It's wrong to call this in a QMP monitor.  Use qerror_report() there.
 */
#ifdef _WIN32
void error_vreport(const char *fmt, va_list ap)
{
    error_print_loc();
    vfprintf(stderr, fmt, ap);
    fprintf(stderr, "\n");
}
#else
void error_vreport(const char *fmt, va_list ap)
{
    GTimeVal tv;
    gchar *timestr;

    error_print_loc();
    error_vprintf(fmt, ap);
    error_printf("\n");
}
#endif

/*
 * Print an error message to current monitor if we have one, else to stderr.
 * Format arguments like sprintf().  The result should not contain
 * newlines.
 * Prepend the current location and append a newline.
 * It's wrong to call this in a QMP monitor.  Use qerror_report() there.
 */
void error_report(const char *fmt, ...)
{
    va_list ap;

    va_start(ap, fmt);
    error_vreport(fmt, ap);
    va_end(ap);
}
