/*
 * Logging support
 *
 *  Copyright (c) 2003 Fabrice Bellard
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, see <http://www.gnu.org/licenses/>.
 */

#include "qemu/osdep.h"
#include "qemu-common.h"
#include "qemu/log.h"

FILE *qemu_logfile;
int qemu_loglevel;

/* Return the number of characters emitted.  */
int qemu_log(const char *fmt, ...)
{
    int ret = 0;
    if (qemu_logfile) {
        va_list ap;
        va_start(ap, fmt);
        ret = vfprintf(qemu_logfile, fmt, ap);
        va_end(ap);

        /* Don't pass back error results.  */
        if (ret < 0) {
            ret = 0;
        }
    }
    return ret;
}

/* fflush() the log file */
void qemu_log_flush(void)
{
    fflush(qemu_logfile);
}

/* Close the log file */
void qemu_log_close(void)
{
    if (qemu_logfile) {
        if (qemu_logfile != stderr) {
            fclose(qemu_logfile);
        }
        qemu_logfile = NULL;
    }
}

/* Returns true if addr is in our debug filter or no filter defined
 */
bool qemu_log_in_addr_range(uint64_t addr)
{
    // Unicorn: stubbed
    return true;
}


void qemu_set_dfilter_ranges(const char *filter_spec)
{
    // Unicorn: stubbed
}
