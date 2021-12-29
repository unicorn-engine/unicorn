/*
 * This file is supposed to be included only by .c files. No header file should
 * depend on qemu-common.h, as this would easily lead to circular header
 * dependencies.
 *
 * If a header file uses a definition from qemu-common.h, that definition
 * must be moved to a separate header file, and the header that uses it
 * must include that header.
 */
#ifndef QEMU_COMMON_H
#define QEMU_COMMON_H

#include <unicorn/platform.h>
#include <qemu/typedefs.h>

#define TFR(expr) do { if ((expr) != -1) break; } while (errno == EINTR)

/* Copyright string for -version arguments, About dialogs, etc */
#define QEMU_COPYRIGHT "Copyright (c) 2003-2020 " \
    "Fabrice Bellard and the QEMU Project developers"

/* Bug reporting information for --help arguments, About dialogs, etc */
#define QEMU_HELP_BOTTOM \
    "See <https://qemu.org/contribute/report-a-bug> for how to report bugs.\n" \
    "More information on the QEMU project at <https://qemu.org>."

/* main function, renamed */
#if defined(CONFIG_COCOA)
int qemu_main(int argc, char **argv, char **envp);
#endif

void qemu_get_timedate(struct tm *tm, int offset);
int qemu_timedate_diff(struct tm *tm);

void *qemu_oom_check(void *ptr);

#ifdef _WIN32
/* MinGW needs type casts for the 'buf' and 'optval' arguments. */
#define qemu_getsockopt(sockfd, level, optname, optval, optlen) \
    getsockopt(sockfd, level, optname, (void *)optval, optlen)
#define qemu_setsockopt(sockfd, level, optname, optval, optlen) \
    setsockopt(sockfd, level, optname, (const void *)optval, optlen)
#define qemu_recv(sockfd, buf, len, flags) recv(sockfd, (void *)buf, len, flags)
#define qemu_sendto(sockfd, buf, len, flags, destaddr, addrlen) \
    sendto(sockfd, (const void *)buf, len, flags, destaddr, addrlen)
#else
#define qemu_getsockopt(sockfd, level, optname, optval, optlen) \
    getsockopt(sockfd, level, optname, optval, optlen)
#define qemu_setsockopt(sockfd, level, optname, optval, optlen) \
    setsockopt(sockfd, level, optname, optval, optlen)
#define qemu_recv(sockfd, buf, len, flags) recv(sockfd, buf, len, flags)
#define qemu_sendto(sockfd, buf, len, flags, destaddr, addrlen) \
    sendto(sockfd, buf, len, flags, destaddr, addrlen)
#endif

struct uc_struct;
void cpu_exec_init_all(struct uc_struct *uc);

/**
 * set_preferred_target_page_bits:
 * @bits: number of bits needed to represent an address within the page
 *
 * Set the preferred target page size (the actual target page
 * size may be smaller than any given CPU's preference).
 * Returns true on success, false on failure (which can only happen
 * if this is called after the system has already finalized its
 * choice of page size and the requested page size is smaller than that).
 */
bool set_preferred_target_page_bits(struct uc_struct *uc, int bits);

/**
 * finalize_target_page_bits:
 * Commit the final value set by set_preferred_target_page_bits.
 */
void finalize_target_page_bits(struct uc_struct *uc);

/* OS specific functions */
void os_setup_early_signal_handling(void);

void page_size_init(struct uc_struct *uc);

CPUState *qemu_get_cpu(struct uc_struct *uc, int index);

#endif
