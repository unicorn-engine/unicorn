
/* Common header file that is included by all of QEMU.
 *
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

#include "qemu/osdep.h"
#include "qemu/typedefs.h"
#include "qemu/fprintf-fn.h"
#include "exec/cpu-common.h"

#define TFR(expr) do { if ((expr) != -1) break; } while (errno == EINTR)

#include "unicorn/platform.h"

#define qemu_isalnum(c)		isalnum((unsigned char)(c))
#define qemu_isalpha(c)		isalpha((unsigned char)(c))
#define qemu_iscntrl(c)		iscntrl((unsigned char)(c))
#define qemu_isdigit(c)		isdigit((unsigned char)(c))
#define qemu_isgraph(c)		isgraph((unsigned char)(c))
#define qemu_islower(c)		islower((unsigned char)(c))
#define qemu_isprint(c)		isprint((unsigned char)(c))
#define qemu_ispunct(c)		ispunct((unsigned char)(c))
#define qemu_isspace(c)		isspace((unsigned char)(c))
#define qemu_isupper(c)		isupper((unsigned char)(c))
#define qemu_isxdigit(c)	isxdigit((unsigned char)(c))
#define qemu_tolower(c)		tolower((unsigned char)(c))
#define qemu_toupper(c)		toupper((unsigned char)(c))
#define qemu_isascii(c)		isascii((unsigned char)(c))
#define qemu_toascii(c)		toascii((unsigned char)(c))

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

/* Error handling.  */

void tcg_exec_init(struct uc_struct *uc, unsigned long tb_size);
bool tcg_enabled(struct uc_struct *uc);

struct uc_struct;
void cpu_exec_init_all(struct uc_struct *uc);

#include "qemu/module.h"

// support for calling functions before main code is executed.
#if defined(_MSC_VER)
    #pragma section(".CRT$XCU",read)
    #define INITIALIZER2_(f,p) \
        static void f(void); \
        __declspec(allocate(".CRT$XCU")) void (*f##_)(void) = f; \
        __pragma(comment(linker,"/include:" p #f "_")) \
        static void f(void)
    #ifdef _WIN64
        #define INITIALIZER(f) INITIALIZER2_(f,"")
    #else
        #define INITIALIZER(f) INITIALIZER2_(f,"_")
    #endif
#else
    #define INITIALIZER(f) \
        static void f(void) __attribute__((constructor)); \
        static void f(void)
#endif

#endif
