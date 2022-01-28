#ifndef QEMU_LOG_H
#define QEMU_LOG_H

#define CPU_LOG_TB_OUT_ASM (1 << 0)
#define CPU_LOG_TB_IN_ASM  (1 << 1)
#define CPU_LOG_TB_OP      (1 << 2)
#define CPU_LOG_TB_OP_OPT  (1 << 3)
#define CPU_LOG_INT        (1 << 4)
#define CPU_LOG_EXEC       (1 << 5)
#define CPU_LOG_PCALL      (1 << 6)
#define CPU_LOG_TB_CPU     (1 << 8)
#define CPU_LOG_RESET      (1 << 9)
#define LOG_UNIMP          (1 << 10)
#define LOG_GUEST_ERROR    (1 << 11)
#define CPU_LOG_MMU        (1 << 12)
#define CPU_LOG_TB_NOCHAIN (1 << 13)
#define CPU_LOG_PAGE       (1 << 14)
/* LOG_TRACE (1 << 15) is defined in log-for-trace.h */
#define CPU_LOG_TB_OP_IND  (1 << 16)
#define CPU_LOG_TB_FPU     (1 << 17)
#define CPU_LOG_PLUGIN     (1 << 18)
/* LOG_STRACE is used for user-mode strace logging. */
#define LOG_STRACE         (1 << 19)

/* Lock output for a series of related logs.  Since this is not needed
 * for a single qemu_log / qemu_log_mask / qemu_log_mask_and_addr, we
 * assume that qemu_loglevel_mask has already been tested, and that
 * qemu_loglevel is never set when qemu_logfile is unset.
 */

/* Logging functions: */

/* log only if a bit is set on the current loglevel mask:
 * @mask: bit to check in the mask
 * @fmt: printf-style format string
 * @args: optional arguments for format string
 */
#define qemu_log_mask(MASK, FMT, ...)

/* log only if a bit is set on the current loglevel mask
 * and we are in the address range we care about:
 * @mask: bit to check in the mask
 * @addr: address to check in dfilter
 * @fmt: printf-style format string
 * @args: optional arguments for format string
 */
#define qemu_log_mask_and_addr(MASK, ADDR, FMT, ...)

#endif
