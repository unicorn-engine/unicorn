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

/* To verbose logging, enable the next line. */
//#define UNICORN_LOGGING // to enable logging

#ifdef UNICORN_LOGGING

#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdbool.h>

/**
 * Reads the @p env_name and tries to parse the value into an uint32_t.
 * @param env_name The environment variable name to parse.
 * @return The parsed value.
 ** 0 in case if the value can not be parsed (or is 0).
 ** ULONG_MAX if the value is bigger than an uint32_t.
 */
static inline uint32_t read_and_parse_env(const char* env_name)
{
    uint32_t data = 0;
    const char* env_data = getenv(env_name);

    if (env_data != NULL) {
        char buffer[11] = {0}; // 0xFFFF'FFFF\0
        strncpy(buffer, env_data, sizeof(buffer) - 1);
        data = (uint32_t)strtoul(buffer, NULL, 0);
    }

    return data;
}

/**
 * Gets the log level by reading it once.
 * @return The log level.
 */
static inline uint32_t get_log_level()
{
    static uint64_t log_level = UINT64_MAX;

    if (log_level == UINT64_MAX) {
        log_level = read_and_parse_env("UNICORN_LOG_LEVEL");
    }

    return (uint32_t)log_level;
}

/**
 * Gets the log detail level by reading it once.
 * @return The detail log level.
 */
static inline uint32_t get_log_detail_level()
{
    static uint64_t log_detail_level = UINT64_MAX;

    if (log_detail_level == UINT64_MAX) {
        log_detail_level = read_and_parse_env("UNICORN_LOG_DETAIL_LEVEL");
    }

    return (uint32_t)log_detail_level;
}

/**
 * Checks if the @p log_level is active.
 * @param log_level The log level to be checked.
 * @return True if the log level is active.
 */
static inline bool is_log_level_active(uint32_t log_level)
{
    const uint32_t active_log_level = get_log_level();
    const bool is_active = (active_log_level & log_level) == log_level;

    return is_active;
}

/**
 * Checks if the logging is enabled.
 * @return True if enabled, else false.
 */
static inline bool is_logging_enabled()
{
    const bool log_level = get_log_level();

    return log_level != 0;
}

/**
 * Gets the filename of the caller on given @p detail_level.
 * @param filename The filename to process on.
 * @param detail_level The level of detail of the filename.
 ** 0: Returns an empty string.
 ** 1: Returns the full filename including it's path.
 ** 2: Returns just the filename (to shorten the log).
 * @return always an valid null-terminated string. Do NOT free it.
 */
static inline const char* const get_detailed_filename(const char* filename,
    int detail_level)
{
    filename = (filename != NULL) ? filename : "";
    const char* resulting_filename = filename;

#if (defined(WIN32) || defined(WIN64) || defined(_WIN32) || defined(_WIN64))
    const char path_separator = '\\';
#else
    const char path_separator = '/';
#endif

    switch (detail_level) {
        default:
        case 0:
            resulting_filename = "";
            break;
        case 1:
            resulting_filename = filename;
            break;
        case 2:
            resulting_filename = strrchr(filename, path_separator);

            if (resulting_filename == NULL) {
                resulting_filename = filename;
            }
            else {
                ++resulting_filename;
            }

            break;
    }

    return resulting_filename;
}

/**
 * Prints the formatted log message with details if enabled.
 * @param mask The log mask to log on.
 * @param filename The filename of the caller.
 * @param line The line number of the caller.
 * @param fmt Printf-style format string.
 * @param args optional arguments for the format string.
 */
static inline void print_log(uint32_t mask, const char* filename, uint32_t line, const char* fmt, ...)
{
    if ((mask & get_log_level()) == 0) {
        return;
    }

    const uint32_t log_detail_level = get_log_detail_level();

    if (log_detail_level > 0) {
        const char* detailed_filename = get_detailed_filename(filename, log_detail_level);
        printf("[%s:%u] ", detailed_filename, line);
    }

    va_list argptr;

    va_start(argptr, fmt);
    vfprintf(stdout, fmt, argptr);
    va_end(argptr);
}

/**
 * Logs only if the right log level is set.
 * @param mask The log mask to log on.
 * @param fmt Printf-style format string.
 * @param args optional arguments for the format string.
 */
#define LOG_MESSAGE(mask, fmt, ...) \
    do { \
        print_log(mask, __FILE__, __LINE__, fmt, ## __VA_ARGS__); \
    } while (0)
#else
#define LOG_MESSAGE(mask, fmt, ...)

/**
 * Dummy implementation which returns always false.
 * @return Always false.
 */
static inline bool is_logging_enabled()
{
    return false;
}

/**
 * Dummy implementation which returns always false.
 * @param level The log level to be checked.
 * @return Always false.
 */
static inline bool is_log_level_active(uint32_t level)
{
    (void)level;

    return false;
}
#endif /* UNICORN_LOGGING */

/**
 * Logs only if the right log level is set.
 * @param mask The log mask to log on.
 * @param fmt Printf-style format string.
 * @param args Optional arguments for the format string.
 */
#define qemu_log_mask(mask, fmt, ...) \
    LOG_MESSAGE(mask, fmt, ## __VA_ARGS__)

#endif /* QEMU_LOG_H */
