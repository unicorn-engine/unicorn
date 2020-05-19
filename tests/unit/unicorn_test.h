#ifndef UNICORN_TEST_H
#define UNICORN_TEST_H

#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>
#include <unicorn/unicorn.h>
#include <sys/stat.h>

/**
 * Assert that err matches expect
 */
#define uc_assert_err(expect, err)                                  \
do {                                                                \
    uc_err __err = err;                                             \
    if (__err != expect) {                                          \
        fail_msg("%s", uc_strerror(__err));                         \
    }                                                               \
} while (0)

/**
 * Assert that err is UC_ERR_OK
 */
#define uc_assert_success(err)  uc_assert_err(UC_ERR_OK, err)

/**
 * Assert that err is anything but UC_ERR_OK
 *
 * Note: Better to use uc_assert_err(<specific error>, err),
 * as this serves to document which errors a function will return
 * in various scenarios.
 */
#define uc_assert_fail(err)                                         \
do {                                                                \
    uc_err __err = err;                                             \
    if (__err == UC_ERR_OK) {                                       \
        fail_msg("%s", uc_strerror(__err));                         \
    }                                                               \
} while (0)

char * read_file(const char *filename, struct stat *info) {
    stat(filename, info);
    char *code = malloc(info->st_size);
    if (code == NULL) {
        return NULL;
    }
    FILE *fp = fopen(filename, "r");
    if (fp == NULL) {
        free(code);
        return NULL;
    }
    fread(code, info->st_size, 1, fp);
    return code;
}

#endif /* UNICORN_TEST_H */
