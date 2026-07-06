/*
 * Regression guard for the __int128_t redefinition in
 * qemu/include/qemu/int128.h (the "#else / !CONFIG_INT128" fallback).
 *
 * In that fallback QEMU aliases the reserved builtin name __int128_t to its
 * struct Int128 so fallback code can name the type. That is only valid on
 * compilers that do NOT provide __int128_t as a builtin; on GCC/Clang (where
 * __SIZEOF_INT128__ is defined) emitting the alias is a "typedef redefinition
 * with different types" error. It bit real Clang builds (e.g. Apple clang on
 * arm64, and the Rust unicorn-engine-sys crate) whenever the build reached the
 * fallback. int128.h now gates the alias on !defined(__SIZEOF_INT128__), which
 * subsumes the earlier clang-cl-only guard from PR #2251.
 *
 * This test reproduces the exact construct so CI compilers that DO have the
 * __int128_t builtin (every Linux/macOS runner) keep compiling it. Compiled
 * with -Werror, the pre-fix clang-cl-only guard fails here on such compilers.
 * Keep the guard below in sync with int128.h's fallback typedef.
 */

#include <stdint.h>

typedef struct Int128 Int128;
#if !defined(__SIZEOF_INT128__)
/* Only aliased when the compiler lacks the __int128_t builtin (e.g. MSVC). */
typedef Int128 __int128_t;
#endif

struct Int128 {
    uint64_t lo;
    int64_t hi;
};

int main(void)
{
    /*
     * On a compiler with the builtin, __int128_t still names the 128-bit type
     * (the struct alias above was correctly skipped). Exercise both so the file
     * fails to compile if the guard ever redefines the builtin again.
     */
    Int128 fallback = { 1, 2 };
    __int128_t native = ((__int128_t)fallback.hi << 64) | fallback.lo;
    return native == (((__int128_t)2 << 64) | 1) ? 0 : 1;
}
