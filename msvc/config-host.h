/* Hand-maintained equivalent of the config-host.h that qemu/configure generates.
   MSVC builds do not run configure, so the host architecture is selected here from
   the compiler's predefined macros (x86 / x64 / ARM64). */
#if defined(_M_ARM64)
#define HOST_AARCH64 1
#else
#define HOST_I386 1
#endif
#define CONFIG_WIN32 1
#define CONFIG_TCG 1
#if !defined(_M_ARM64)
/* <cpuid.h> / __cpuid() only exist on x86 hosts. */
#define CONFIG_CPUID_H 1
#endif
// #define CONFIG_INT128 1
#define CONFIG_CMPXCHG128 1
// #define CONFIG_ATOMIC64 1
#define CONFIG_PLUGIN 1
