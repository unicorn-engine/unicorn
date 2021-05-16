# Tested on window10(x64) with vs2019.
# Open the "x86 Native Tools Command Prompt for VS 2019",
#   cd ${UNICORN_SOURCE_DIR}
#   mkdir build
#   cd build
#   cmake -G "NMake Makefiles" ..
#   nmake
# Or Open "x64 Native Tools Command Prompt for VS 2019" for 64bit binary.
# Tested on Ubuntu-1804-amd64 with gcc.
#   $ cd ${UNICORN_SOURCE_DIR}
#   $ mkdir build
#   $ cd build
#   $ cmake ..
#   $ make
# By Huitao Chen, 2019

cmake_minimum_required(VERSION 3.1)
project(unicorn C)

set(UNICORN_VERSION_MAJOR 1)
set(UNICORN_VERSION_MINOR 0)
set(UNICORN_VERSION_PATCH 3)

option(BUILD_SHARED_LIBS "Build shared instead of static library" ON)
option(UNICORN_INSTALL "Install unicorn" ON)
option(UNICORN_BUILD_SAMPLES "Build samples" ON)
set(UNICORN_ARCH "x86 arm aarch64 m68k mips sparc" CACHE STRING "Supported architectures")

# Deprecated option (CMake has this feature built-in)
if(UNICORN_BUILD_SHARED)
    set(BUILD_SHARED_LIBS ON CACHE BOOL "" FORCE)
endif()

string(TOUPPER ${UNICORN_ARCH} UNICORN_ARCH)
string(REPLACE " " ";" UNICORN_ARCH_LIST ${UNICORN_ARCH})

foreach(ARCH_LOOP ${UNICORN_ARCH_LIST})
    set(UNICORN_HAS_${ARCH_LOOP} TRUE)
endforeach(ARCH_LOOP)

# qemu uses assert(). It is not recommended to define NDEBUG if using assert()
#  to detect error conditions since the software may behave
#  non-deterministically. Remove the NDEBUG macro.
if(CMAKE_BUILD_TYPE STREQUAL "Release")
    string(REPLACE "-DNDEBUG" "" CMAKE_C_FLAGS_RELEASE ${CMAKE_C_FLAGS_RELEASE})
endif()

if(MSVC)
    include_directories(
        ${CMAKE_CURRENT_SOURCE_DIR}/msvc/unicorn
    )
else()
    include_directories(
        ${CMAKE_BINARY_DIR}
    )
endif()

include_directories(
    qemu
    qemu/include
    qemu/tcg
    include
)

if(MSVC)
    if(CMAKE_SIZEOF_VOID_P EQUAL 8)
        set(MSVC_FLAG -D__x86_64__)
    elseif(CMAKE_SIZEOF_VOID_P EQUAL 4)
        set(MSVC_FLAG -D__i386__)
    else()
        message(FATAL_ERROR "Neither WIN64 or WIN32!")
    endif()
    add_compile_options(
        -Dinline=__inline
        -D__func__=__FUNCTION__
        -D_CRT_SECURE_NO_WARNINGS
        -DWIN32_LEAN_AND_MEAN
        ${MSVC_FLAG}
        /I${CMAKE_CURRENT_SOURCE_DIR}/qemu/tcg/i386
        /wd4018 /wd4244 /wd4267
    )
    if(CMAKE_BUILD_TYPE STREQUAL "Debug")
        string(REPLACE "/ZI" "/Zi" CMAKE_C_FLAGS_DEBUG ${CMAKE_C_FLAGS_DEBUG})
    endif()
    # default use the multithread, static version of the run-time library.
    option(UNICORN_STATIC_MSVCRT "Embed static runtime library" ON)
    if (UNICORN_STATIC_MSVCRT)
        string(REPLACE "/MD" "/MT" CMAKE_C_FLAGS_DEBUG ${CMAKE_C_FLAGS_DEBUG})
        string(REPLACE "/MD" "/MT" CMAKE_C_FLAGS_RELEASE ${CMAKE_C_FLAGS_RELEASE})
    endif()
else()
    # detect host arch.
    execute_process(COMMAND ${CMAKE_C_COMPILER} -dM -E -
        INPUT_FILE /dev/null
        OUTPUT_VARIABLE UC_COMPILER_MACRO)

    while(TRUE)
        string(FIND ${UC_COMPILER_MACRO} "__x86_64__" UC_RET)
        if (${UC_RET} GREATER "0")
            set(UNICORN_TARGET_ARCH "i386")
            break()
        endif()
        string(FIND ${UC_COMPILER_MACRO} "__i386__" UC_RET)
        if (${UC_RET} GREATER "0")
            set(UNICORN_TARGET_ARCH "i386")
            break()
        endif()
        string(FIND ${UC_COMPILER_MACRO} "__arm__" UC_RET)
        if (${UC_RET} GREATER "0")
            set(UNICORN_TARGET_ARCH "arm")
            break()
        endif()
        string(FIND ${UC_COMPILER_MACRO} "__aarch64__" UC_RET)
        if (${UC_RET} GREATER "0")
            set(UNICORN_TARGET_ARCH "aarch64")
            break()
        endif()
        string(FIND ${UC_COMPILER_MACRO} "__mips__" UC_RET)
        if (${UC_RET} GREATER "0")
            set(UNICORN_TARGET_ARCH "mips")
            break()
        endif()
        string(FIND ${UC_COMPILER_MACRO} "__sparc__" UC_RET)
        if (${UC_RET} GREATER "0")
            set(UNICORN_TARGET_ARCH "sparc")
            break()
        endif()
        string(FIND ${UC_COMPILER_MACRO} "__ia64__" UC_RET)
        if (${UC_RET} GREATER "0")
            set(UNICORN_TARGET_ARCH "ia64")
            break()
        endif()
        string(FIND ${UC_COMPILER_MACRO} "_ARCH_PPC" UC_RET)
        if (${UC_RET} GREATER "0")
            set(UNICORN_TARGET_ARCH "ppc")
            break()
        endif()
        string(FIND ${UC_COMPILER_MACRO} "__s390__" UC_RET)
        if (${UC_RET} GREATER "0")
            set(UNICORN_TARGET_ARCH "s390")
            break()
        endif()
        message(FATAL_ERROR "Unknown host compiler: ${CMAKE_C_COMPILER}.")
    endwhile(TRUE)

    set(EXTRA_CFLAGS "--extra-cflags=")
    if (UNICORN_HAS_X86)
        set (EXTRA_CFLAGS "${EXTRA_CFLAGS}-DUNICORN_HAS_X86 ")
    endif()
    if (UNICORN_HAS_ARM)
        set (EXTRA_CFLAGS "${EXTRA_CFLAGS}-DUNICORN_HAS_ARM -DUNICORN_HAS_ARMEB ")
    endif()
    if (UNICORN_HAS_AARCH64)
        set (EXTRA_CFLAGS "${EXTRA_CFLAGS}-DUNICORN_HAS_ARM64 -DUNICORN_HAS_ARM64EB ")
    endif()
    if (UNICORN_HAS_M68K)
        set (EXTRA_CFLAGS "${EXTRA_CFLAGS}-DUNICORN_HAS_M68K ")
    endif()
    if (UNICORN_HAS_MIPS)
        set (EXTRA_CFLAGS "${EXTRA_CFLAGS}-DUNICORN_HAS_MIPS -DUNICORN_HAS_MIPSEL -DUNICORN_HAS_MIPS64 -DUNICORN_HAS_MIPS64EL ")
    endif()
    if (UNICORN_HAS_SPARC)
        set (EXTRA_CFLAGS "${EXTRA_CFLAGS}-DUNICORN_HAS_SPARC ")
    endif()
    set (EXTRA_CFLAGS "${EXTRA_CFLAGS}-fPIC -fvisibility=hidden")

    set(TARGET_LIST "--target-list=")
    if (UNICORN_HAS_X86)
        set (TARGET_LIST "${TARGET_LIST}x86_64-softmmu, ")
    endif()
    if (UNICORN_HAS_ARM)
        set (TARGET_LIST "${TARGET_LIST}arm-softmmu, armeb-softmmu, ")
    endif()
    if (UNICORN_HAS_AARCH64)
        set (TARGET_LIST "${TARGET_LIST}aarch64-softmmu, aarch64eb-softmmu, ")
    endif()
    if (UNICORN_HAS_M68K)
        set (TARGET_LIST "${TARGET_LIST}m68k-softmmu, ")
    endif()
    if (UNICORN_HAS_MIPS)
        set (TARGET_LIST "${TARGET_LIST}mips-softmmu, mipsel-softmmu, mips64-softmmu, mips64el-softmmu, ")
    endif()
    if (UNICORN_HAS_SPARC)
        set (TARGET_LIST "${TARGET_LIST}sparc-softmmu, sparc64-softmmu, ")
    endif()
    set (TARGET_LIST "${TARGET_LIST} ")

    # GEN config-host.mak & target directories
    execute_process(COMMAND sh ${CMAKE_CURRENT_SOURCE_DIR}/qemu/configure
        ${EXTRA_CFLAGS}
        ${TARGET_LIST}
        WORKING_DIRECTORY ${CMAKE_BINARY_DIR}
    )
    execute_process(COMMAND sh ${CMAKE_CURRENT_SOURCE_DIR}/qemu/scripts/create_config
        INPUT_FILE ${CMAKE_BINARY_DIR}/config-host.mak
        OUTPUT_FILE ${CMAKE_BINARY_DIR}/config-host.h
    )
    if (UNICORN_HAS_X86)
        execute_process(COMMAND sh ${CMAKE_CURRENT_SOURCE_DIR}/qemu/scripts/create_config
            INPUT_FILE ${CMAKE_BINARY_DIR}/x86_64-softmmu/config-target.mak
            OUTPUT_FILE ${CMAKE_BINARY_DIR}/x86_64-softmmu/config-target.h
        )
    endif()
    if (UNICORN_HAS_ARM)
        execute_process(COMMAND sh ${CMAKE_CURRENT_SOURCE_DIR}/qemu/scripts/create_config
            INPUT_FILE ${CMAKE_BINARY_DIR}/arm-softmmu/config-target.mak
            OUTPUT_FILE ${CMAKE_BINARY_DIR}/arm-softmmu/config-target.h
        )
        execute_process(COMMAND sh ${CMAKE_CURRENT_SOURCE_DIR}/qemu/scripts/create_config
            INPUT_FILE ${CMAKE_BINARY_DIR}/armeb-softmmu/config-target.mak
            OUTPUT_FILE ${CMAKE_BINARY_DIR}/armeb-softmmu/config-target.h
        )
    endif()
    if (UNICORN_HAS_AARCH64)
        execute_process(COMMAND sh ${CMAKE_CURRENT_SOURCE_DIR}/qemu/scripts/create_config
            INPUT_FILE ${CMAKE_BINARY_DIR}/aarch64-softmmu/config-target.mak
            OUTPUT_FILE ${CMAKE_BINARY_DIR}/aarch64-softmmu/config-target.h
        )
        execute_process(COMMAND sh ${CMAKE_CURRENT_SOURCE_DIR}/qemu/scripts/create_config
            INPUT_FILE ${CMAKE_BINARY_DIR}/aarch64eb-softmmu/config-target.mak
            OUTPUT_FILE ${CMAKE_BINARY_DIR}/aarch64eb-softmmu/config-target.h
        )
    endif()
    if (UNICORN_HAS_M68K)
        execute_process(COMMAND sh ${CMAKE_CURRENT_SOURCE_DIR}/qemu/scripts/create_config
            INPUT_FILE ${CMAKE_BINARY_DIR}/m68k-softmmu/config-target.mak
            OUTPUT_FILE ${CMAKE_BINARY_DIR}/m68k-softmmu/config-target.h
        )
    endif()
    if (UNICORN_HAS_MIPS)
        execute_process(COMMAND sh ${CMAKE_CURRENT_SOURCE_DIR}/qemu/scripts/create_config
            INPUT_FILE ${CMAKE_BINARY_DIR}/mips-softmmu/config-target.mak
            OUTPUT_FILE ${CMAKE_BINARY_DIR}/mips-softmmu/config-target.h
        )
        execute_process(COMMAND sh ${CMAKE_CURRENT_SOURCE_DIR}/qemu/scripts/create_config
            INPUT_FILE ${CMAKE_BINARY_DIR}/mipsel-softmmu/config-target.mak
            OUTPUT_FILE ${CMAKE_BINARY_DIR}/mipsel-softmmu/config-target.h
        )
        execute_process(COMMAND sh ${CMAKE_CURRENT_SOURCE_DIR}/qemu/scripts/create_config
            INPUT_FILE ${CMAKE_BINARY_DIR}/mips64-softmmu/config-target.mak
            OUTPUT_FILE ${CMAKE_BINARY_DIR}/mips64-softmmu/config-target.h
        )
        execute_process(COMMAND sh ${CMAKE_CURRENT_SOURCE_DIR}/qemu/scripts/create_config
            INPUT_FILE ${CMAKE_BINARY_DIR}/mips64el-softmmu/config-target.mak
            OUTPUT_FILE ${CMAKE_BINARY_DIR}/mips64el-softmmu/config-target.h
        )
    endif()
    if (UNICORN_HAS_SPARC)
        execute_process(COMMAND sh ${CMAKE_CURRENT_SOURCE_DIR}/qemu/scripts/create_config
            INPUT_FILE ${CMAKE_BINARY_DIR}/sparc-softmmu/config-target.mak
            OUTPUT_FILE ${CMAKE_BINARY_DIR}/sparc-softmmu/config-target.h
        )
        execute_process(COMMAND sh ${CMAKE_CURRENT_SOURCE_DIR}/qemu/scripts/create_config
            INPUT_FILE ${CMAKE_BINARY_DIR}/sparc64-softmmu/config-target.mak
            OUTPUT_FILE ${CMAKE_BINARY_DIR}/sparc64-softmmu/config-target.h
        )
    endif()
    add_compile_options(
        -I${CMAKE_CURRENT_SOURCE_DIR}/qemu/tcg/${UNICORN_TARGET_ARCH}
        -D_GNU_SOURCE
        -D_FILE_OFFSET_BITS=64
        -D_LARGEFILE_SOURCE
        -Wall -O2
        -fPIC -fpic -fvisibility=hidden
    )
endif()

if (UNICORN_HAS_X86)
add_library(x86_64-softmmu OBJECT
    qemu/cpu-exec.c
    qemu/cpus.c
    qemu/cputlb.c
    qemu/exec.c
    qemu/fpu/softfloat.c
    qemu/hw/i386/pc.c
    qemu/hw/i386/pc_piix.c
    qemu/hw/intc/apic.c
    qemu/hw/intc/apic_common.c
    qemu/ioport.c
    qemu/memory.c
    qemu/memory_mapping.c
    qemu/target-i386/arch_memory_mapping.c
    qemu/target-i386/cc_helper.c
    qemu/target-i386/cpu.c
    qemu/target-i386/excp_helper.c
    qemu/target-i386/fpu_helper.c
    qemu/target-i386/helper.c
    qemu/target-i386/int_helper.c
    qemu/target-i386/mem_helper.c
    qemu/target-i386/misc_helper.c
    qemu/target-i386/seg_helper.c
    qemu/target-i386/smm_helper.c
    qemu/target-i386/svm_helper.c
    qemu/target-i386/translate.c
    qemu/target-i386/unicorn.c
    qemu/tcg/optimize.c
    qemu/tcg/tcg.c
    qemu/translate-all.c
)

if(MSVC)
    target_compile_options(x86_64-softmmu PRIVATE
        -DNEED_CPU_H
        /FIx86_64.h
        /I${CMAKE_CURRENT_SOURCE_DIR}/msvc/unicorn/x86_64-softmmu
        /I${CMAKE_CURRENT_SOURCE_DIR}/qemu/target-i386
    )
else()
    target_compile_options(x86_64-softmmu PRIVATE
        -DNEED_CPU_H
        -include x86_64.h
        -I${CMAKE_BINARY_DIR}/x86_64-softmmu
        -I${CMAKE_CURRENT_SOURCE_DIR}/qemu/target-i386
    )
endif()
endif()

if (UNICORN_HAS_ARM)
add_library(arm-softmmu OBJECT
    qemu/cpu-exec.c
    qemu/cpus.c
    qemu/cputlb.c
    qemu/exec.c
    qemu/fpu/softfloat.c
    qemu/hw/arm/tosa.c
    qemu/hw/arm/virt.c
    qemu/ioport.c
    qemu/memory.c
    qemu/memory_mapping.c
    qemu/target-arm/cpu.c
    qemu/target-arm/crypto_helper.c
    qemu/target-arm/helper.c
    qemu/target-arm/iwmmxt_helper.c
    qemu/target-arm/neon_helper.c
    qemu/target-arm/op_helper.c
    qemu/target-arm/psci.c
    qemu/target-arm/translate.c
    qemu/target-arm/unicorn_arm.c
    qemu/tcg/optimize.c
    qemu/tcg/tcg.c
    qemu/translate-all.c
)

if(MSVC)
    target_compile_options(arm-softmmu PRIVATE
        -DNEED_CPU_H
        /FIarm.h
        /I${CMAKE_CURRENT_SOURCE_DIR}/msvc/unicorn/arm-softmmu
        /I${CMAKE_CURRENT_SOURCE_DIR}/qemu/target-arm
    )
else()
    target_compile_options(arm-softmmu PRIVATE
        -DNEED_CPU_H
        -include arm.h
        -I${CMAKE_BINARY_DIR}/arm-softmmu
        -I${CMAKE_CURRENT_SOURCE_DIR}/qemu/target-arm
    )
endif()

add_library(armeb-softmmu OBJECT
    qemu/cpu-exec.c
    qemu/cpus.c
    qemu/cputlb.c
    qemu/exec.c
    qemu/fpu/softfloat.c
    qemu/hw/arm/tosa.c
    qemu/hw/arm/virt.c
    qemu/ioport.c
    qemu/memory.c
    qemu/memory_mapping.c
    qemu/target-arm/cpu.c
    qemu/target-arm/crypto_helper.c
    qemu/target-arm/helper.c
    qemu/target-arm/iwmmxt_helper.c
    qemu/target-arm/neon_helper.c
    qemu/target-arm/op_helper.c
    qemu/target-arm/psci.c
    qemu/target-arm/translate.c
    qemu/target-arm/unicorn_arm.c
    qemu/tcg/optimize.c
    qemu/tcg/tcg.c
    qemu/translate-all.c
)

if(MSVC)
    target_compile_options(armeb-softmmu PRIVATE
        -DNEED_CPU_H
        /FIarmeb.h
        /I${CMAKE_CURRENT_SOURCE_DIR}/msvc/unicorn/armeb-softmmu
        /I${CMAKE_CURRENT_SOURCE_DIR}/qemu/target-arm
    )
else()
    target_compile_options(armeb-softmmu PRIVATE
        -DNEED_CPU_H
        -include armeb.h
        -I${CMAKE_BINARY_DIR}/armeb-softmmu
        -I${CMAKE_CURRENT_SOURCE_DIR}/qemu/target-arm
    )
endif()
endif()

if (UNICORN_HAS_AARCH64)
add_library(aarch64-softmmu OBJECT
    qemu/cpu-exec.c
    qemu/cpus.c
    qemu/cputlb.c
    qemu/exec.c
    qemu/fpu/softfloat.c
    qemu/hw/arm/tosa.c
    qemu/hw/arm/virt.c
    qemu/ioport.c
    qemu/memory.c
    qemu/memory_mapping.c
    qemu/target-arm/cpu.c
    qemu/target-arm/cpu64.c
    qemu/target-arm/crypto_helper.c
    qemu/target-arm/helper-a64.c
    qemu/target-arm/helper.c
    qemu/target-arm/iwmmxt_helper.c
    qemu/target-arm/neon_helper.c
    qemu/target-arm/op_helper.c
    qemu/target-arm/psci.c
    qemu/target-arm/translate-a64.c
    qemu/target-arm/translate.c
    qemu/target-arm/unicorn_aarch64.c
    qemu/tcg/optimize.c
    qemu/tcg/tcg.c
    qemu/translate-all.c
)

if(MSVC)
    target_compile_options(aarch64-softmmu PRIVATE
        -DNEED_CPU_H
        /FIaarch64.h
        /I${CMAKE_CURRENT_SOURCE_DIR}/msvc/unicorn/aarch64-softmmu
        /I${CMAKE_CURRENT_SOURCE_DIR}/qemu/target-arm
    )
else()
    target_compile_options(aarch64-softmmu PRIVATE
        -DNEED_CPU_H
        -include aarch64.h
        -I${CMAKE_BINARY_DIR}/aarch64-softmmu
        -I${CMAKE_CURRENT_SOURCE_DIR}/qemu/target-arm
    )
endif()

add_library(aarch64eb-softmmu OBJECT
    qemu/cpu-exec.c
    qemu/cpus.c
    qemu/cputlb.c
    qemu/exec.c
    qemu/fpu/softfloat.c
    qemu/hw/arm/tosa.c
    qemu/hw/arm/virt.c
    qemu/ioport.c
    qemu/memory.c
    qemu/memory_mapping.c
    qemu/target-arm/cpu.c
    qemu/target-arm/cpu64.c
    qemu/target-arm/crypto_helper.c
    qemu/target-arm/helper-a64.c
    qemu/target-arm/helper.c
    qemu/target-arm/iwmmxt_helper.c
    qemu/target-arm/neon_helper.c
    qemu/target-arm/op_helper.c
    qemu/target-arm/psci.c
    qemu/target-arm/translate-a64.c
    qemu/target-arm/translate.c
    qemu/target-arm/unicorn_aarch64.c
    qemu/tcg/optimize.c
    qemu/tcg/tcg.c
    qemu/translate-all.c
)

if(MSVC)
    target_compile_options(aarch64eb-softmmu PRIVATE
        -DNEED_CPU_H
        /FIaarch64eb.h
        /I${CMAKE_CURRENT_SOURCE_DIR}/msvc/unicorn/aarch64eb-softmmu
        /I${CMAKE_CURRENT_SOURCE_DIR}/qemu/target-arm
    )
else()
    target_compile_options(aarch64eb-softmmu PRIVATE
        -DNEED_CPU_H
        -include aarch64eb.h
        -I${CMAKE_BINARY_DIR}/aarch64eb-softmmu
        -I${CMAKE_CURRENT_SOURCE_DIR}/qemu/target-arm
    )
endif()
endif()

if (UNICORN_HAS_M68K)
add_library(m68k-softmmu OBJECT
    qemu/cpu-exec.c
    qemu/cpus.c
    qemu/cputlb.c
    qemu/exec.c
    qemu/fpu/softfloat.c
    qemu/hw/m68k/dummy_m68k.c
    qemu/ioport.c
    qemu/memory.c
    qemu/memory_mapping.c
    qemu/target-m68k/cpu.c
    qemu/target-m68k/helper.c
    qemu/target-m68k/op_helper.c
    qemu/target-m68k/translate.c
    qemu/target-m68k/unicorn.c
    qemu/tcg/optimize.c
    qemu/tcg/tcg.c
    qemu/translate-all.c
)

if(MSVC)
    target_compile_options(m68k-softmmu PRIVATE
        -DNEED_CPU_H
        /FIm68k.h
        /I${CMAKE_CURRENT_SOURCE_DIR}/msvc/unicorn/m68k-softmmu
        /I${CMAKE_CURRENT_SOURCE_DIR}/qemu/target-m68k
    )
else()
    target_compile_options(m68k-softmmu PRIVATE
        -DNEED_CPU_H
        -include m68k.h
        -I${CMAKE_BINARY_DIR}/m68k-softmmu
        -I${CMAKE_CURRENT_SOURCE_DIR}/qemu/target-m68k
    )
endif()
endif()

if (UNICORN_HAS_MIPS)
add_library(mips-softmmu OBJECT
    qemu/cpu-exec.c
    qemu/cpus.c
    qemu/cputlb.c
    qemu/exec.c
    qemu/fpu/softfloat.c
    qemu/hw/mips/addr.c
    qemu/hw/mips/cputimer.c
    qemu/hw/mips/mips_r4k.c
    qemu/ioport.c
    qemu/memory.c
    qemu/memory_mapping.c
    qemu/target-mips/cpu.c
    qemu/target-mips/dsp_helper.c
    qemu/target-mips/helper.c
    qemu/target-mips/lmi_helper.c
    qemu/target-mips/msa_helper.c
    qemu/target-mips/op_helper.c
    qemu/target-mips/translate.c
    qemu/target-mips/unicorn.c
    qemu/tcg/optimize.c
    qemu/tcg/tcg.c
    qemu/translate-all.c
)

if(MSVC)
    target_compile_options(mips-softmmu PRIVATE
        -DNEED_CPU_H
        /FImips.h
        /I${CMAKE_CURRENT_SOURCE_DIR}/msvc/unicorn/mips-softmmu
        /I${CMAKE_CURRENT_SOURCE_DIR}/qemu/target-mips
    )
else()
    target_compile_options(mips-softmmu PRIVATE
        -DNEED_CPU_H
        -include mips.h
        -I${CMAKE_BINARY_DIR}/mips-softmmu
        -I${CMAKE_CURRENT_SOURCE_DIR}/qemu/target-mips
    )
endif()

add_library(mipsel-softmmu OBJECT
    qemu/cpu-exec.c
    qemu/cpus.c
    qemu/cputlb.c
    qemu/exec.c
    qemu/fpu/softfloat.c
    qemu/hw/mips/addr.c
    qemu/hw/mips/cputimer.c
    qemu/hw/mips/mips_r4k.c
    qemu/ioport.c
    qemu/memory.c
    qemu/memory_mapping.c
    qemu/target-mips/cpu.c
    qemu/target-mips/dsp_helper.c
    qemu/target-mips/helper.c
    qemu/target-mips/lmi_helper.c
    qemu/target-mips/msa_helper.c
    qemu/target-mips/op_helper.c
    qemu/target-mips/translate.c
    qemu/target-mips/unicorn.c
    qemu/tcg/optimize.c
    qemu/tcg/tcg.c
    qemu/translate-all.c
)

if(MSVC)
    target_compile_options(mipsel-softmmu PRIVATE
        -DNEED_CPU_H
        /FImipsel.h
        /I${CMAKE_CURRENT_SOURCE_DIR}/msvc/unicorn/mipsel-softmmu
        /I${CMAKE_CURRENT_SOURCE_DIR}/qemu/target-mips
    )
else()
    target_compile_options(mipsel-softmmu PRIVATE
        -DNEED_CPU_H
        -include mipsel.h
        -I${CMAKE_BINARY_DIR}/mipsel-softmmu
        -I${CMAKE_CURRENT_SOURCE_DIR}/qemu/target-mips
    )
endif()

add_library(mips64-softmmu OBJECT
    qemu/cpu-exec.c
    qemu/cpus.c
    qemu/cputlb.c
    qemu/exec.c
    qemu/fpu/softfloat.c
    qemu/hw/mips/addr.c
    qemu/hw/mips/cputimer.c
    qemu/hw/mips/mips_r4k.c
    qemu/ioport.c
    qemu/memory.c
    qemu/memory_mapping.c
    qemu/target-mips/cpu.c
    qemu/target-mips/dsp_helper.c
    qemu/target-mips/helper.c
    qemu/target-mips/lmi_helper.c
    qemu/target-mips/msa_helper.c
    qemu/target-mips/op_helper.c
    qemu/target-mips/translate.c
    qemu/target-mips/unicorn.c
    qemu/tcg/optimize.c
    qemu/tcg/tcg.c
    qemu/translate-all.c
)

if(MSVC)
    target_compile_options(mips64-softmmu PRIVATE
        -DNEED_CPU_H
        /FImips64.h
        /I${CMAKE_CURRENT_SOURCE_DIR}/msvc/unicorn/mips64-softmmu
        /I${CMAKE_CURRENT_SOURCE_DIR}/qemu/target-mips
    )
else()
    target_compile_options(mips64-softmmu PRIVATE
        -DNEED_CPU_H
        -include mips64.h
        -I${CMAKE_BINARY_DIR}/mips64-softmmu
        -I${CMAKE_CURRENT_SOURCE_DIR}/qemu/target-mips
    )
endif()

add_library(mips64el-softmmu OBJECT
    qemu/cpu-exec.c
    qemu/cpus.c
    qemu/cputlb.c
    qemu/exec.c
    qemu/fpu/softfloat.c
    qemu/hw/mips/addr.c
    qemu/hw/mips/cputimer.c
    qemu/hw/mips/mips_r4k.c
    qemu/ioport.c
    qemu/memory.c
    qemu/memory_mapping.c
    qemu/target-mips/cpu.c
    qemu/target-mips/dsp_helper.c
    qemu/target-mips/helper.c
    qemu/target-mips/lmi_helper.c
    qemu/target-mips/msa_helper.c
    qemu/target-mips/op_helper.c
    qemu/target-mips/translate.c
    qemu/target-mips/unicorn.c
    qemu/tcg/optimize.c
    qemu/tcg/tcg.c
    qemu/translate-all.c
)

if(MSVC)
    target_compile_options(mips64el-softmmu PRIVATE
        -DNEED_CPU_H
        /FImips64el.h
        /I${CMAKE_CURRENT_SOURCE_DIR}/msvc/unicorn/mips64el-softmmu
        /I${CMAKE_CURRENT_SOURCE_DIR}/qemu/target-mips
    )
else()
    target_compile_options(mips64el-softmmu PRIVATE
        -DNEED_CPU_H
        -include mips64el.h
        -I${CMAKE_BINARY_DIR}/mips64el-softmmu
        -I${CMAKE_CURRENT_SOURCE_DIR}/qemu/target-mips
    )
endif()
endif()

if (UNICORN_HAS_SPARC)
add_library(sparc-softmmu OBJECT
    qemu/cpu-exec.c
    qemu/cpus.c
    qemu/cputlb.c
    qemu/exec.c
    qemu/fpu/softfloat.c
    qemu/hw/sparc/leon3.c
    qemu/ioport.c
    qemu/memory.c
    qemu/memory_mapping.c
    qemu/target-sparc/cc_helper.c
    qemu/target-sparc/cpu.c
    qemu/target-sparc/fop_helper.c
    qemu/target-sparc/helper.c
    qemu/target-sparc/int32_helper.c
    qemu/target-sparc/ldst_helper.c
    qemu/target-sparc/mmu_helper.c
    qemu/target-sparc/translate.c
    qemu/target-sparc/unicorn.c
    qemu/target-sparc/win_helper.c
    qemu/tcg/optimize.c
    qemu/tcg/tcg.c
    qemu/translate-all.c
)

if(MSVC)
    target_compile_options(sparc-softmmu PRIVATE
        -DNEED_CPU_H
        /FIsparc.h
        /I${CMAKE_CURRENT_SOURCE_DIR}/msvc/unicorn/sparc-softmmu
        /I${CMAKE_CURRENT_SOURCE_DIR}/qemu/target-sparc
    )
else()
    target_compile_options(sparc-softmmu PRIVATE
        -DNEED_CPU_H
        -include sparc.h
        -I${CMAKE_BINARY_DIR}/sparc-softmmu
        -I${CMAKE_CURRENT_SOURCE_DIR}/qemu/target-sparc
    )
endif()

add_library(sparc64-softmmu OBJECT
    qemu/cpu-exec.c
    qemu/cpus.c
    qemu/cputlb.c
    qemu/exec.c
    qemu/fpu/softfloat.c
    qemu/hw/sparc64/sun4u.c
    qemu/ioport.c
    qemu/memory.c
    qemu/memory_mapping.c
    qemu/target-sparc/cc_helper.c
    qemu/target-sparc/cpu.c
    qemu/target-sparc/fop_helper.c
    qemu/target-sparc/helper.c
    qemu/target-sparc/int64_helper.c
    qemu/target-sparc/ldst_helper.c
    qemu/target-sparc/mmu_helper.c
    qemu/target-sparc/translate.c
    qemu/target-sparc/unicorn64.c
    qemu/target-sparc/vis_helper.c
    qemu/target-sparc/win_helper.c
    qemu/tcg/optimize.c
    qemu/tcg/tcg.c
    qemu/translate-all.c
)

if(MSVC)
    target_compile_options(sparc64-softmmu PRIVATE
        -DNEED_CPU_H
        /FIsparc64.h
        /I${CMAKE_CURRENT_SOURCE_DIR}/msvc/unicorn/sparc64-softmmu
        /I${CMAKE_CURRENT_SOURCE_DIR}/qemu/target-sparc
    )
else()
    target_compile_options(sparc64-softmmu PRIVATE
        -DNEED_CPU_H
        -include sparc64.h
        -I${CMAKE_BINARY_DIR}/sparc64-softmmu
        -I${CMAKE_CURRENT_SOURCE_DIR}/qemu/target-sparc
    )
endif()
endif()

set(UNICORN_SRCS_COMMON
    list.c
    qemu/accel.c
    qemu/glib_compat.c
    qemu/hw/core/machine.c
    qemu/hw/core/qdev.c
    qemu/qapi/qapi-dealloc-visitor.c
    qemu/qapi/qapi-visit-core.c
    qemu/qapi/qmp-input-visitor.c
    qemu/qapi/qmp-output-visitor.c
    qemu/qapi/string-input-visitor.c
    qemu/qemu-log.c
    qemu/qemu-timer.c
    qemu/qobject/qbool.c
    qemu/qobject/qdict.c
    qemu/qobject/qerror.c
    qemu/qobject/qfloat.c
    qemu/qobject/qint.c
    qemu/qobject/qlist.c
    qemu/qobject/qstring.c
    qemu/qom/container.c
    qemu/qom/cpu.c
    qemu/qom/object.c
    qemu/qom/qom-qobject.c
    qemu/tcg-runtime.c
    qemu/util/aes.c
    qemu/util/bitmap.c
    qemu/util/bitops.c
    qemu/util/crc32c.c
    qemu/util/cutils.c
    qemu/util/error.c
    qemu/util/getauxval.c
    qemu/util/host-utils.c
    qemu/util/module.c
    qemu/util/qemu-timer-common.c
    qemu/vl.c
    uc.c
)

if (WIN32)
    set(UNICORN_SRCS
        ${UNICORN_SRCS_COMMON}
        qemu/util/oslib-win32.c
        qemu/util/qemu-thread-win32.c
        qemu/util/qemu-error.c
        ${CMAKE_CURRENT_SOURCE_DIR}/msvc/unicorn/qapi-types.c
        ${CMAKE_CURRENT_SOURCE_DIR}/msvc/unicorn/qapi-visit.c
    )
    if(CMAKE_SIZEOF_VOID_P EQUAL 8)
        if(MSVC_VERSION LESS 1600 AND MSVC_IDE)
            add_custom_command(OUTPUT "${CMAKE_CURRENT_SOURCE_DIR}/build/setjmp-wrapper-win32.dir/setjmp-wrapper-win32.obj"
                COMMAND ml64 /c /nologo /Fo"${CMAKE_CURRENT_SOURCE_DIR}/build/setjmp-wrapper-win32.dir/setjmp-wrapper-win32.obj" /W3 /errorReport:prompt /Ta"${CMAKE_CURRENT_SOURCE_DIR}/qemu/util/setjmp-wrapper-win32.asm"
                DEPENDS "${CMAKE_CURRENT_SOURCE_DIR}/qemu/util/setjmp-wrapper-win32.asm"
            )
            set(UNICORN_SRCS ${UNICORN_SRCS} "${CMAKE_CURRENT_SOURCE_DIR}/build/setjmp-wrapper-win32.dir/setjmp-wrapper-win32.obj")
        else()
            enable_language(ASM_MASM)
        endif()
        set(UNICORN_SRCS ${UNICORN_SRCS} qemu/util/setjmp-wrapper-win32.asm)
    endif()
else()
    set(UNICORN_SRCS
        ${UNICORN_SRCS_COMMON}
        qemu/util/oslib-posix.c
        qemu/util/qemu-thread-posix.c
        qemu/qapi-types.c
        qemu/qapi-visit.c
    )
endif()

if (UNICORN_HAS_X86)
    list(APPEND UNICORN_COMPILE_OPTIONS -DUNICORN_HAS_X86)
    list(APPEND UNICORN_OBJECT_LIBRARIES x86_64-softmmu)
    list(APPEND UNICORN_SAMPLE_FILE sample_x86 sample_x86_32_gdt_and_seg_regs sample_batch_reg mem_apis shellcode)
endif()
if (UNICORN_HAS_ARM)
    list(APPEND UNICORN_COMPILE_OPTIONS -DUNICORN_HAS_ARM -DUNICORN_HAS_ARMEB)
    list(APPEND UNICORN_OBJECT_LIBRARIES arm-softmmu armeb-softmmu)
    list(APPEND UNICORN_SAMPLE_FILE sample_arm sample_armeb)
endif()
if (UNICORN_HAS_AARCH64)
    list(APPEND UNICORN_COMPILE_OPTIONS -DUNICORN_HAS_ARM64)
    list(APPEND UNICORN_OBJECT_LIBRARIES aarch64-softmmu aarch64eb-softmmu)
    list(APPEND UNICORN_SAMPLE_FILE sample_arm64 sample_arm64eb)
endif()
if (UNICORN_HAS_M68K)
    list(APPEND UNICORN_COMPILE_OPTIONS -DUNICORN_HAS_M68K)
    list(APPEND UNICORN_OBJECT_LIBRARIES m68k-softmmu)
    list(APPEND UNICORN_SAMPLE_FILE sample_m68k)
endif()
if (UNICORN_HAS_MIPS)
    list(APPEND UNICORN_COMPILE_OPTIONS -DUNICORN_HAS_MIPS -DUNICORN_HAS_MIPSEL -DUNICORN_HAS_MIPS64 -DUNICORN_HAS_MIPS64EL)
    list(APPEND UNICORN_OBJECT_LIBRARIES mips-softmmu mipsel-softmmu mips64-softmmu mips64el-softmmu)
    list(APPEND UNICORN_SAMPLE_FILE sample_mips)
endif()
if (UNICORN_HAS_SPARC)
    list(APPEND UNICORN_COMPILE_OPTIONS -DUNICORN_HAS_SPARC)
    list(APPEND UNICORN_OBJECT_LIBRARIES sparc-softmmu sparc64-softmmu)
    list(APPEND UNICORN_SAMPLE_FILE sample_sparc)
endif()

foreach(OBJECT_LIBRARY ${UNICORN_OBJECT_LIBRARIES})
    list(APPEND UNICORN_SRCS $<TARGET_OBJECTS:${OBJECT_LIBRARY}>)
endforeach()

add_library(unicorn
    ${UNICORN_SRCS}
)

if(WIN32)
    if(BUILD_SHARED_LIBS)
        list(APPEND UNICORN_COMPILE_OPTIONS -DUNICORN_SHARED)
    endif()

    set_target_properties(unicorn PROPERTIES
        VERSION "${UNICORN_VERSION_MAJOR}.${UNICORN_VERSION_MINOR}"
    )
else()
    target_link_libraries(unicorn PRIVATE m)

    set_target_properties(unicorn PROPERTIES
        VERSION ${UNICORN_VERSION_MAJOR}
        SOVERSION ${UNICORN_VERSION_MAJOR}
    )
endif()

target_compile_options(unicorn PRIVATE
    ${UNICORN_COMPILE_OPTIONS}
)

target_include_directories(unicorn PUBLIC
    include
)

if(UNICORN_BUILD_SAMPLES)
    find_package(Threads REQUIRED)

    foreach(SAMPLE_FILE ${UNICORN_SAMPLE_FILE})
        add_executable(${SAMPLE_FILE}
            ${CMAKE_CURRENT_SOURCE_DIR}/samples/${SAMPLE_FILE}.c
        )
        target_link_libraries(${SAMPLE_FILE} PRIVATE
            unicorn
            ${CMAKE_THREAD_LIBS_INIT}
        )
    endforeach()
endif()

if(UNICORN_INSTALL)
    include("GNUInstallDirs")
    file(GLOB UNICORN_HEADERS ${CMAKE_CURRENT_SOURCE_DIR}/include/unicorn/*.h)
    install(TARGETS unicorn
        RUNTIME DESTINATION bin
        ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
        LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
    )
    install(FILES ${UNICORN_HEADERS} DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/unicorn)
    file(WRITE ${CMAKE_BINARY_DIR}/unicorn.pc "Name: unicorn\n\
Description: Unicorn emulator engine\n\
Version: ${UNICORN_VERSION_MAJOR}.${UNICORN_VERSION_MINOR}.${UNICORN_VERSION_PATCH}\n\
libdir=${CMAKE_INSTALL_FULL_LIBDIR}\n\
includedir=${CMAKE_INSTALL_FULL_INCLUDEDIR}\n\
Libs: -L\$\{libdir\} -lunicorn\n\
Cflags: -I\$\{includedir\}\n"
    )
    install(FILES ${CMAKE_BINARY_DIR}/unicorn.pc DESTINATION ${CMAKE_INSTALL_LIBDIR}/pkgconfig)
endif()
