# CMake setup for Unicorn 2.
# By Huitao Chen & Nguyen Anh Quynh, 2019-2020

cmake_minimum_required(VERSION 3.5)

# Only required for MSVC, but we can't know the compiler at this point because we haven't
# called enable_language() or project(), and if we did that it would lock in the old
# policy. Setting these policies is harmless for non-MSVC though, so just enable them
# always.
if(CMAKE_VERSION VERSION_GREATER_EQUAL "3.15")
    # Set explicitly the policies we want rather than raising the base to the current
    # version. This prevents unintended behavior changes as CMake evolves and provides a
    # consistent experience across different CMake versions.
    # CMP0091: prevent msvcrt flags being added to default CMAKE_<LANG>_FLAGS_<CONFIG>
    cmake_policy(SET CMP0091 NEW)
    # CMP0092: prevent warning flags being added to default CMAKE_<LANG>_FLAGS for MSVC
    cmake_policy(SET CMP0092 NEW)
endif()

# Honor visibility properties for all target types.
cmake_policy(SET CMP0063 NEW)

option(ZIG_BUILD "Enable zig build" OFF)
if(ZIG_BUILD)
    include(cmake/zig.cmake)
endif()

# Workaround to fix wrong compiler on macos.
if(APPLE AND NOT CMAKE_C_COMPILER)
    set(CMAKE_C_COMPILER "/usr/bin/cc")
endif()

# Source: https://github.com/capstone-engine/capstone/blob/next/CMakeLists.txt
# If building for OSX it's best to allow CMake to handle building both architectures
if(APPLE)
    # The cibuildwheel on Github Actions sets this env variable
    # with the architecture flags it wants to build for.
    if(DEFINED ENV{ARCHFLAGS})
        if("$ENV{ARCHFLAGS}" STREQUAL "-arch arm64 -arch x86_64")
            set(CMAKE_OSX_ARCHITECTURES "x86_64;arm64")
        elseif("$ENV{ARCHFLAGS}" STREQUAL "-arch arm64")
            set(CMAKE_OSX_ARCHITECTURES "arm64")
        elseif("$ENV{ARCHFLAGS}" STREQUAL "-arch x86_64")
            set(CMAKE_OSX_ARCHITECTURES "x86_64")
        endif()
    else()
        set(CMAKE_OSX_ARCHITECTURES "x86_64;arm64")
    endif()
endif()

# Detect if unicorn is compiled as the top-level project
set(PROJECT_IS_TOP_LEVEL OFF)
if(CMAKE_CURRENT_SOURCE_DIR STREQUAL CMAKE_SOURCE_DIR)
    set(PROJECT_IS_TOP_LEVEL ON)

    # Enable folder support
    set_property(GLOBAL PROPERTY USE_FOLDERS ON)
endif()

project(unicorn C)

# We depend on the availability of the CMAKE_MSVC_RUNTIME_LIBRARY, which is only
# available in CMake 3.15 and above (see also the comments above in regards to policy
# CMP0091).
if(MSVC AND CMAKE_VERSION VERSION_LESS "3.15")
    message(FATAL_ERROR "Please update CMake to 3.15 or greater.")
endif()

# mainline qemu mostly just uses compiler default
set(CMAKE_C_STANDARD 11)

set(UNICORN_VERSION_MAJOR 2)
set(UNICORN_VERSION_MINOR 1)
set(UNICORN_VERSION_PATCH 1)

include(cmake/bundle_static.cmake)

# Even though we generate shared lib and static archive at the same time, we still support
# using unicorn as a subdirectory so we have to respect BUILD_SHARED_LIBS.
#
# Also we would like users to link a native cmake target, instead of a custom target for better
# compatability.
option(BUILD_SHARED_LIBS "Build shared instead of static library" ${PROJECT_IS_TOP_LEVEL})
option(UNICORN_FUZZ "Enable fuzzing" OFF)
option(UNICORN_LOGGING "Enable logging" OFF)
option(UNICORN_BUILD_TESTS "Build unicorn tests" ${PROJECT_IS_TOP_LEVEL})
option(UNICORN_INSTALL "Enable unicorn installation" ${PROJECT_IS_TOP_LEVEL})
set(UNICORN_ARCH "x86;arm;aarch64;riscv;mips;sparc;m68k;ppc;s390x;tricore" CACHE STRING "Enabled unicorn architectures")
option(UNICORN_TRACER "Trace unicorn execution" OFF)

foreach(ARCH_LOOP ${UNICORN_ARCH})
    string(TOUPPER "${ARCH_LOOP}" ARCH_LOOP)
    set(UNICORN_HAS_${ARCH_LOOP} TRUE)
endforeach()

if(MSVC)
    include_directories(
        ${CMAKE_CURRENT_SOURCE_DIR}/msvc
    )
else()
    include_directories(
        ${CMAKE_BINARY_DIR}
    )
endif()

include_directories(
    glib_compat
    qemu
    qemu/include
    include
    qemu/tcg
)

# QEMU logging facility
if (UNICORN_LOGGING)
    add_compile_options(-DUNICORN_LOGGING)
endif()

# Some distributions on some rare architecures don't auto link atomic for us and
# we do this manually by adding flags.
set(ATOMIC_LINKAGE_FIX FALSE)
if(MSVC)
    if(CMAKE_SIZEOF_VOID_P EQUAL 8)
        set(MSVC_FLAG  -D__x86_64__)
    elseif(CMAKE_SIZEOF_VOID_P EQUAL 4)
        set(MSVC_FLAG  -D__i386__)
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
    )

    # Disable some warnings
    add_compile_options($<$<COMPILE_LANGUAGE:C>:/wd4018>)
    add_compile_options($<$<COMPILE_LANGUAGE:C>:/wd4098>)
    add_compile_options($<$<COMPILE_LANGUAGE:C>:/wd4244>)
    add_compile_options($<$<COMPILE_LANGUAGE:C>:/wd4267>)

    # handle msvcrt setting being passed in CMAKE_C_FLAGS
    if(CMAKE_C_FLAGS MATCHES "[/-]M[TD]d?")
        # ensure CMAKE_MSVC_RUNTIME_LIBRARY is not already defined
        if(DEFINED CMAKE_MSVC_RUNTIME_LIBRARY)
            message(FATAL_ERROR "please set the runtime library via either CMAKE_C_FLAGS or CMAKE_MSVC_RUNTIME_LIBRARY, not both")
        endif()

        if(CMAKE_C_FLAGS MATCHES "[/-]MTd")
            set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreadedDebug")
        elseif(CMAKE_C_FLAGS MATCHES "[/-]MDd")
            set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreadedDebugDLL")
        elseif(CMAKE_C_FLAGS MATCHES "[/-]MT")
            set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded")
        elseif(CMAKE_C_FLAGS MATCHES "[/-]MD")
            set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreadedDLL")
        endif()

        # prevent the arg from occurring more than once (not a big deal, just to keep tidy)
        string(REGEX REPLACE "[/-]M[TD]d?" "" CMAKE_C_FLAGS ${CMAKE_C_FLAGS})
    endif()
else()
    if(MINGW)
        execute_process(COMMAND ${CMAKE_C_COMPILER} -dumpmachine
            OUTPUT_VARIABLE UC_COMPILER_VERSION)

        string(FIND "${UC_COMPILER_VERSION}" "i686" UC_RET)
        if(${UC_RET} GREATER_EQUAL "0")
            set(UNICORN_TARGET_ARCH "i386")
            set(UNICORN_CFLAGS -m32 -static-libgcc) # Workaround for github action bugs
            set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -m32")
            set(CMAKE_SHARED_LINKER_FLAGS "${CMAKE_SHARED_LINKER_FLAGS} -m32")
        else()
            set(UNICORN_TARGET_ARCH "i386")
            set(UNICORN_CFLAGS -m64 -mcx16)
            set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -m64")
            set(CMAKE_SHARED_LINKER_FLAGS "${CMAKE_SHARED_LINKER_FLAGS} -m64")
        endif()
    elseif(ANDROID_ABI)
        string(FIND "${ANDROID_ABI}" "arm64" UC_RET)
        file(WRITE ${CMAKE_BINARY_DIR}/adb.sh "#!/bin/bash\n\n# Auto-generated by CMakeLists.txt\n\nadb shell mkdir -p /data/local/tmp/build\n")

        if(${UC_RET} GREATER_EQUAL "0")
            set(UNICORN_TARGET_ARCH "aarch64")
        else()
            string(FIND "${ANDROID_ABI}" "armeabi" UC_RET)

            if(${UC_RET} GREATER_EQUAL "0")
                set(UNICORN_TARGET_ARCH "arm")
            else()
                set(UNICORN_TARGET_ARCH "i386")
            endif()
        endif()
    else()
        execute_process(COMMAND ${CMAKE_C_COMPILER} -dM -E -
            INPUT_FILE /dev/null
            OUTPUT_VARIABLE UC_COMPILER_MACRO)

        while(TRUE)
            string(FIND "${UC_COMPILER_MACRO}" "__x86_64__" UC_RET)
            if(${UC_RET} GREATER_EQUAL "0")
                set(UNICORN_TARGET_ARCH "i386")
                string(FIND "${UC_COMPILER_MACRO}" "__ILP32__" UC_RET)
                if(${UC_RET} GREATER_EQUAL "0")
                    set(UNICORN_CFLAGS -mx32)
                    set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -mx32")
                    set(CMAKE_SHARED_LINKER_FLAGS "${CMAKE_SHARED_LINKER_FLAGS} -mx32")
                else()
                    set(UNICORN_CFLAGS -m64 -mcx16)
                    set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -m64")
                    set(CMAKE_SHARED_LINKER_FLAGS "${CMAKE_SHARED_LINKER_FLAGS} -m64")
                endif()
                break()
            endif()
            string(FIND "${UC_COMPILER_MACRO}" "__i386__" UC_RET)
            if(${UC_RET} GREATER_EQUAL "0")
                set(UNICORN_TARGET_ARCH "i386")
                break()
            endif()
            string(FIND "${UC_COMPILER_MACRO}" "__arm__" UC_RET)
            if(${UC_RET} GREATER_EQUAL "0")
                set(UNICORN_TARGET_ARCH "arm")
                set(ATOMIC_LINKAGE_FIX TRUE)
                break()
            endif()
            string(FIND "${UC_COMPILER_MACRO}" "__aarch64__" UC_RET)
            if(${UC_RET} GREATER_EQUAL "0")
                set(UNICORN_TARGET_ARCH "aarch64")
                break()
            endif()
            string(FIND "${UC_COMPILER_MACRO}" "__mips__" UC_RET)
            if(${UC_RET} GREATER_EQUAL "0")
                set(UNICORN_TARGET_ARCH "mips")
                set(ATOMIC_LINKAGE_FIX TRUE)
                break()
            endif()
            string(FIND "${UC_COMPILER_MACRO}" "__sparc__" UC_RET)
            if(${UC_RET} GREATER_EQUAL "0")
                set(UNICORN_TARGET_ARCH "sparc")
                set(ATOMIC_LINKAGE_FIX TRUE)
                break()
            endif()
            string(FIND "${UC_COMPILER_MACRO}" "__ia64__" UC_RET)
            if(${UC_RET} GREATER_EQUAL "0")
                set(UNICORN_TARGET_ARCH "ia64")
                break()
            endif()
            string(FIND "${UC_COMPILER_MACRO}" "_ARCH_PPC" UC_RET)
            if(${UC_RET} GREATER_EQUAL "0")
                set(UNICORN_TARGET_ARCH "ppc")
                set(ATOMIC_LINKAGE_FIX TRUE)
                break()
            endif()
            string(FIND "${UC_COMPILER_MACRO}" "__riscv" UC_RET)
            if(${UC_RET} GREATER_EQUAL "0")
                set(UNICORN_TARGET_ARCH "riscv")
                set(ATOMIC_LINKAGE_FIX TRUE)
                break()
            endif()
            string(FIND "${UC_COMPILER_MACRO}" "__s390__" UC_RET)
            if(${UC_RET} GREATER_EQUAL "0")
                set(UNICORN_TARGET_ARCH "s390")
                set(ATOMIC_LINKAGE_FIX TRUE)
                break()
            endif()
            string(FIND ${UC_COMPILER_MACRO} "__tricore__" UC_RET)
            if (${UC_RET} GREATER_EQUAL "0")
                set(UNICORN_TARGET_ARCH "tricore")
                break()
            endif()
            message(FATAL_ERROR "Unknown host compiler: ${CMAKE_C_COMPILER}.")
        endwhile(TRUE)
    endif()

    set(EXTRA_CFLAGS "--extra-cflags=")
    if(UNICORN_HAS_X86)
        set(EXTRA_CFLAGS "${EXTRA_CFLAGS}-DUNICORN_HAS_X86 ")
    endif()
    if(UNICORN_HAS_ARM)
        set(EXTRA_CFLAGS "${EXTRA_CFLAGS}-DUNICORN_HAS_ARM ")
    endif()
    if(UNICORN_HAS_AARCH64)
        set(EXTRA_CFLAGS "${EXTRA_CFLAGS}-DUNICORN_HAS_ARM64 ")
    endif()
    if(UNICORN_HAS_M68K)
        set(EXTRA_CFLAGS "${EXTRA_CFLAGS}-DUNICORN_HAS_M68K ")
    endif()
    if(UNICORN_HAS_MIPS)
        set(EXTRA_CFLAGS "${EXTRA_CFLAGS}-DUNICORN_HAS_MIPS -DUNICORN_HAS_MIPSEL -DUNICORN_HAS_MIPS64 -DUNICORN_HAS_MIPS64EL ")
    endif()
    if(UNICORN_HAS_SPARC)
        set(EXTRA_CFLAGS "${EXTRA_CFLAGS}-DUNICORN_HAS_SPARC ")
    endif()
    if(UNICORN_HAS_PPC)
        set(EXTRA_CFLAGS "${EXTRA_CFLAGS}-DUNICORN_HAS_PPC ")
    endif()
    if(UNICORN_HAS_RISCV)
        set(EXTRA_CFLAGS "${EXTRA_CFLAGS}-DUNICORN_HAS_RISCV ")
    endif()
    if (UNICORN_HAS_S390X)
        set (EXTRA_CFLAGS "${EXTRA_CFLAGS}-DUNICORN_HAS_S390X ")
    endif()
    if (UNICORN_HAS_TRICORE)
        set (EXTRA_CFLAGS "${EXTRA_CFLAGS}-DUNICORN_HAS_TRICORE ")
    endif()

    set(EXTRA_CFLAGS "${EXTRA_CFLAGS}-fPIC")
    if(ANDROID_ABI)
        set(EXTRA_CFLAGS "${EXTRA_CFLAGS} --target=${CMAKE_C_COMPILER_TARGET}")
        set(EXTRA_CFLAGS "${EXTRA_CFLAGS} --sysroot=${CMAKE_SYSROOT}")
    endif()
    if(UNICORN_FUZZ)
        set(EXTRA_CFLAGS "${EXTRA_CFLAGS} ${CMAKE_C_FLAGS}")
    endif()
    if(UNICORN_TRACER)
        set (EXTRA_CFLAGS "${EXTRA_CFLAGS} -DUNICORN_TRACER")
    endif()
    if (ATOMIC_LINKAGE_FIX)
        set (EXTRA_CFLAGS "${EXTRA_CFLAGS} -latomic")
    endif()
    if (CMAKE_OSX_SYSROOT)
        # https://github.com/unicorn-engine/unicorn/issues/1917
        set (EXTRA_CFLAGS "${EXTRA_CFLAGS} -isysroot ${CMAKE_OSX_SYSROOT} ")
    endif()

    set(TARGET_LIST "--target-list=")
    if(UNICORN_HAS_X86)
        set(TARGET_LIST "${TARGET_LIST}x86_64-softmmu, ")
    endif()
    if(UNICORN_HAS_ARM)
        set(TARGET_LIST "${TARGET_LIST}arm-softmmu, ")
    endif()
    if(UNICORN_HAS_AARCH64)
        set(TARGET_LIST "${TARGET_LIST}aarch64-softmmu, ")
    endif()
    if(UNICORN_HAS_M68K)
        set(TARGET_LIST "${TARGET_LIST}m68k-softmmu, ")
    endif()
    if(UNICORN_HAS_MIPS)
        set(TARGET_LIST "${TARGET_LIST}mips-softmmu, mipsel-softmmu, mips64-softmmu, mips64el-softmmu, ")
    endif()
    if(UNICORN_HAS_SPARC)
        set(TARGET_LIST "${TARGET_LIST}sparc-softmmu, sparc64-softmmu, ")
    endif()
    if(UNICORN_HAS_PPC)
        set(TARGET_LIST "${TARGET_LIST}ppc-softmmu, ppc64-softmmu, ")
    endif()
    if(UNICORN_HAS_RISCV)
        set(TARGET_LIST "${TARGET_LIST}riscv32-softmmu, riscv64-softmmu, ")
    endif()
    if(UNICORN_HAS_S390X)
        set(TARGET_LIST "${TARGET_LIST}s390x-softmmu, ")
    endif()
    if (UNICORN_HAS_TRICORE)
        set (TARGET_LIST "${TARGET_LIST}tricore-softmmu, ")
    endif()
    set(TARGET_LIST "${TARGET_LIST} ")

    # GEN config-host.mak & target directories
    execute_process(COMMAND sh ${CMAKE_CURRENT_SOURCE_DIR}/qemu/configure
        --cc=${CMAKE_C_COMPILER}
        ${EXTRA_CFLAGS}
        ${TARGET_LIST}
        WORKING_DIRECTORY ${CMAKE_BINARY_DIR}
    )
    execute_process(COMMAND sh ${CMAKE_CURRENT_SOURCE_DIR}/qemu/scripts/create_config
        INPUT_FILE ${CMAKE_BINARY_DIR}/config-host.mak
        OUTPUT_FILE ${CMAKE_BINARY_DIR}/config-host.h
    )
    if(UNICORN_HAS_X86)
        execute_process(COMMAND sh ${CMAKE_CURRENT_SOURCE_DIR}/qemu/scripts/create_config
            INPUT_FILE ${CMAKE_BINARY_DIR}/x86_64-softmmu/config-target.mak
            OUTPUT_FILE ${CMAKE_BINARY_DIR}/x86_64-softmmu/config-target.h
        )
    endif()
    if(UNICORN_HAS_ARM)
        execute_process(COMMAND sh ${CMAKE_CURRENT_SOURCE_DIR}/qemu/scripts/create_config
            INPUT_FILE ${CMAKE_BINARY_DIR}/arm-softmmu/config-target.mak
            OUTPUT_FILE ${CMAKE_BINARY_DIR}/arm-softmmu/config-target.h
        )
    endif()
    if(UNICORN_HAS_AARCH64)
        execute_process(COMMAND sh ${CMAKE_CURRENT_SOURCE_DIR}/qemu/scripts/create_config
            INPUT_FILE ${CMAKE_BINARY_DIR}/aarch64-softmmu/config-target.mak
            OUTPUT_FILE ${CMAKE_BINARY_DIR}/aarch64-softmmu/config-target.h
        )
    endif()
    if(UNICORN_HAS_M68K)
        execute_process(COMMAND sh ${CMAKE_CURRENT_SOURCE_DIR}/qemu/scripts/create_config
            INPUT_FILE ${CMAKE_BINARY_DIR}/m68k-softmmu/config-target.mak
            OUTPUT_FILE ${CMAKE_BINARY_DIR}/m68k-softmmu/config-target.h
        )
    endif()
    if(UNICORN_HAS_MIPS)
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
    if(UNICORN_HAS_SPARC)
        execute_process(COMMAND sh ${CMAKE_CURRENT_SOURCE_DIR}/qemu/scripts/create_config
            INPUT_FILE ${CMAKE_BINARY_DIR}/sparc-softmmu/config-target.mak
            OUTPUT_FILE ${CMAKE_BINARY_DIR}/sparc-softmmu/config-target.h
        )
        execute_process(COMMAND sh ${CMAKE_CURRENT_SOURCE_DIR}/qemu/scripts/create_config
            INPUT_FILE ${CMAKE_BINARY_DIR}/sparc64-softmmu/config-target.mak
            OUTPUT_FILE ${CMAKE_BINARY_DIR}/sparc64-softmmu/config-target.h
        )
    endif()
    if(UNICORN_HAS_PPC)
        execute_process(COMMAND sh ${CMAKE_CURRENT_SOURCE_DIR}/qemu/scripts/create_config
            INPUT_FILE ${CMAKE_BINARY_DIR}/ppc-softmmu/config-target.mak
            OUTPUT_FILE ${CMAKE_BINARY_DIR}/ppc-softmmu/config-target.h
        )
        execute_process(COMMAND sh ${CMAKE_CURRENT_SOURCE_DIR}/qemu/scripts/create_config
            INPUT_FILE ${CMAKE_BINARY_DIR}/ppc64-softmmu/config-target.mak
            OUTPUT_FILE ${CMAKE_BINARY_DIR}/ppc64-softmmu/config-target.h
        )
    endif()
    if(UNICORN_HAS_RISCV)
        execute_process(COMMAND sh ${CMAKE_CURRENT_SOURCE_DIR}/qemu/scripts/create_config
            INPUT_FILE ${CMAKE_BINARY_DIR}/riscv32-softmmu/config-target.mak
            OUTPUT_FILE ${CMAKE_BINARY_DIR}/riscv32-softmmu/config-target.h
        )
        execute_process(COMMAND sh ${CMAKE_CURRENT_SOURCE_DIR}/qemu/scripts/create_config
            INPUT_FILE ${CMAKE_BINARY_DIR}/riscv64-softmmu/config-target.mak
            OUTPUT_FILE ${CMAKE_BINARY_DIR}/riscv64-softmmu/config-target.h
        )
    endif()
    if (UNICORN_HAS_S390X)
        execute_process(COMMAND sh ${CMAKE_CURRENT_SOURCE_DIR}/qemu/scripts/create_config
            INPUT_FILE ${CMAKE_BINARY_DIR}/s390x-softmmu/config-target.mak
            OUTPUT_FILE ${CMAKE_BINARY_DIR}/s390x-softmmu/config-target.h
        )
    endif()
    if (UNICORN_HAS_TRICORE)
        execute_process(COMMAND sh ${CMAKE_CURRENT_SOURCE_DIR}/qemu/scripts/create_config
            INPUT_FILE ${CMAKE_BINARY_DIR}/tricore-softmmu/config-target.mak
            OUTPUT_FILE ${CMAKE_BINARY_DIR}/tricore-softmmu/config-target.h
        )
    endif()
    add_compile_options(
        ${UNICORN_CFLAGS}
        -I${CMAKE_CURRENT_SOURCE_DIR}/qemu/tcg/${UNICORN_TARGET_ARCH}
        -D_GNU_SOURCE
        -D_FILE_OFFSET_BITS=64
        -D_LARGEFILE_SOURCE
        -Wall
        -fPIC
    )
    if (ATOMIC_LINKAGE_FIX)
        add_compile_options(
            -latomic
        )
    endif()
    if(APPLE)
        # This warning is disabled by default for gcc and doesn't cause any bug.
        add_compile_options(
            -Wno-missing-braces
        )
    endif()
endif()

set(UNICORN_ARCH_COMMON
    qemu/exec.c
    qemu/exec-vary.c

    qemu/softmmu/cpus.c
    qemu/softmmu/ioport.c
    qemu/softmmu/memory.c
    qemu/softmmu/memory_mapping.c

    qemu/fpu/softfloat.c

    qemu/tcg/optimize.c
    qemu/tcg/tcg.c
    qemu/tcg/tcg-op.c
    qemu/tcg/tcg-op-gvec.c
    qemu/tcg/tcg-op-vec.c

    qemu/accel/tcg/cpu-exec.c
    qemu/accel/tcg/cpu-exec-common.c
    qemu/accel/tcg/cputlb.c
    qemu/accel/tcg/tcg-all.c
    qemu/accel/tcg/tcg-runtime.c
    qemu/accel/tcg/tcg-runtime-gvec.c
    qemu/accel/tcg/translate-all.c
    qemu/accel/tcg/translator.c

    qemu/softmmu/unicorn_vtlb.c
)

if(UNICORN_HAS_X86)
add_library(x86_64-softmmu STATIC
    ${UNICORN_ARCH_COMMON}

    qemu/hw/i386/x86.c

    qemu/target/i386/arch_memory_mapping.c
    qemu/target/i386/bpt_helper.c
    qemu/target/i386/cc_helper.c
    qemu/target/i386/cpu.c
    qemu/target/i386/excp_helper.c
    qemu/target/i386/fpu_helper.c
    qemu/target/i386/helper.c
    qemu/target/i386/int_helper.c
    qemu/target/i386/machine.c
    qemu/target/i386/mem_helper.c
    qemu/target/i386/misc_helper.c
    qemu/target/i386/mpx_helper.c
    qemu/target/i386/seg_helper.c
    qemu/target/i386/smm_helper.c
    qemu/target/i386/svm_helper.c
    qemu/target/i386/translate.c
    qemu/target/i386/xsave_helper.c
    qemu/target/i386/unicorn.c
)

if(MSVC)
    target_compile_options(x86_64-softmmu PRIVATE
        -DNEED_CPU_H
        /FIx86_64.h
        /I${CMAKE_CURRENT_SOURCE_DIR}/msvc/x86_64-softmmu
        /I${CMAKE_CURRENT_SOURCE_DIR}/qemu/target/i386
    )
else()
    target_compile_options(x86_64-softmmu PRIVATE
        -DNEED_CPU_H
        -include x86_64.h
        -I${CMAKE_BINARY_DIR}/x86_64-softmmu
        -I${CMAKE_CURRENT_SOURCE_DIR}/qemu/target/i386
    )

    # Log and pow
    target_link_libraries(x86_64-softmmu PRIVATE m)
endif()

if(UNICORN_TRACER)
    target_compile_options(x86_64-softmmu PRIVATE -DUNICORN_TRACER)
endif()

endif()

if(UNICORN_HAS_ARM)
add_library(arm-softmmu STATIC
    ${UNICORN_ARCH_COMMON}

    qemu/target/arm/cpu.c
    qemu/target/arm/crypto_helper.c
    qemu/target/arm/debug_helper.c
    qemu/target/arm/helper.c
    qemu/target/arm/iwmmxt_helper.c
    qemu/target/arm/m_helper.c
    qemu/target/arm/neon_helper.c
    qemu/target/arm/op_helper.c
    qemu/target/arm/psci.c
    qemu/target/arm/tlb_helper.c
    qemu/target/arm/translate.c
    qemu/target/arm/vec_helper.c
    qemu/target/arm/vfp_helper.c
    qemu/target/arm/unicorn_arm.c
)

if(MSVC)
    target_compile_options(arm-softmmu PRIVATE
        -DNEED_CPU_H
        /FIarm.h
        /I${CMAKE_CURRENT_SOURCE_DIR}/msvc/arm-softmmu
        /I${CMAKE_CURRENT_SOURCE_DIR}/qemu/target/arm
    )
else()
    target_compile_options(arm-softmmu PRIVATE
        -DNEED_CPU_H
        -include arm.h
        -I${CMAKE_BINARY_DIR}/arm-softmmu
        -I${CMAKE_CURRENT_SOURCE_DIR}/qemu/target/arm
    )
endif()

if(UNICORN_TRACER)
    target_compile_options(arm-softmmu PRIVATE -DUNICORN_TRACER)
endif()

endif()

if(UNICORN_HAS_AARCH64)
add_library(aarch64-softmmu STATIC
    ${UNICORN_ARCH_COMMON}

    qemu/target/arm/cpu64.c
    qemu/target/arm/cpu.c
    qemu/target/arm/crypto_helper.c
    qemu/target/arm/debug_helper.c
    qemu/target/arm/helper-a64.c
    qemu/target/arm/helper.c
    qemu/target/arm/iwmmxt_helper.c
    qemu/target/arm/m_helper.c
    qemu/target/arm/neon_helper.c
    qemu/target/arm/op_helper.c
    qemu/target/arm/pauth_helper.c
    qemu/target/arm/psci.c
    qemu/target/arm/sve_helper.c
    qemu/target/arm/tlb_helper.c
    qemu/target/arm/translate-a64.c
    qemu/target/arm/translate.c
    qemu/target/arm/translate-sve.c
    qemu/target/arm/vec_helper.c
    qemu/target/arm/vfp_helper.c
    qemu/target/arm/unicorn_aarch64.c
)

if(MSVC)
    target_compile_options(aarch64-softmmu PRIVATE
        -DNEED_CPU_H
        /FIaarch64.h
        /I${CMAKE_CURRENT_SOURCE_DIR}/msvc/aarch64-softmmu
        /I${CMAKE_CURRENT_SOURCE_DIR}/qemu/target/arm
    )
else()
    target_compile_options(aarch64-softmmu PRIVATE
        -DNEED_CPU_H
        -include aarch64.h
        -I${CMAKE_BINARY_DIR}/aarch64-softmmu
        -I${CMAKE_CURRENT_SOURCE_DIR}/qemu/target/arm
    )
endif()

if(UNICORN_TRACER)
    target_compile_options(aarch64-softmmu PRIVATE -DUNICORN_TRACER)
endif()

endif()

if(UNICORN_HAS_M68K)
add_library(m68k-softmmu STATIC
    ${UNICORN_ARCH_COMMON}

    qemu/target/m68k/cpu.c
    qemu/target/m68k/fpu_helper.c
    qemu/target/m68k/helper.c
    qemu/target/m68k/op_helper.c
    qemu/target/m68k/softfloat.c
    qemu/target/m68k/translate.c
    qemu/target/m68k/unicorn.c
)

if(MSVC)
    target_compile_options(m68k-softmmu PRIVATE
        -DNEED_CPU_H
        /FIm68k.h
        /I${CMAKE_CURRENT_SOURCE_DIR}/msvc/m68k-softmmu
        /I${CMAKE_CURRENT_SOURCE_DIR}/qemu/target/m68k
    )
else()
    target_compile_options(m68k-softmmu PRIVATE
        -DNEED_CPU_H
        -include m68k.h
        -I${CMAKE_BINARY_DIR}/m68k-softmmu
        -I${CMAKE_CURRENT_SOURCE_DIR}/qemu/target/m68k
    )
endif()

if(UNICORN_TRACER)
    target_compile_options(m68k-softmmu PRIVATE -DUNICORN_TRACER)
endif()

endif()

if(UNICORN_HAS_MIPS)
add_library(mips-softmmu STATIC
    ${UNICORN_ARCH_COMMON}

    qemu/target/mips/cp0_helper.c
    qemu/target/mips/cp0_timer.c
    qemu/target/mips/cpu.c
    qemu/target/mips/dsp_helper.c
    qemu/target/mips/fpu_helper.c
    qemu/target/mips/helper.c
    qemu/target/mips/lmi_helper.c
    qemu/target/mips/msa_helper.c
    qemu/target/mips/op_helper.c
    qemu/target/mips/translate.c
    qemu/target/mips/unicorn.c
)

if(MSVC)
    target_compile_options(mips-softmmu PRIVATE
        -DNEED_CPU_H
        /FImips.h
        /I${CMAKE_CURRENT_SOURCE_DIR}/msvc/mips-softmmu
        /I${CMAKE_CURRENT_SOURCE_DIR}/qemu/target/mips
    )
else()
    target_compile_options(mips-softmmu PRIVATE
        -DNEED_CPU_H
        -include mips.h
        -I${CMAKE_BINARY_DIR}/mips-softmmu
        -I${CMAKE_CURRENT_SOURCE_DIR}/qemu/target/mips
    )
endif()

if(UNICORN_TRACER)
    target_compile_options(mips-softmmu PRIVATE -DUNICORN_TRACER)
endif()

add_library(mipsel-softmmu STATIC
    ${UNICORN_ARCH_COMMON}

    qemu/target/mips/cp0_helper.c
    qemu/target/mips/cp0_timer.c
    qemu/target/mips/cpu.c
    qemu/target/mips/dsp_helper.c
    qemu/target/mips/fpu_helper.c
    qemu/target/mips/helper.c
    qemu/target/mips/lmi_helper.c
    qemu/target/mips/msa_helper.c
    qemu/target/mips/op_helper.c
    qemu/target/mips/translate.c
    qemu/target/mips/unicorn.c
)

if(MSVC)
    target_compile_options(mipsel-softmmu PRIVATE
        -DNEED_CPU_H
        /FImipsel.h
        /I${CMAKE_CURRENT_SOURCE_DIR}/msvc/mipsel-softmmu
        /I${CMAKE_CURRENT_SOURCE_DIR}/qemu/target/mips
    )
else()
    target_compile_options(mipsel-softmmu PRIVATE
        -DNEED_CPU_H
        -include mipsel.h
        -I${CMAKE_BINARY_DIR}/mipsel-softmmu
        -I${CMAKE_CURRENT_SOURCE_DIR}/qemu/target/mips
    )
endif()

if(UNICORN_TRACER)
    target_compile_options(mipsel-softmmu PRIVATE -DUNICORN_TRACER)
endif()

add_library(mips64-softmmu STATIC
    ${UNICORN_ARCH_COMMON}

    qemu/target/mips/cp0_helper.c
    qemu/target/mips/cp0_timer.c
    qemu/target/mips/cpu.c
    qemu/target/mips/dsp_helper.c
    qemu/target/mips/fpu_helper.c
    qemu/target/mips/helper.c
    qemu/target/mips/lmi_helper.c
    qemu/target/mips/msa_helper.c
    qemu/target/mips/op_helper.c
    qemu/target/mips/translate.c
    qemu/target/mips/unicorn.c
)

if(MSVC)
    target_compile_options(mips64-softmmu PRIVATE
        -DNEED_CPU_H
        /FImips64.h
        /I${CMAKE_CURRENT_SOURCE_DIR}/msvc/mips64-softmmu
        /I${CMAKE_CURRENT_SOURCE_DIR}/qemu/target/mips
    )
else()
    target_compile_options(mips64-softmmu PRIVATE
        -DNEED_CPU_H
        -include mips64.h
        -I${CMAKE_BINARY_DIR}/mips64-softmmu
        -I${CMAKE_CURRENT_SOURCE_DIR}/qemu/target/mips
    )
endif()

if(UNICORN_TRACER)
    target_compile_options(mips64-softmmu PRIVATE -DUNICORN_TRACER)
endif()

add_library(mips64el-softmmu STATIC
    ${UNICORN_ARCH_COMMON}

    qemu/target/mips/cp0_helper.c
    qemu/target/mips/cp0_timer.c
    qemu/target/mips/cpu.c
    qemu/target/mips/dsp_helper.c
    qemu/target/mips/fpu_helper.c
    qemu/target/mips/helper.c
    qemu/target/mips/lmi_helper.c
    qemu/target/mips/msa_helper.c
    qemu/target/mips/op_helper.c
    qemu/target/mips/translate.c
    qemu/target/mips/unicorn.c
)

if(MSVC)
    target_compile_options(mips64el-softmmu PRIVATE
        -DNEED_CPU_H
        /FImips64el.h
        /I${CMAKE_CURRENT_SOURCE_DIR}/msvc/mips64el-softmmu
        /I${CMAKE_CURRENT_SOURCE_DIR}/qemu/target/mips
    )
else()
    target_compile_options(mips64el-softmmu PRIVATE
        -DNEED_CPU_H
        -include mips64el.h
        -I${CMAKE_BINARY_DIR}/mips64el-softmmu
        -I${CMAKE_CURRENT_SOURCE_DIR}/qemu/target/mips
    )
endif()

if(UNICORN_TRACER)
    target_compile_options(mips64el-softmmu PRIVATE -DUNICORN_TRACER)
endif()

endif()

if(UNICORN_HAS_SPARC)
add_library(sparc-softmmu STATIC
    ${UNICORN_ARCH_COMMON}

    qemu/target/sparc/cc_helper.c
    qemu/target/sparc/cpu.c
    qemu/target/sparc/fop_helper.c
    qemu/target/sparc/helper.c
    qemu/target/sparc/int32_helper.c
    qemu/target/sparc/ldst_helper.c
    qemu/target/sparc/mmu_helper.c
    qemu/target/sparc/translate.c
    qemu/target/sparc/win_helper.c
    qemu/target/sparc/unicorn.c
)

if(MSVC)
    target_compile_options(sparc-softmmu PRIVATE
        -DNEED_CPU_H
        /FIsparc.h
        /I${CMAKE_CURRENT_SOURCE_DIR}/msvc/sparc-softmmu
        /I${CMAKE_CURRENT_SOURCE_DIR}/qemu/target/sparc
    )
else()
    target_compile_options(sparc-softmmu PRIVATE
        -DNEED_CPU_H
        -include sparc.h
        -I${CMAKE_BINARY_DIR}/sparc-softmmu
        -I${CMAKE_CURRENT_SOURCE_DIR}/qemu/target/sparc
    )
endif()

if(UNICORN_TRACER)
    target_compile_options(sparc-softmmu PRIVATE -DUNICORN_TRACER)
endif()

add_library(sparc64-softmmu STATIC
    ${UNICORN_ARCH_COMMON}

    qemu/target/sparc/cc_helper.c
    qemu/target/sparc/cpu.c
    qemu/target/sparc/fop_helper.c
    qemu/target/sparc/helper.c
    qemu/target/sparc/int64_helper.c
    qemu/target/sparc/ldst_helper.c
    qemu/target/sparc/mmu_helper.c
    qemu/target/sparc/translate.c
    qemu/target/sparc/vis_helper.c
    qemu/target/sparc/win_helper.c
    qemu/target/sparc/unicorn64.c
)

if(MSVC)
    target_compile_options(sparc64-softmmu PRIVATE
        -DNEED_CPU_H
        /FIsparc64.h
        /I${CMAKE_CURRENT_SOURCE_DIR}/msvc/sparc64-softmmu
        /I${CMAKE_CURRENT_SOURCE_DIR}/qemu/target/sparc
    )
else()
    target_compile_options(sparc64-softmmu PRIVATE
        -DNEED_CPU_H
        -include sparc64.h
        -I${CMAKE_BINARY_DIR}/sparc64-softmmu
        -I${CMAKE_CURRENT_SOURCE_DIR}/qemu/target/sparc
    )
endif()

if(UNICORN_TRACER)
    target_compile_options(sparc64-softmmu PRIVATE -DUNICORN_TRACER)
endif()

endif()

if(UNICORN_HAS_PPC)
add_library(ppc-softmmu STATIC
    ${UNICORN_ARCH_COMMON}

    qemu/hw/ppc/ppc.c
    qemu/hw/ppc/ppc_booke.c

    qemu/libdecnumber/decContext.c
    qemu/libdecnumber/decNumber.c
    qemu/libdecnumber/dpd/decimal128.c
    qemu/libdecnumber/dpd/decimal32.c
    qemu/libdecnumber/dpd/decimal64.c

    qemu/target/ppc/cpu.c
    qemu/target/ppc/cpu-models.c
    qemu/target/ppc/dfp_helper.c
    qemu/target/ppc/excp_helper.c
    qemu/target/ppc/fpu_helper.c
    qemu/target/ppc/int_helper.c
    qemu/target/ppc/machine.c
    qemu/target/ppc/mem_helper.c
    qemu/target/ppc/misc_helper.c
    qemu/target/ppc/mmu-hash32.c
    qemu/target/ppc/mmu_helper.c
    qemu/target/ppc/timebase_helper.c
    qemu/target/ppc/translate.c
    qemu/target/ppc/unicorn.c
)

if(MSVC)
    target_compile_options(ppc-softmmu PRIVATE
        -DNEED_CPU_H
        /FIppc.h
        /I${CMAKE_CURRENT_SOURCE_DIR}/msvc/ppc-softmmu
        /I${CMAKE_CURRENT_SOURCE_DIR}/qemu/target/ppc
    )
else()
    target_compile_options(ppc-softmmu PRIVATE
        -DNEED_CPU_H
        -include ppc.h
        -I${CMAKE_BINARY_DIR}/ppc-softmmu
        -I${CMAKE_CURRENT_SOURCE_DIR}/qemu/target/ppc
    )
endif()

if(UNICORN_TRACER)
    target_compile_options(ppc-softmmu PRIVATE -DUNICORN_TRACER)
endif()

add_library(ppc64-softmmu STATIC
    ${UNICORN_ARCH_COMMON}

    qemu/hw/ppc/ppc.c
    qemu/hw/ppc/ppc_booke.c

    qemu/libdecnumber/decContext.c
    qemu/libdecnumber/decNumber.c
    qemu/libdecnumber/dpd/decimal128.c
    qemu/libdecnumber/dpd/decimal32.c
    qemu/libdecnumber/dpd/decimal64.c

    qemu/target/ppc/compat.c
    qemu/target/ppc/cpu.c
    qemu/target/ppc/cpu-models.c
    qemu/target/ppc/dfp_helper.c
    qemu/target/ppc/excp_helper.c
    qemu/target/ppc/fpu_helper.c
    qemu/target/ppc/int_helper.c
    qemu/target/ppc/machine.c
    qemu/target/ppc/mem_helper.c
    qemu/target/ppc/misc_helper.c
    qemu/target/ppc/mmu-book3s-v3.c
    qemu/target/ppc/mmu-hash32.c
    qemu/target/ppc/mmu-hash64.c
    qemu/target/ppc/mmu_helper.c
    qemu/target/ppc/mmu-radix64.c
    qemu/target/ppc/timebase_helper.c
    qemu/target/ppc/translate.c
    qemu/target/ppc/unicorn.c
)

if(MSVC)
    target_compile_options(ppc64-softmmu PRIVATE
        -DNEED_CPU_H
        /FIppc64.h
        /I${CMAKE_CURRENT_SOURCE_DIR}/msvc/ppc64-softmmu
        /I${CMAKE_CURRENT_SOURCE_DIR}/qemu/target/ppc
    )
else()
    target_compile_options(ppc64-softmmu PRIVATE
        -DNEED_CPU_H
        -include ppc64.h
        -I${CMAKE_BINARY_DIR}/ppc64-softmmu
        -I${CMAKE_CURRENT_SOURCE_DIR}/qemu/target/ppc
    )
endif()

if(UNICORN_TRACER)
    target_compile_options(ppc64-softmmu PRIVATE -DUNICORN_TRACER)
endif()

endif()

if(UNICORN_HAS_RISCV)
add_library(riscv32-softmmu STATIC
    ${UNICORN_ARCH_COMMON}

    qemu/target/riscv/cpu.c
    qemu/target/riscv/cpu_helper.c
    qemu/target/riscv/csr.c
    qemu/target/riscv/fpu_helper.c
    qemu/target/riscv/op_helper.c
    qemu/target/riscv/pmp.c
    qemu/target/riscv/translate.c
    qemu/target/riscv/unicorn.c
)

if(MSVC)
    target_compile_options(riscv32-softmmu PRIVATE
        -DNEED_CPU_H
        /FIriscv32.h
        /I${CMAKE_CURRENT_SOURCE_DIR}/msvc/riscv32-softmmu
        /I${CMAKE_CURRENT_SOURCE_DIR}/qemu/target/riscv
    )
else()
    target_compile_options(riscv32-softmmu PRIVATE
        -DNEED_CPU_H
        -include riscv32.h
        -I${CMAKE_BINARY_DIR}/riscv32-softmmu
        -I${CMAKE_CURRENT_SOURCE_DIR}/qemu/target/riscv
    )
endif()

if(UNICORN_TRACER)
    target_compile_options(riscv32-softmmu PRIVATE -DUNICORN_TRACER)
endif()

add_library(riscv64-softmmu STATIC
    ${UNICORN_ARCH_COMMON}

    qemu/target/riscv/cpu.c
    qemu/target/riscv/cpu_helper.c
    qemu/target/riscv/csr.c
    qemu/target/riscv/fpu_helper.c
    qemu/target/riscv/op_helper.c
    qemu/target/riscv/pmp.c
    qemu/target/riscv/translate.c
    qemu/target/riscv/unicorn.c
)

if(MSVC)
    target_compile_options(riscv64-softmmu PRIVATE
        -DNEED_CPU_H
        /FIriscv64.h
        /I${CMAKE_CURRENT_SOURCE_DIR}/msvc/riscv64-softmmu
        /I${CMAKE_CURRENT_SOURCE_DIR}/qemu/target/riscv
    )
else()
    target_compile_options(riscv64-softmmu PRIVATE
        -DNEED_CPU_H
        -include riscv64.h
        -I${CMAKE_BINARY_DIR}/riscv64-softmmu
        -I${CMAKE_CURRENT_SOURCE_DIR}/qemu/target/riscv
    )
endif()

if(UNICORN_TRACER)
    target_compile_options(riscv64-softmmu PRIVATE -DUNICORN_TRACER)
endif()

endif()

if (UNICORN_HAS_S390X)
add_library(s390x-softmmu STATIC
    ${UNICORN_ARCH_COMMON}

    qemu/hw/s390x/s390-skeys.c

    qemu/target/s390x/cc_helper.c
    qemu/target/s390x/cpu.c
    qemu/target/s390x/cpu_features.c
    qemu/target/s390x/cpu_models.c
    qemu/target/s390x/crypto_helper.c
    qemu/target/s390x/excp_helper.c
    qemu/target/s390x/fpu_helper.c
    qemu/target/s390x/helper.c
    qemu/target/s390x/interrupt.c
    qemu/target/s390x/int_helper.c
    qemu/target/s390x/ioinst.c
    qemu/target/s390x/mem_helper.c
    qemu/target/s390x/misc_helper.c
    qemu/target/s390x/mmu_helper.c
    qemu/target/s390x/sigp.c
    qemu/target/s390x/tcg-stub.c
    qemu/target/s390x/translate.c
    qemu/target/s390x/vec_fpu_helper.c
    qemu/target/s390x/vec_helper.c
    qemu/target/s390x/vec_int_helper.c
    qemu/target/s390x/vec_string_helper.c
    qemu/target/s390x/unicorn.c
)

if(MSVC)
    target_compile_options(s390x-softmmu PRIVATE
        -DNEED_CPU_H
        /FIs390x.h
        /I${CMAKE_CURRENT_SOURCE_DIR}/msvc/s390x-softmmu
        /I${CMAKE_CURRENT_SOURCE_DIR}/qemu/target/s390x
    )
else()
    target_compile_options(s390x-softmmu PRIVATE
        -DNEED_CPU_H
        -include s390x.h
        -I${CMAKE_BINARY_DIR}/s390x-softmmu
        -I${CMAKE_CURRENT_SOURCE_DIR}/qemu/target/s390x
    )
endif()
endif()


if (UNICORN_HAS_TRICORE)
add_library(tricore-softmmu STATIC
    ${UNICORN_ARCH_COMMON}

    qemu/target/tricore/cpu.c
    qemu/target/tricore/fpu_helper.c
    qemu/target/tricore/helper.c
    qemu/target/tricore/op_helper.c
    qemu/target/tricore/translate.c
    qemu/target/tricore/unicorn.c
)

if(MSVC)
    target_compile_options(tricore-softmmu PRIVATE
        -DNEED_CPU_H
        /FItricore.h
        /I${CMAKE_CURRENT_SOURCE_DIR}/msvc/tricore-softmmu
        /I${CMAKE_CURRENT_SOURCE_DIR}/qemu/target/tricore
    )
else()
    target_compile_options(tricore-softmmu PRIVATE
        -DNEED_CPU_H
        -include tricore.h
        -I${CMAKE_BINARY_DIR}/tricore-softmmu
        -I${CMAKE_CURRENT_SOURCE_DIR}/qemu/target/tricore
    )
endif()
endif()


set(UNICORN_SRCS
    uc.c

    qemu/softmmu/vl.c

    qemu/hw/core/cpu.c
)

set(UNICORN_COMMON_SRCS

    list.c

    glib_compat/glib_compat.c
    glib_compat/gtestutils.c
    glib_compat/garray.c
    glib_compat/gtree.c
    glib_compat/grand.c
    glib_compat/glist.c
    glib_compat/gmem.c
    glib_compat/gpattern.c
    glib_compat/gslice.c

    qemu/util/bitmap.c
    qemu/util/bitops.c
    qemu/util/crc32c.c
    qemu/util/cutils.c
    qemu/util/getauxval.c
    qemu/util/guest-random.c
    qemu/util/host-utils.c
    qemu/util/osdep.c
    qemu/util/qdist.c
    qemu/util/qemu-timer.c
    qemu/util/qemu-timer-common.c
    qemu/util/range.c
    qemu/util/qht.c
    qemu/util/pagesize.c
    qemu/util/cacheinfo.c

    qemu/crypto/aes.c
)

# A workaround to avoid circle dependency between unicorn and *-softmmu
if(MSVC)
    set(UNICORN_COMMON_SRCS
        ${UNICORN_COMMON_SRCS}
        qemu/util/oslib-win32.c
        qemu/util/qemu-thread-win32.c
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
        set(UNICORN_COMMON_SRCS ${UNICORN_COMMON_SRCS} qemu/util/setjmp-wrapper-win32.asm)
        set_property(SOURCE qemu/util/setjmp-wrapper-win32.asm PROPERTY LANGUAGE ASM_MASM)
    endif()
else()
    set(UNICORN_COMMON_SRCS
        ${UNICORN_COMMON_SRCS}
        qemu/util/oslib-posix.c
        qemu/util/qemu-thread-posix.c
    )
endif()

add_library(unicorn-common STATIC
    ${UNICORN_COMMON_SRCS}
)

set_target_properties(unicorn-common
                      PROPERTIES
                      C_VISIBILITY_PRESET
                      hidden)

if(NOT MSVC AND NOT ANDROID_ABI)
    target_link_libraries(unicorn-common PRIVATE pthread)
endif()

add_library(unicorn ${UNICORN_SRCS})
# For static archive
if (BUILD_SHARED_LIBS)
    add_library(unicorn_static STATIC ${UNICORN_SRCS})
endif()

if(BUILD_SHARED_LIBS)
    if(ANDROID_ABI)
        file(APPEND ${CMAKE_BINARY_DIR}/adb.sh "adb push ./libunicorn.so /data/local/tmp/build/\n")
    endif()
endif()

set(UNICORN_LINK_LIBRARIES ${UNICORN_LINK_LIBRARIES} unicorn-common)
if (ATOMIC_LINKAGE_FIX)
    set(UNICORN_COMPILE_OPTIONS ${UNICORN_COMPILE_OPTIONS} -latomic)
endif()
if(UNICORN_HAS_X86)
    set(UNICORN_COMPILE_OPTIONS ${UNICORN_COMPILE_OPTIONS} -DUNICORN_HAS_X86)
    set(UNICORN_LINK_LIBRARIES ${UNICORN_LINK_LIBRARIES} x86_64-softmmu)
    set(UNICORN_SAMPLE_FILE ${UNICORN_SAMPLE_FILE} sample_x86 sample_x86_32_gdt_and_seg_regs sample_batch_reg mem_apis shellcode sample_mmu)
    target_link_libraries(x86_64-softmmu PRIVATE unicorn-common)
    set(UNICORN_TEST_FILE ${UNICORN_TEST_FILE} test_x86)
endif()
if(UNICORN_HAS_ARM)
    set(UNICORN_COMPILE_OPTIONS ${UNICORN_COMPILE_OPTIONS} -DUNICORN_HAS_ARM)
    set(UNICORN_LINK_LIBRARIES ${UNICORN_LINK_LIBRARIES} arm-softmmu)
    set(UNICORN_SAMPLE_FILE ${UNICORN_SAMPLE_FILE} sample_arm)
    target_link_libraries(arm-softmmu PRIVATE unicorn-common)
    set(UNICORN_TEST_FILE ${UNICORN_TEST_FILE} test_arm)
endif()
if(UNICORN_HAS_AARCH64)
    set(UNICORN_COMPILE_OPTIONS ${UNICORN_COMPILE_OPTIONS} -DUNICORN_HAS_ARM64)
    set(UNICORN_LINK_LIBRARIES ${UNICORN_LINK_LIBRARIES} aarch64-softmmu)
    set(UNICORN_SAMPLE_FILE ${UNICORN_SAMPLE_FILE} sample_arm64)
    target_link_libraries(aarch64-softmmu PRIVATE unicorn-common)
    set(UNICORN_TEST_FILE ${UNICORN_TEST_FILE} test_arm64)
endif()
if(UNICORN_HAS_M68K)
    set(UNICORN_COMPILE_OPTIONS ${UNICORN_COMPILE_OPTIONS} -DUNICORN_HAS_M68K)
    set(UNICORN_LINK_LIBRARIES ${UNICORN_LINK_LIBRARIES} m68k-softmmu)
    set(UNICORN_SAMPLE_FILE ${UNICORN_SAMPLE_FILE} sample_m68k)
    target_link_libraries(m68k-softmmu PRIVATE unicorn-common)
    set(UNICORN_TEST_FILE ${UNICORN_TEST_FILE} test_m68k)
endif()
if(UNICORN_HAS_MIPS)
    set(UNICORN_COMPILE_OPTIONS ${UNICORN_COMPILE_OPTIONS} -DUNICORN_HAS_MIPS -DUNICORN_HAS_MIPSEL -DUNICORN_HAS_MIPS64 -DUNICORN_HAS_MIPS64EL)
    set(UNICORN_LINK_LIBRARIES ${UNICORN_LINK_LIBRARIES} mips-softmmu mipsel-softmmu mips64-softmmu mips64el-softmmu)
    set(UNICORN_SAMPLE_FILE ${UNICORN_SAMPLE_FILE} sample_mips)
    target_link_libraries(mips-softmmu PRIVATE unicorn-common)
    target_link_libraries(mipsel-softmmu PRIVATE unicorn-common)
    target_link_libraries(mips64-softmmu PRIVATE unicorn-common)
    target_link_libraries(mips64el-softmmu PRIVATE unicorn-common)
    set(UNICORN_TEST_FILE ${UNICORN_TEST_FILE} test_mips)
endif()
if(UNICORN_HAS_SPARC)
    set(UNICORN_COMPILE_OPTIONS ${UNICORN_COMPILE_OPTIONS} -DUNICORN_HAS_SPARC)
    set(UNICORN_LINK_LIBRARIES ${UNICORN_LINK_LIBRARIES} sparc-softmmu sparc64-softmmu)
    set(UNICORN_SAMPLE_FILE ${UNICORN_SAMPLE_FILE} sample_sparc)
    target_link_libraries(sparc-softmmu PRIVATE unicorn-common)
    target_link_libraries(sparc64-softmmu PRIVATE unicorn-common)
    set(UNICORN_TEST_FILE ${UNICORN_TEST_FILE} test_sparc)
endif()
if(UNICORN_HAS_PPC)
    set(UNICORN_COMPILE_OPTIONS ${UNICORN_COMPILE_OPTIONS} -DUNICORN_HAS_PPC)
    set(UNICORN_LINK_LIBRARIES ${UNICORN_LINK_LIBRARIES} ppc-softmmu ppc64-softmmu)
    set(UNICORN_SAMPLE_FILE ${UNICORN_SAMPLE_FILE} sample_ppc)
    target_link_libraries(ppc-softmmu PRIVATE unicorn-common)
    target_link_libraries(ppc64-softmmu PRIVATE unicorn-common)
    set(UNICORN_TEST_FILE ${UNICORN_TEST_FILE} test_ppc)
endif()
if(UNICORN_HAS_RISCV)
    set(UNICORN_COMPILE_OPTIONS ${UNICORN_COMPILE_OPTIONS} -DUNICORN_HAS_RISCV)
    set(UNICORN_LINK_LIBRARIES ${UNICORN_LINK_LIBRARIES} riscv32-softmmu riscv64-softmmu)
    set(UNICORN_SAMPLE_FILE ${UNICORN_SAMPLE_FILE} sample_riscv)
    target_link_libraries(riscv32-softmmu PRIVATE unicorn-common)
    target_link_libraries(riscv64-softmmu PRIVATE unicorn-common)
    set(UNICORN_TEST_FILE ${UNICORN_TEST_FILE} test_riscv)
endif()
if (UNICORN_HAS_S390X)
    set(UNICORN_COMPILE_OPTIONS ${UNICORN_COMPILE_OPTIONS} -DUNICORN_HAS_S390X)
    set(UNICORN_LINK_LIBRARIES ${UNICORN_LINK_LIBRARIES} s390x-softmmu)
    set(UNICORN_SAMPLE_FILE ${UNICORN_SAMPLE_FILE} sample_s390x)
    target_link_libraries(s390x-softmmu PRIVATE unicorn-common)
    set(UNICORN_TEST_FILE ${UNICORN_TEST_FILE} test_s390x)
endif()
if (UNICORN_HAS_TRICORE)
    set(UNICORN_COMPILE_OPTIONS ${UNICORN_COMPILE_OPTIONS} -DUNICORN_HAS_TRICORE)
    set(UNICORN_LINK_LIBRARIES ${UNICORN_LINK_LIBRARIES} tricore-softmmu)
    set(UNICORN_SAMPLE_FILE ${UNICORN_SAMPLE_FILE} sample_tricore)
    target_link_libraries(tricore-softmmu unicorn-common)
    set(UNICORN_TEST_FILE ${UNICORN_TEST_FILE} test_tricore)
endif()

# Extra tests
set(UNICORN_TEST_FILE ${UNICORN_TEST_FILE} test_mem)
set(UNICORN_TEST_FILE ${UNICORN_TEST_FILE} test_ctl)
set(UNICORN_SAMPLE_FILE ${UNICORN_SAMPLE_FILE} sample_ctl)

if(UNICORN_TRACER)
    target_compile_options(unicorn-common PRIVATE -DUNICORN_TRACER)
    target_compile_options(unicorn PRIVATE -DUNICORN_TRACER)
endif()

target_compile_options(unicorn-common PRIVATE
    ${UNICORN_COMPILE_OPTIONS}
)

target_compile_options(unicorn PRIVATE
    ${UNICORN_COMPILE_OPTIONS}
)

# For static archive
if (BUILD_SHARED_LIBS)
    target_compile_options(unicorn_static PRIVATE
        ${UNICORN_COMPILE_OPTIONS}
    )
endif()

if(MINGW)
    set(UNICORN_LINK_LIBRARIES ${UNICORN_LINK_LIBRARIES} pthread)
endif()

if(ATOMIC_LINKAGE_FIX)
    set(UNICORN_LINK_LIBRARIES ${UNICORN_LINK_LIBRARIES} atomic)
endif()

if(MSVC)
    if(BUILD_SHARED_LIBS)
        target_compile_options(unicorn PRIVATE
            -DUNICORN_SHARED
        )

        # For static archive
        target_link_libraries(unicorn_static PRIVATE
            ${UNICORN_LINK_LIBRARIES}
        )
    endif()

    target_link_libraries(unicorn PRIVATE
        ${UNICORN_LINK_LIBRARIES}
    )

    set_target_properties(unicorn PROPERTIES
        VERSION "${UNICORN_VERSION_MAJOR}.${UNICORN_VERSION_MINOR}"
    )
else()
    target_link_libraries(unicorn PRIVATE
        ${UNICORN_LINK_LIBRARIES}
        m
    )

    target_link_libraries(unicorn PUBLIC
        m
    )

    # For static archive
    if (BUILD_SHARED_LIBS)
        target_link_libraries(unicorn_static PUBLIC
            m
        )

        target_link_libraries(unicorn_static PRIVATE
            ${UNICORN_LINK_LIBRARIES}
            m
        )
    endif()

    set_target_properties(unicorn PROPERTIES
        VERSION ${UNICORN_VERSION_MAJOR}
        SOVERSION ${UNICORN_VERSION_MAJOR}
    )
endif()

if(MSVC)
    set(SAMPLES_LIB
        unicorn
    )
elseif(NOT ANDROID_ABI)
    set(SAMPLES_LIB
        unicorn
        pthread
    )
else()
    set(SAMPLES_LIB
        unicorn
    )
endif()

if(ATOMIC_LINKAGE_FIX)
    set(SAMPLES_LIB
        ${SAMPLES_LIB}
        atomic
    )
endif()

target_include_directories(unicorn PUBLIC
    include
)

# For static archive
if (BUILD_SHARED_LIBS)
    target_include_directories(unicorn_static PUBLIC
        include
    )
endif()

# Black magic for generating static archives...
if (BUILD_SHARED_LIBS)
    if (MSVC)
        # Avoid the import lib built by MVSC clash with our archive.
        set_target_properties(unicorn PROPERTIES ARCHIVE_OUTPUT_NAME "unicorn-import")
    endif()
    bundle_static_library(unicorn_static unicorn_archive unicorn)
else()
    # Rename the "static" lib to avoid filename clash.
    set_target_properties(unicorn PROPERTIES OUTPUT_NAME "unicorn-static")
    bundle_static_library(unicorn unicorn_archive unicorn)
endif()

if(UNICORN_FUZZ)
    set(UNICORN_FUZZ_SUFFIX "arm_arm;arm_armbe;arm_thumb;arm64_arm;arm64_armbe;m68k_be;mips_32be;mips_32le;sparc_32be;x86_16;x86_32;x86_64;s390x_be")
    if (NOT APPLE)
        set(SAMPLES_LIB ${SAMPLES_LIB} rt)
    endif()
    foreach(SUFFIX ${UNICORN_FUZZ_SUFFIX})
        add_executable(fuzz_emu_${SUFFIX}
            ${CMAKE_CURRENT_SOURCE_DIR}/tests/fuzz/fuzz_emu_${SUFFIX}.c
            ${CMAKE_CURRENT_SOURCE_DIR}/tests/fuzz/onedir.c
        )
        target_link_libraries(fuzz_emu_${SUFFIX} PRIVATE
            ${SAMPLES_LIB}
        )
    endforeach()
endif()

if(UNICORN_BUILD_TESTS)
    enable_testing()
    foreach(SAMPLE_FILE ${UNICORN_SAMPLE_FILE})
        add_executable(${SAMPLE_FILE}
            ${CMAKE_CURRENT_SOURCE_DIR}/samples/${SAMPLE_FILE}.c
        )
        target_link_libraries(${SAMPLE_FILE} PRIVATE
            ${SAMPLES_LIB}
        )
        endforeach()

        foreach(TEST_FILE ${UNICORN_TEST_FILE})
        add_executable(${TEST_FILE}
            ${CMAKE_CURRENT_SOURCE_DIR}/tests/unit/${TEST_FILE}.c
        )
        target_compile_options(${TEST_FILE} PRIVATE
            ${UNICORN_COMPILE_OPTIONS}
        )
        target_link_libraries(${TEST_FILE} PRIVATE
            ${SAMPLES_LIB}
        )
        add_test(${TEST_FILE} ${TEST_FILE})
        if(ANDROID_ABI)
            file(APPEND ${CMAKE_BINARY_DIR}/adb.sh "adb push ${TEST_FILE} /data/local/tmp/build/\n")
            file(APPEND ${CMAKE_BINARY_DIR}/adb.sh "adb shell \"chmod +x /data/local/tmp/build/${TEST_FILE}\"\n")
            file(APPEND ${CMAKE_BINARY_DIR}/adb.sh "adb shell \'LD_LIBRARY_PATH=/data/local/tmp/build:$LD_LIBRARY_PATH /data/local/tmp/build/${TEST_FILE}\' || exit -1\n")
        endif()
        if (UNICORN_TARGET_ARCH STREQUAL "aarch64" OR UNICORN_TARGET_ARCH STREQUAL "ppc")
            target_compile_definitions(${TEST_FILE} PRIVATE TARGET_READ_INLINED)
        endif()
    endforeach()
endif()


if(UNICORN_INSTALL AND NOT MSVC)
    include("GNUInstallDirs")
    file(GLOB UNICORN_HEADERS ${CMAKE_CURRENT_SOURCE_DIR}/include/unicorn/*.h)
    if (BUILD_SHARED_LIBS)
        install(TARGETS unicorn
            RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
            ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
            LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
        )
    endif()
    install(FILES $<TARGET_FILE:unicorn_archive> DESTINATION ${CMAKE_INSTALL_LIBDIR})
    install(FILES $<TARGET_FILE_DIR:unicorn_archive>/$<TARGET_PROPERTY:unicorn_archive,SYMLINK_NAME> DESTINATION ${CMAKE_INSTALL_LIBDIR})
    install(FILES ${UNICORN_HEADERS} DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/unicorn)
    if (ATOMIC_LINKAGE_FIX)
        set(ATOMIC_LINK_PKG_CONFIG " -latomic")
    else()
        set(ATOMIC_LINK_PKG_CONFIG "")
    endif()
    file(WRITE ${CMAKE_BINARY_DIR}/unicorn.pc "Name: unicorn\n\
Description: Unicorn emulator engine\n\
Version: ${UNICORN_VERSION_MAJOR}.${UNICORN_VERSION_MINOR}.${UNICORN_VERSION_PATCH}\n\
libdir=${CMAKE_INSTALL_FULL_LIBDIR}\n\
includedir=${CMAKE_INSTALL_FULL_INCLUDEDIR}\n\
Libs: -L\$\{libdir\} -lunicorn\n\
Libs.private: -lpthread -lm${ATOMIC_LINK_PKG_CONFIG}\n\
Cflags: -I\$\{includedir\}\n"
    )
    install(FILES ${CMAKE_BINARY_DIR}/unicorn.pc DESTINATION ${CMAKE_INSTALL_LIBDIR}/pkgconfig)
endif()
