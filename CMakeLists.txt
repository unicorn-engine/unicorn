# Tested on window10(x64) with vs2019.
# Open the "x86 Native Tools Command Prompt for VS 2019",
# cd ${UNICORN_SOURCE_DIR}
# mkdir build
# cd build
# cmake -G "NMake Makefiles" ..
# nmake
# Or Open "x64 Native Tools Command Prompt for VS 2019" for 64bit binary.
# Tested on Ubuntu-1804-amd64 with gcc.
# cd ${UNICORN_SOURCE_DIR}
# mkdir build
# cd build
# cmake ..
# make
# By Huitao Chen, 2019
cmake_minimum_required(VERSION 3.1)
project(unicorn C)

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
        set(MSVC_FLAG  -D__x86_64__)
    elseif(CMAKE_SIZEOF_VOID_P EQUAL 4)
        set(MSVC_FLAG  -D__i386__)
    else()
        message(FATAL_ERROR "Neither WIN64 or WIN32!")
    endif()
    add_compile_options(
        -D_CRT_SECURE_NO_WARNINGS
        -DWIN32_LEAN_AND_MEAN
        ${MSVC_FLAG}
        /I${CMAKE_CURRENT_SOURCE_DIR}/qemu/tcg/i386
        /wd4018 /wd4244 /wd4267
    )
    if(CMAKE_BUILD_TYPE STREQUAL "Debug")
        string(REPLACE "/ZI" "/Zi" CMAKE_C_FLAGS_DEBUG ${CMAKE_C_FLAGS_DEBUG})
    endif()
else()
# check python
    find_program(PYTHON_CMD python)
    if (NOT PYTHON_CMD)
        message(FATAL_ERROR "Please install python.")
    endif()
# GEN dynamic source files
    execute_process(COMMAND sh ${CMAKE_CURRENT_SOURCE_DIR}/qemu/configure
        "--extra-cflags=-DUNICORN_HAS_X86 \
            -DUNICORN_HAS_ARM -DUNICORN_HAS_ARMEB \
            -DUNICORN_HAS_ARM64 -DUNICORN_HAS_ARM64EB \
            -DUNICORN_HAS_M68K \
            -DUNICORN_HAS_MIPS -DUNICORN_HAS_MIPSEL \
            -DUNICORN_HAS_MIPS64 -DUNICORN_HAS_MIPS64EL \
            -DUNICORN_HAS_SPARC \
            -fPIC -fvisibility=hidden"
        "--target-list=x86_64-softmmu, \
            arm-softmmu, armeb-softmmu, \
            aarch64-softmmu, aarch64eb-softmmu, \
            m68k-softmmu, \
            mips-softmmu, mipsel-softmmu, \
            mips64-softmmu, mips64el-softmmu, \
            sparc-softmmu, sparc64-softmmu"
    )
    execute_process(COMMAND sh ${CMAKE_CURRENT_SOURCE_DIR}/qemu/scripts/create_config
        INPUT_FILE ${CMAKE_BINARY_DIR}/config-host.mak
        OUTPUT_FILE ${CMAKE_BINARY_DIR}/config-host.h
    )
    execute_process(COMMAND sh ${CMAKE_CURRENT_SOURCE_DIR}/qemu/scripts/create_config
        INPUT_FILE ${CMAKE_BINARY_DIR}/x86_64-softmmu/config-target.mak
        OUTPUT_FILE ${CMAKE_BINARY_DIR}/x86_64-softmmu/config-target.h
    )
    execute_process(COMMAND sh ${CMAKE_CURRENT_SOURCE_DIR}/qemu/scripts/create_config
        INPUT_FILE ${CMAKE_BINARY_DIR}/arm-softmmu/config-target.mak
        OUTPUT_FILE ${CMAKE_BINARY_DIR}/arm-softmmu/config-target.h
    )
    execute_process(COMMAND sh ${CMAKE_CURRENT_SOURCE_DIR}/qemu/scripts/create_config
        INPUT_FILE ${CMAKE_BINARY_DIR}/armeb-softmmu/config-target.mak
        OUTPUT_FILE ${CMAKE_BINARY_DIR}/armeb-softmmu/config-target.h
    )
    execute_process(COMMAND sh ${CMAKE_CURRENT_SOURCE_DIR}/qemu/scripts/create_config
        INPUT_FILE ${CMAKE_BINARY_DIR}/aarch64-softmmu/config-target.mak
        OUTPUT_FILE ${CMAKE_BINARY_DIR}/aarch64-softmmu/config-target.h
    )
    execute_process(COMMAND sh ${CMAKE_CURRENT_SOURCE_DIR}/qemu/scripts/create_config
        INPUT_FILE ${CMAKE_BINARY_DIR}/aarch64eb-softmmu/config-target.mak
        OUTPUT_FILE ${CMAKE_BINARY_DIR}/aarch64eb-softmmu/config-target.h
    )
    execute_process(COMMAND sh ${CMAKE_CURRENT_SOURCE_DIR}/qemu/scripts/create_config
        INPUT_FILE ${CMAKE_BINARY_DIR}/m68k-softmmu/config-target.mak
        OUTPUT_FILE ${CMAKE_BINARY_DIR}/m68k-softmmu/config-target.h
    )
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
    execute_process(COMMAND sh ${CMAKE_CURRENT_SOURCE_DIR}/qemu/scripts/create_config
        INPUT_FILE ${CMAKE_BINARY_DIR}/sparc-softmmu/config-target.mak
        OUTPUT_FILE ${CMAKE_BINARY_DIR}/sparc-softmmu/config-target.h
    )
    execute_process(COMMAND sh ${CMAKE_CURRENT_SOURCE_DIR}/qemu/scripts/create_config
        INPUT_FILE ${CMAKE_BINARY_DIR}/sparc64-softmmu/config-target.mak
        OUTPUT_FILE ${CMAKE_BINARY_DIR}/sparc64-softmmu/config-target.h
    )
    execute_process(COMMAND python -B ${CMAKE_CURRENT_SOURCE_DIR}/qemu/scripts/qapi-types.py
        -h -o ${CMAKE_BINARY_DIR} -b -i ${CMAKE_CURRENT_SOURCE_DIR}/qemu/qapi-schema.json
    )
    execute_process(COMMAND python -B ${CMAKE_CURRENT_SOURCE_DIR}/qemu/scripts/qapi-types.py
        -c -o ${CMAKE_BINARY_DIR} -b -i ${CMAKE_CURRENT_SOURCE_DIR}/qemu/qapi-schema.json
    )
    execute_process(COMMAND python -B ${CMAKE_CURRENT_SOURCE_DIR}/qemu/scripts/qapi-visit.py
        -h -o ${CMAKE_BINARY_DIR} -b -i ${CMAKE_CURRENT_SOURCE_DIR}/qemu/qapi-schema.json
    )
    execute_process(COMMAND python -B ${CMAKE_CURRENT_SOURCE_DIR}/qemu/scripts/qapi-visit.py
        -c -o ${CMAKE_BINARY_DIR} -b -i ${CMAKE_CURRENT_SOURCE_DIR}/qemu/qapi-schema.json
    )
    add_compile_options(
        -I${CMAKE_CURRENT_SOURCE_DIR}/qemu/tcg/i386
        -D_GNU_SOURCE
        -D_FILE_OFFSET_BITS=64
        -D_LARGEFILE_SOURCE
        -Wall -O2
        -fPIC -fpic -fvisibility=hidden
    )
endif()

add_library(x86_64-softmmu
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
        /FI x86_64.h
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

add_library(arm-softmmu
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
        /FI arm.h
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

add_library(armeb-softmmu
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
        /FI armeb.h
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

add_library(aarch64-softmmu
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
        /FI aarch64.h
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

add_library(aarch64eb-softmmu
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
        /FI aarch64eb.h
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

add_library(m68k-softmmu
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
        /FI m68k.h
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

add_library(mips-softmmu
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
        /FI mips.h
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

add_library(mipsel-softmmu
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
        /FI mipsel.h
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

add_library(mips64-softmmu
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
        /FI mips64.h
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

add_library(mips64el-softmmu
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
        /FI mips64el.h
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

add_library(sparc-softmmu
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
        /FI sparc.h
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

add_library(sparc64-softmmu
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
        /FI sparc64.h
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

if (MSVC)
    set(UNICORN_SRCS
        ${UNICORN_SRCS_COMMON}
        qemu/util/oslib-win32.c
        qemu/util/qemu-thread-win32.c
        qemu/util/qemu-error.c
        ${CMAKE_CURRENT_SOURCE_DIR}/msvc/unicorn/qapi-types.c
        ${CMAKE_CURRENT_SOURCE_DIR}/msvc/unicorn/qapi-visit.c
    )
else()
    set(UNICORN_SRCS
        ${UNICORN_SRCS_COMMON}
        qemu/util/oslib-posix.c
        qemu/util/qemu-thread-posix.c
        ${CMAKE_BINARY_DIR}/qapi-types.c
        ${CMAKE_BINARY_DIR}/qapi-visit.c
    )
endif()

add_library(unicorn SHARED
    ${UNICORN_SRCS}
)

if(MSVC)
    target_compile_options(unicorn PRIVATE
        -DUNICORN_HAS_ARM
        -DUNICORN_HAS_ARM64
        -DUNICORN_HAS_M68K
        -DUNICORN_HAS_MIPS
        -DUNICORN_HAS_MIPS64
        -DUNICORN_HAS_MIPSEL
        -DUNICORN_HAS_MIPS64EL
        -DUNICORN_HAS_SPARC
        -DUNICORN_HAS_X86
        -DUNICORN_SHARED
    )
    target_link_libraries(unicorn
        arm-softmmu
        armeb-softmmu
        aarch64-softmmu
        aarch64eb-softmmu
        m68k-softmmu
        mips-softmmu
        mipsel-softmmu
        mips64-softmmu
        mips64el-softmmu
        sparc-softmmu
        sparc64-softmmu
        x86_64-softmmu
    )
else()
    target_compile_options(unicorn PRIVATE
        -DUNICORN_HAS_ARM
        -DUNICORN_HAS_ARM64
        -DUNICORN_HAS_M68K
        -DUNICORN_HAS_MIPS
        -DUNICORN_HAS_MIPS64
        -DUNICORN_HAS_MIPSEL
        -DUNICORN_HAS_MIPS64EL
        -DUNICORN_HAS_SPARC
        -DUNICORN_HAS_X86
    )
    set_target_properties(unicorn PROPERTIES VERSION 1 SOVERSION 1)
    target_link_libraries(unicorn
        arm-softmmu
        armeb-softmmu
        aarch64-softmmu
        aarch64eb-softmmu
        m68k-softmmu
        mips-softmmu
        mipsel-softmmu
        mips64-softmmu
        mips64el-softmmu
        sparc-softmmu
        sparc64-softmmu
        x86_64-softmmu
        m
    )
endif()

if(MSVC)
    set(SAMPLES_LIB
        unicorn
    )
else()
    set(SAMPLES_LIB
        unicorn
        pthread
    )
endif()

foreach(SAMPLE_FILE
    sample_x86
    sample_arm
    sample_armeb
    sample_arm64
    sample_arm64eb
    sample_m68k
    sample_mips
    sample_sparc
    sample_x86_32_gdt_and_seg_regs
    sample_batch_reg
    mem_apis
    shellcode
)
    add_executable(${SAMPLE_FILE}
        ${CMAKE_CURRENT_SOURCE_DIR}/samples/${SAMPLE_FILE}.c
    )

    target_link_libraries(${SAMPLE_FILE}
        ${SAMPLES_LIB}
    )
endforeach(SAMPLE_FILE)
