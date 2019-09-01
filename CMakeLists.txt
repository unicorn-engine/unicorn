# Only tested in vs2019.
# Open the "x86 Native Tools Command Prompt for VS 2019",
# cd ${UNICORN_SOURCE_DIR}
# mkdir build
# cd build
# cmake -G "NMake Makefiles" ..
# nmake
# or Open "x64 Native Tools Command Prompt for VS 2019" for 64bit binary.
cmake_minimum_required(VERSION 3.1)
project(unicorn)

set(CMAKE_CXX_STANDARD 11)
set(CMAKE_C_STANDARD 11)

#set(CMAKE_BUILD_TYPE "Debug")
set(CMAKE_BUILD_TYPE "Release")

if(MSVC)
    include_directories(SYSTEM
        ${CMAKE_CURRENT_SOURCE_DIR}/msvc/unicorn
    )
else()
    include_directories(SYSTEM
        ${CMAKE_CURRENT_SOURCE_DIR}
    )
endif()

include_directories(SYSTEM
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
        /FI x86_64.h
        /I${CMAKE_CURRENT_SOURCE_DIR}/msvc/unicorn/x86_64-softmmu
        /I${CMAKE_CURRENT_SOURCE_DIR}/qemu/tcg/i386
        /I${CMAKE_CURRENT_SOURCE_DIR}/qemu/target-i386
        /wd4018 /wd4244 /wd4267
    )

    target_compile_definitions(x86_64-softmmu PRIVATE
        -D_CRT_SECURE_NO_WARNINGS
        -Dinline=__inline
        -D__func__=__FUNCTION__
        -DNEED_CPU_H
        -DWIN32_LEAN_AND_MEAN
        ${MSVC_FLAG}
    )
else()
    target_compile_options(x86_64-softmmu PRIVATE
        -include x86_64.h
        -I${CMAKE_CURRENT_SOURCE_DIR}/qemu/x86_64-softmmu
        -I${CMAKE_CURRENT_SOURCE_DIR}/qemu/tcg/i386
        -I${CMAKE_CURRENT_SOURCE_DIR}/qemu/target-i386
    )
    target_compile_definitions(x86_64-softmmu PRIVATE
        -DNEED_CPU_H
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
        /FI arm.h
        /I${CMAKE_CURRENT_SOURCE_DIR}/msvc/unicorn/arm-softmmu
        /I${CMAKE_CURRENT_SOURCE_DIR}/qemu/tcg/i386
        /I${CMAKE_CURRENT_SOURCE_DIR}/qemu/target-arm
        /wd4018 /wd4244 /wd4267
    )

    target_compile_definitions(arm-softmmu PRIVATE
        -D_CRT_SECURE_NO_WARNINGS
        -Dinline=__inline
        -D__func__=__FUNCTION__
        -DNEED_CPU_H
        -DWIN32_LEAN_AND_MEAN
        ${MSVC_FLAG}
    )
else()
    target_compile_options(arm-softmmu PRIVATE
        -include arm.h
        -I${CMAKE_CURRENT_SOURCE_DIR}/qemu/arm-softmmu
        -I${CMAKE_CURRENT_SOURCE_DIR}/qemu/tcg/i386
        -I${CMAKE_CURRENT_SOURCE_DIR}/qemu/target-arm
    )
    target_compile_definitions(arm-softmmu PRIVATE
        -DNEED_CPU_H
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
        /FI armeb.h
        /I${CMAKE_CURRENT_SOURCE_DIR}/msvc/unicorn/armeb-softmmu
        /I${CMAKE_CURRENT_SOURCE_DIR}/qemu/tcg/i386
        /I${CMAKE_CURRENT_SOURCE_DIR}/qemu/target-arm
        /wd4018 /wd4244 /wd4267
    )

    target_compile_definitions(armeb-softmmu PRIVATE
        -D_CRT_SECURE_NO_WARNINGS
        -Dinline=__inline
        -D__func__=__FUNCTION__
        -DNEED_CPU_H
        -DWIN32_LEAN_AND_MEAN
        ${MSVC_FLAG}
    )
else()
    target_compile_options(armeb-softmmu PRIVATE
        -include armeb.h
        -I${CMAKE_CURRENT_SOURCE_DIR}/qemu/armeb-softmmu
        -I${CMAKE_CURRENT_SOURCE_DIR}/qemu/tcg/i386
        -I${CMAKE_CURRENT_SOURCE_DIR}/qemu/target-arm
    )
    target_compile_definitions(armeb-softmmu PRIVATE
        -DNEED_CPU_H
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
        /FI aarch64.h
        /I${CMAKE_CURRENT_SOURCE_DIR}/msvc/unicorn/aarch64-softmmu
        /I${CMAKE_CURRENT_SOURCE_DIR}/qemu/tcg/i386
        /I${CMAKE_CURRENT_SOURCE_DIR}/qemu/target-arm
        /wd4018 /wd4244 /wd4267
    )

    target_compile_definitions(aarch64-softmmu PRIVATE
        -D_CRT_SECURE_NO_WARNINGS
        -Dinline=__inline
        -D__func__=__FUNCTION__
        -DNEED_CPU_H
        -DWIN32_LEAN_AND_MEAN
        ${MSVC_FLAG}
    )
else()
    target_compile_options(aarch64-softmmu PRIVATE
        -include aarch64.h
        -I${CMAKE_CURRENT_SOURCE_DIR}/qemu/aarch64-softmmu
        -I${CMAKE_CURRENT_SOURCE_DIR}/qemu/tcg/i386
        -I${CMAKE_CURRENT_SOURCE_DIR}/qemu/target-arm
    )
    target_compile_definitions(aarch64-softmmu PRIVATE
        -DNEED_CPU_H
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
        /FI aarch64eb.h
        /I${CMAKE_CURRENT_SOURCE_DIR}/msvc/unicorn/aarch64eb-softmmu
        /I${CMAKE_CURRENT_SOURCE_DIR}/qemu/tcg/i386
        /I${CMAKE_CURRENT_SOURCE_DIR}/qemu/target-arm
        /wd4018 /wd4244 /wd4267
    )

    target_compile_definitions(aarch64eb-softmmu PRIVATE
        -D_CRT_SECURE_NO_WARNINGS
        -Dinline=__inline
        -D__func__=__FUNCTION__
        -DNEED_CPU_H
        -DWIN32_LEAN_AND_MEAN
        ${MSVC_FLAG}
    )
else()
    target_compile_options(aarch64eb-softmmu PRIVATE
        -include aarch64eb.h
        -I${CMAKE_CURRENT_SOURCE_DIR}/qemu/aarch64eb-softmmu
        -I${CMAKE_CURRENT_SOURCE_DIR}/qemu/tcg/i386
        -I${CMAKE_CURRENT_SOURCE_DIR}/qemu/target-arm
    )
    target_compile_definitions(aarch64eb-softmmu PRIVATE
        -DNEED_CPU_H
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
        /FI m68k.h
        /I${CMAKE_CURRENT_SOURCE_DIR}/msvc/unicorn/m68k-softmmu
        /I${CMAKE_CURRENT_SOURCE_DIR}/qemu/tcg/i386
        /I${CMAKE_CURRENT_SOURCE_DIR}/qemu/target-m68k
        /wd4018 /wd4244 /wd4267
    )

    target_compile_definitions(m68k-softmmu PRIVATE
        -D_CRT_SECURE_NO_WARNINGS
        -Dinline=__inline
        -D__func__=__FUNCTION__
        -DNEED_CPU_H
        -DWIN32_LEAN_AND_MEAN
        ${MSVC_FLAG}
    )
else()
    target_compile_options(m68k-softmmu PRIVATE
        -include m68k.h
        -I${CMAKE_CURRENT_SOURCE_DIR}/qemu/m68k-softmmu
        -I${CMAKE_CURRENT_SOURCE_DIR}/qemu/tcg/i386
        -I${CMAKE_CURRENT_SOURCE_DIR}/qemu/target-m68k
    )
    target_compile_definitions(m68k-softmmu PRIVATE
        -DNEED_CPU_H
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
        /FI mips.h
        /I${CMAKE_CURRENT_SOURCE_DIR}/msvc/unicorn/mips-softmmu
        /I${CMAKE_CURRENT_SOURCE_DIR}/qemu/tcg/i386
        /I${CMAKE_CURRENT_SOURCE_DIR}/qemu/target-mips
        /wd4018 /wd4244 /wd4267
    )

    target_compile_definitions(mips-softmmu PRIVATE
        -D_CRT_SECURE_NO_WARNINGS
        -Dinline=__inline
        -D__func__=__FUNCTION__
        -DNEED_CPU_H
        -DWIN32_LEAN_AND_MEAN
        ${MSVC_FLAG}
    )
else()
    target_compile_options(mips-softmmu PRIVATE
        -include mips.h
        -I${CMAKE_CURRENT_SOURCE_DIR}/qemu/mips-softmmu
        -I${CMAKE_CURRENT_SOURCE_DIR}/qemu/tcg/i386
        -I${CMAKE_CURRENT_SOURCE_DIR}/qemu/target-mips
    )
    target_compile_definitions(mips-softmmu PRIVATE
        -DNEED_CPU_H
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
        /FI mipsel.h
        /I${CMAKE_CURRENT_SOURCE_DIR}/msvc/unicorn/mipsel-softmmu
        /I${CMAKE_CURRENT_SOURCE_DIR}/qemu/tcg/i386
        /I${CMAKE_CURRENT_SOURCE_DIR}/qemu/target-mips
        /wd4018 /wd4244 /wd4267
    )

    target_compile_definitions(mipsel-softmmu PRIVATE
        -D_CRT_SECURE_NO_WARNINGS
        -Dinline=__inline
        -D__func__=__FUNCTION__
        -DNEED_CPU_H
        -DWIN32_LEAN_AND_MEAN
        ${MSVC_FLAG}
    )
else()
    target_compile_options(mipsel-softmmu PRIVATE
        -include mipsel.h
        -I${CMAKE_CURRENT_SOURCE_DIR}/qemu/mipsel-softmmu
        -I${CMAKE_CURRENT_SOURCE_DIR}/qemu/tcg/i386
        -I${CMAKE_CURRENT_SOURCE_DIR}/qemu/target-mips
    )
    target_compile_definitions(mipsel-softmmu PRIVATE
        -DNEED_CPU_H
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
        /FI mips64.h
        /I${CMAKE_CURRENT_SOURCE_DIR}/msvc/unicorn/mips64-softmmu
        /I${CMAKE_CURRENT_SOURCE_DIR}/qemu/tcg/i386
        /I${CMAKE_CURRENT_SOURCE_DIR}/qemu/target-mips
        /wd4018 /wd4244 /wd4267
    )

    target_compile_definitions(mips64-softmmu PRIVATE
        -D_CRT_SECURE_NO_WARNINGS
        -Dinline=__inline
        -D__func__=__FUNCTION__
        -DNEED_CPU_H
        -DWIN32_LEAN_AND_MEAN
        ${MSVC_FLAG}
    )
else()
    target_compile_options(mips64-softmmu PRIVATE
        -include mips64.h
        -I${CMAKE_CURRENT_SOURCE_DIR}/qemu/mips64-softmmu
        -I${CMAKE_CURRENT_SOURCE_DIR}/qemu/tcg/i386
        -I${CMAKE_CURRENT_SOURCE_DIR}/qemu/target-mips
    )
    target_compile_definitions(mips64-softmmu PRIVATE
        -DNEED_CPU_H
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
        /FI mips64el.h
        /I${CMAKE_CURRENT_SOURCE_DIR}/msvc/unicorn/mips64el-softmmu
        /I${CMAKE_CURRENT_SOURCE_DIR}/qemu/tcg/i386
        /I${CMAKE_CURRENT_SOURCE_DIR}/qemu/target-mips
        /wd4018 /wd4244 /wd4267
    )

    target_compile_definitions(mips64el-softmmu PRIVATE
        -D_CRT_SECURE_NO_WARNINGS
        -Dinline=__inline
        -D__func__=__FUNCTION__
        -DNEED_CPU_H
        -DWIN32_LEAN_AND_MEAN
        ${MSVC_FLAG}
    )
else()
    target_compile_options(mips64el-softmmu PRIVATE
        -include mips64el.h
        -I${CMAKE_CURRENT_SOURCE_DIR}/qemu/mips64el-softmmu
        -I${CMAKE_CURRENT_SOURCE_DIR}/qemu/tcg/i386
        -I${CMAKE_CURRENT_SOURCE_DIR}/qemu/target-mips
    )
    target_compile_definitions(mips64el-softmmu PRIVATE
        -DNEED_CPU_H
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
        /FI sparc.h
        /I${CMAKE_CURRENT_SOURCE_DIR}/msvc/unicorn/sparc-softmmu
        /I${CMAKE_CURRENT_SOURCE_DIR}/qemu/tcg/i386
        /I${CMAKE_CURRENT_SOURCE_DIR}/qemu/target-sparc
        /wd4018 /wd4244 /wd4267
    )

    target_compile_definitions(sparc-softmmu PRIVATE
        -D_CRT_SECURE_NO_WARNINGS
        -Dinline=__inline
        -D__func__=__FUNCTION__
        -DNEED_CPU_H
        -DWIN32_LEAN_AND_MEAN
        ${MSVC_FLAG}
    )
else()
    target_compile_options(sparc-softmmu PRIVATE
        -include sparc.h
        -I${CMAKE_CURRENT_SOURCE_DIR}/qemu/sparc-softmmu
        -I${CMAKE_CURRENT_SOURCE_DIR}/qemu/tcg/i386
        -I${CMAKE_CURRENT_SOURCE_DIR}/qemu/target-sparc
    )
    target_compile_definitions(sparc-softmmu PRIVATE
        -DNEED_CPU_H
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
        /FI sparc64.h
        /I${CMAKE_CURRENT_SOURCE_DIR}/msvc/unicorn/sparc64-softmmu
        /I${CMAKE_CURRENT_SOURCE_DIR}/qemu/tcg/i386
        /I${CMAKE_CURRENT_SOURCE_DIR}/qemu/target-sparc
        /wd4018 /wd4244 /wd4267
    )

    target_compile_definitions(sparc64-softmmu PRIVATE
        -D_CRT_SECURE_NO_WARNINGS
        -Dinline=__inline
        -D__func__=__FUNCTION__
        -DNEED_CPU_H
        -DWIN32_LEAN_AND_MEAN
        ${MSVC_FLAG}
    )
else()
    target_compile_options(sparc64-softmmu PRIVATE
        -include sparc64.h
        -I${CMAKE_CURRENT_SOURCE_DIR}/qemu/sparc64-softmmu
        -I${CMAKE_CURRENT_SOURCE_DIR}/qemu/tcg/i386
        -I${CMAKE_CURRENT_SOURCE_DIR}/qemu/target-sparc
    )
    target_compile_definitions(sparc64-softmmu PRIVATE
        -DNEED_CPU_H
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
        ${CMAKE_CURRENT_SOURCE_DIR}/qemu/qapi-types.c
        ${CMAKE_CURRENT_SOURCE_DIR}/qemu/qapi-visit.c
    )
endif()

add_library(unicorn SHARED
    ${UNICORN_SRCS}
)

if(MSVC)
    target_compile_options(unicorn PRIVATE
        /wd4018 /wd4244 /wd4267
    )
    target_compile_definitions(unicorn PRIVATE
        -D_CRT_SECURE_NO_WARNINGS
        -Dinline=__inline
        -D__func__=__FUNCTION__
        -DWIN32_LEAN_AND_MEAN
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
        ${MSVC_FLAG}
    )
else()
    target_compile_options(unicorn PRIVATE
        -I${CMAKE_CURRENT_SOURCE_DIR}
    )
    target_compile_definitions(unicorn PRIVATE
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
endif()

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

add_executable(sample_x86
    ${CMAKE_CURRENT_SOURCE_DIR}/samples/sample_x86.c
)

target_link_libraries(sample_x86
    unicorn
)

add_executable(sample_arm
    ${CMAKE_CURRENT_SOURCE_DIR}/samples/sample_arm.c
)

target_link_libraries(sample_arm
    unicorn
)

add_executable(sample_armeb
    ${CMAKE_CURRENT_SOURCE_DIR}/samples/sample_armeb.c
)

target_link_libraries(sample_armeb
    unicorn
)

add_executable(sample_arm64
    ${CMAKE_CURRENT_SOURCE_DIR}/samples/sample_arm64.c
)

target_link_libraries(sample_arm64
    unicorn
)

add_executable(sample_arm64eb
    ${CMAKE_CURRENT_SOURCE_DIR}/samples/sample_arm64eb.c
)

target_link_libraries(sample_arm64eb
    unicorn
)

add_executable(sample_m68k
    ${CMAKE_CURRENT_SOURCE_DIR}/samples/sample_m68k.c
)

target_link_libraries(sample_m68k
    unicorn
)

add_executable(sample_mips
    ${CMAKE_CURRENT_SOURCE_DIR}/samples/sample_mips.c
)

target_link_libraries(sample_mips
    unicorn
)

add_executable(sample_sparc
    ${CMAKE_CURRENT_SOURCE_DIR}/samples/sample_sparc.c
)

target_link_libraries(sample_sparc
    unicorn
)


add_executable(sample_x86_32_gdt_and_seg_regs
    ${CMAKE_CURRENT_SOURCE_DIR}/samples/sample_x86_32_gdt_and_seg_regs.c
)

target_link_libraries(sample_x86_32_gdt_and_seg_regs
    unicorn
)

add_executable(sample_batch_reg
    ${CMAKE_CURRENT_SOURCE_DIR}/samples/sample_batch_reg.c
)

target_link_libraries(sample_batch_reg
    unicorn
)

add_executable(mem_apis
    ${CMAKE_CURRENT_SOURCE_DIR}/samples/mem_apis.c
)

target_link_libraries(mem_apis
    unicorn
)

add_executable(shellcode
    ${CMAKE_CURRENT_SOURCE_DIR}/samples/shellcode.c
)

target_link_libraries(shellcode
    unicorn
)
