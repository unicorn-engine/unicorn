cmake_minimum_required(VERSION 3.1)
project(unicorn)

set(CMAKE_CXX_STANDARD 11)
set(CMAKE_C_STANDARD 11)

if(MSVC)
  include_directories(SYSTEM
    ${CMAKE_CURRENT_SOURCE_DIR}/cmake/win
  )
else()
  # GCC or Clang
  include_directories(SYSTEM
    ${CMAKE_CURRENT_SOURCE_DIR}/cmake/nix
  )
endif()
include_directories(SYSTEM
  qemu
  qemu/include
  qemu/tcg
  qemu/tcg/i386
  qemu/target-i386
  include
)

set(SOFTMMU_HEADERS
  qemu/fpu/softfloat-macros.h
  qemu/fpu/softfloat-specialize.h
  qemu/target-i386/cc_helper_template.h
  qemu/target-i386/cpu-qom.h
  qemu/target-i386/cpu.h
  qemu/target-i386/helper.h
  qemu/target-i386/ops_sse.h
  qemu/target-i386/ops_sse_header.h
  qemu/target-i386/shift_helper_template.h
  qemu/target-i386/svm.h
  qemu/target-i386/topology.h
  qemu/target-i386/unicorn.h
  qemu/tcg/i386/tcg-target.h
  qemu/tcg/tcg-be-ldst.h
  qemu/tcg/tcg-be-null.h
  qemu/tcg/tcg-op.h
  qemu/tcg/tcg-opc.h
  qemu/tcg/tcg-runtime.h
  qemu/tcg/tcg.h
  qemu/x86_64.h
  ${CMAKE_CURRENT_SOURCE_DIR}/cmake/x86_64-softmmu/config-target.h
)

set(SOFTMMU_SRCS
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
#  qemu/tcg/i386/tcg-target.c
  qemu/tcg/optimize.c
  qemu/tcg/tcg.c
  qemu/translate-all.c
)

add_library(x86_64softmmu
  ${SOFTMMU_HEADERS}
  ${SOFTMMU_SRCS}
)

if(MSVC)
  target_compile_options(x86_64softmmu PRIVATE /FI"x86_64.h"
    /I"${CMAKE_CURRENT_SOURCE_DIR}/cmake/x86_64-softmmu"
    "/MT$<$<CONFIG:Debug>:d>"
    /wd4018 /wd4244 /wd4267
  )

  target_compile_definitions(x86_64softmmu PRIVATE
    -D_CRT_SECURE_NO_WARNINGS
    -D_LIB
    -D__i386__
    -Dinline=__inline
    -D__func__=__FUNCTION__
    -DNEED_CPU_H
    -DWIN32_LEAN_AND_MEAN
  )
else()
  # GCC or Clang
  target_compile_options(x86_64softmmu PRIVATE
    "-includex86_64.h"
    "-I${CMAKE_CURRENT_SOURCE_DIR}/cmake/x86_64-softmmu"
  )
  target_compile_definitions(x86_64softmmu PRIVATE
    -D_LIB
    -DNEED_CPU_H
  )
endif()

set(UNICORN_HEADERS
  include/list.h
  include/qemu.h
  include/uc_priv.h
  include/unicorn/arm.h
  include/unicorn/arm64.h
  include/unicorn/m68k.h
  include/unicorn/mips.h
  include/unicorn/platform.h
  include/unicorn/sparc.h
  include/unicorn/unicorn.h
  include/unicorn/x86.h
  qemu/include/config.h
  qemu/include/elf.h
  qemu/include/exec/address-spaces.h
  qemu/include/exec/cpu-all.h
  qemu/include/exec/cpu-common.h
  qemu/include/exec/cpu-defs.h
  qemu/include/exec/cputlb.h
  qemu/include/exec/cpu_ldst.h
  qemu/include/exec/cpu_ldst_template.h
  qemu/include/exec/exec-all.h
  qemu/include/exec/gen-icount.h
  qemu/include/exec/helper-gen.h
  qemu/include/exec/helper-head.h
  qemu/include/exec/helper-proto.h
  qemu/include/exec/helper-tcg.h
  qemu/include/exec/hwaddr.h
  qemu/include/exec/ioport.h
  qemu/include/exec/memory-internal.h
  qemu/include/exec/memory.h
  qemu/include/exec/ram_addr.h
  qemu/include/fpu/softfloat.h
  qemu/include/glib_compat.h
  qemu/include/hw/arm/arm.h
  qemu/include/hw/boards.h
  qemu/include/hw/cpu/icc_bus.h
  qemu/include/hw/hw.h
  qemu/include/hw/i386/apic.h
  qemu/include/hw/i386/apic_internal.h
  qemu/include/hw/i386/pc.h
  qemu/include/hw/m68k/m68k.h
  qemu/include/hw/mips/cpudevs.h
  qemu/include/hw/mips/mips.h
  qemu/include/hw/qdev-core.h
  qemu/include/hw/qdev.h
  qemu/include/hw/sparc/sparc.h
  qemu/include/qapi/dealloc-visitor.h
  qemu/include/qapi/error.h
  qemu/include/qapi/qmp-input-visitor.h
  qemu/include/qapi/qmp-output-visitor.h
  qemu/include/qapi/qmp/qbool.h
  qemu/include/qapi/qmp/qdict.h
  qemu/include/qapi/qmp/qerror.h
  qemu/include/qapi/qmp/qfloat.h
  qemu/include/qapi/qmp/qint.h
  qemu/include/qapi/qmp/qjson.h
  qemu/include/qapi/qmp/qlist.h
  qemu/include/qapi/qmp/qobject.h
  qemu/include/qapi/qmp/qstring.h
  qemu/include/qapi/qmp/types.h
  qemu/include/qapi/string-input-visitor.h
  qemu/include/qapi/visitor-impl.h
  qemu/include/qapi/visitor.h
  qemu/include/qemu-common.h
  qemu/include/qemu/aes.h
  qemu/include/qemu/atomic.h
  qemu/include/qemu/bitmap.h
  qemu/include/qemu/bitops.h
  qemu/include/qemu/bswap.h
  qemu/include/qemu/compiler.h
  qemu/include/qemu/crc32c.h
  qemu/include/qemu/host-utils.h
  qemu/include/qemu/int128.h
  qemu/include/qemu/log.h
  qemu/include/qemu/module.h
  qemu/include/qemu/osdep.h
  qemu/include/qemu/queue.h
  qemu/include/qemu/range.h
  qemu/include/qemu/thread-posix.h
  qemu/include/qemu/thread-win32.h
  qemu/include/qemu/thread.h
  qemu/include/qemu/timer.h
  qemu/include/qemu/typedefs.h
  qemu/include/qom/cpu.h
  qemu/include/qom/object.h
  qemu/include/qom/qom-qobject.h
  qemu/include/sysemu/accel.h
  qemu/include/sysemu/cpus.h
  qemu/include/sysemu/memory_mapping.h
  qemu/include/sysemu/os-win32.h
  qemu/include/sysemu/sysemu.h
  qemu/vl.h
)

set(UNICORN_SRCS
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
  set(UNICORN_SRCS ${UNICORN_SRCS}
    qemu/util/oslib-win32.c
    qemu/util/qemu-thread-win32.c
    qemu/util/qemu-error.c

    ${CMAKE_CURRENT_SOURCE_DIR}/cmake/win/qapi-types.c
    ${CMAKE_CURRENT_SOURCE_DIR}/cmake/win/qapi-visit.c

    ${CMAKE_CURRENT_SOURCE_DIR}/cmake/win/config-host.h
    ${CMAKE_CURRENT_SOURCE_DIR}/cmake/win/qapi-types.h
    ${CMAKE_CURRENT_SOURCE_DIR}/cmake/win/qapi-visit.h
  )
else()
  # GCC or Clang
  set(UNICORN_SRCS ${UNICORN_SRCS}
    qemu/util/oslib-posix.c
    qemu/util/qemu-thread-posix.c

    ${CMAKE_CURRENT_SOURCE_DIR}/cmake/nix/qapi-types.c
    ${CMAKE_CURRENT_SOURCE_DIR}/cmake/nix/qapi-visit.c

    ${CMAKE_CURRENT_SOURCE_DIR}/cmake/nix/config-host.h
    ${CMAKE_CURRENT_SOURCE_DIR}/cmake/nix/qapi-types.h
    ${CMAKE_CURRENT_SOURCE_DIR}/cmake/nix/qapi-visit.h
  )
endif()

add_library(unicorn-static
  ${UNICORN_HEADERS}
  ${UNICORN_SRCS}
)

if(MSVC)
  # MBCS?
  target_compile_options(unicorn-static PRIVATE
    "/MT$<$<CONFIG:Debug>:d>"
    /wd4018 /wd4244 /wd4267
  )
  target_compile_definitions(unicorn-static PRIVATE
    -D_LIB
    -D_CRT_SECURE_NO_WARNINGS
    -Dinline=__inline
    -D__func__=__FUNCTION__
    -D__i386__
#   -DUNICORN_HAS_ARM
#   -DUNICORN_HAS_ARM64
#   -DUNICORN_HAS_M68K
#   -DUNICORN_HAS_MIPS
#   -DUNICORN_HAS_MIPS64
#   -DUNICORN_HAS_MIPSEL
#   -DUNICORN_HAS_MIPS64EL
#   -DUNICORN_HAS_SPARC
    -DUNICORN_HAS_X86
    -DWIN32_LEAN_AND_MEAN
    -D_MBCS
  )
else()
  # GCC or Clang
  target_compile_options(unicorn-static PRIVATE
    "-includex86_64.h"
    "-I${CMAKE_CURRENT_SOURCE_DIR}/cmake/nix"
  )
  target_compile_definitions(unicorn-static PRIVATE
    -D_LIB
#   -DUNICORN_HAS_ARM
#   -DUNICORN_HAS_ARM64
#   -DUNICORN_HAS_M68K
#   -DUNICORN_HAS_MIPS
#   -DUNICORN_HAS_MIPS64
#   -DUNICORN_HAS_MIPSEL
#   -DUNICORN_HAS_MIPS64EL
#   -DUNICORN_HAS_SPARC
    -DUNICORN_HAS_X86
  )
endif()

target_link_libraries(unicorn-static
  x86_64softmmu
)