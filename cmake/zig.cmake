set(CMAKE_CROSSCOMPILING TRUE)
# set the compiler
if(WIN32)
    SET(ZIG_CC ${CMAKE_SOURCE_DIR}/bindings/zig/tools/zigcc.cmd)
else()
    SET(ZIG_CC ${CMAKE_SOURCE_DIR}/bindings/zig/tools/zigcc.sh)
endif()
SET(CMAKE_C_COMPILER_ID ${ZIG_CC})
SET(CMAKE_C_COMPILER ${ZIG_CC})
