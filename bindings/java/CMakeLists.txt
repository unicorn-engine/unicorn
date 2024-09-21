cmake_minimum_required(VERSION 3.1)

find_package(JNI)

if (JNI_FOUND)
    message (STATUS "JNI_INCLUDE_DIRS=${JNI_INCLUDE_DIRS}")
    message (STATUS "JNI_LIBRARIES=${JNI_LIBRARIES}")
else()
message(FATAL_ERROR "JNI not found, please try to update JAVA_HOME accordingly")
endif()

add_library(unicorn_java SHARED unicorn_Unicorn.c)

message("${CMAKE_CURRENT_SOURCE_DIR}/bindings/java/target/headers")

if (NOT EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/target/headers")
    message(FATAL_ERROR "bindings/java/target/headers not generated, please generate them firstly")
endif()

target_include_directories(unicorn_java PRIVATE target/headers ${JNI_INCLUDE_DIRS})
target_link_libraries(unicorn_java PRIVATE unicorn ${JNI_LIBRARIES})