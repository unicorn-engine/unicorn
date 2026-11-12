set(UNICORN_ACUTEST_MODULE_DIR "${CMAKE_CURRENT_LIST_DIR}")

function(unicorn_discover_acutest target timeout labels allow_empty)
    if(ANDROID_ABI)
        file(APPEND ${CMAKE_BINARY_DIR}/adb.sh
            "adb shell 'LD_LIBRARY_PATH=/data/local/tmp/build:$LD_LIBRARY_PATH /data/local/tmp/build/${target}' || exit -1\n")
        return()
    endif()

    get_target_property(test_executor ${target} CROSSCOMPILING_EMULATOR)
    if(test_executor MATCHES "-NOTFOUND$")
        set(test_executor ${CMAKE_CROSSCOMPILING_EMULATOR})
    endif()
    if(CMAKE_CROSSCOMPILING AND NOT test_executor)
        message(STATUS
            "Skipping Acutest discovery for ${target}: "
            "no cross-compiling emulator is configured")
        return()
    endif()

    if(CMAKE_VERSION VERSION_LESS 3.10)
        set(test_command ${test_executor} $<TARGET_FILE:${target}>)
        add_test(NAME "unit.${target}" COMMAND ${test_command})
        set_tests_properties("unit.${target}" PROPERTIES
            LABELS "${labels}"
            TIMEOUT ${timeout}
        )
        return()
    endif()

    set(include_file
        "${CMAKE_CURRENT_BINARY_DIR}/${target}_include.cmake")
    get_property(generator_is_multi_config GLOBAL PROPERTY
        GENERATOR_IS_MULTI_CONFIG)
    if(generator_is_multi_config)
        set(tests_file
            "${CMAKE_CURRENT_BINARY_DIR}/${target}_tests-$<CONFIG>.cmake")
        set(byproducts_arg)
    else()
        set(tests_file
            "${CMAKE_CURRENT_BINARY_DIR}/${target}_tests.cmake")
        set(byproducts_arg BYPRODUCTS "${tests_file}")
    endif()
    set_property(TARGET ${target} APPEND PROPERTY LINK_DEPENDS
        "${UNICORN_ACUTEST_MODULE_DIR}/AcutestAddTests.cmake")
    add_custom_command(TARGET ${target} POST_BUILD
        ${byproducts_arg}
        COMMAND ${CMAKE_COMMAND}
            "-DTEST_TARGET=${target}"
            "-DTEST_EXECUTABLE=$<TARGET_FILE:${target}>"
            "-DTEST_EXECUTOR=${test_executor}"
            "-DTEST_TIMEOUT=${timeout}"
            "-DTEST_LABELS=${labels}"
            "-DTEST_ALLOW_EMPTY=${allow_empty}"
            "-DCTEST_FILE=${tests_file}"
            -P ${UNICORN_ACUTEST_MODULE_DIR}/AcutestAddTests.cmake
        VERBATIM
    )
    if(generator_is_multi_config)
        file(WRITE "${include_file}"
            "if(DEFINED CTEST_CONFIGURATION_TYPE AND NOT "
            "CTEST_CONFIGURATION_TYPE STREQUAL \"\")\n"
            "    if(EXISTS \"${CMAKE_CURRENT_BINARY_DIR}/${target}_tests-"
            "\${CTEST_CONFIGURATION_TYPE}.cmake\")\n"
            "        include(\"${CMAKE_CURRENT_BINARY_DIR}/${target}_tests-"
            "\${CTEST_CONFIGURATION_TYPE}.cmake\")\n"
            "    else()\n"
            "        add_test(unit.${target}_NOT_BUILT unit.${target}_NOT_BUILT)\n"
            "    endif()\n"
            "endif()\n"
        )
    else()
        file(WRITE "${include_file}"
            "if(EXISTS [==[${tests_file}]==])\n"
            "    include([==[${tests_file}]==])\n"
            "endif()\n"
        )
    endif()
    set_property(DIRECTORY APPEND PROPERTY TEST_INCLUDE_FILES
        "${include_file}")
endfunction()
