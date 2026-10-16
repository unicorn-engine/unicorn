function(acutest_quote value output)
    set(equals "=")
    string(FIND "${value}" "]${equals}]" closing_bracket)
    while(NOT closing_bracket EQUAL -1)
        set(equals "${equals}=")
        string(FIND "${value}" "]${equals}]" closing_bracket)
    endwhile()
    set(${output} "[${equals}[${value}]${equals}]" PARENT_SCOPE)
endfunction()

if(NOT EXISTS "${TEST_EXECUTABLE}")
    message(FATAL_ERROR "Acutest executable does not exist: ${TEST_EXECUTABLE}")
endif()

execute_process(
    COMMAND ${TEST_EXECUTOR} "${TEST_EXECUTABLE}" --list
    TIMEOUT 30
    OUTPUT_VARIABLE test_output
    ERROR_VARIABLE test_error
    RESULT_VARIABLE test_result
)
if(NOT test_result EQUAL 0)
    message(FATAL_ERROR
        "Acutest discovery failed for ${TEST_TARGET}: ${test_error}")
endif()

string(REPLACE "\r\n" "\n" test_output "${test_output}")
string(REPLACE "\r" "\n" test_output "${test_output}")
string(REPLACE ";" "\\;" test_output "${test_output}")
string(REPLACE "\n" ";" test_names "${test_output}")

set(discovered_names)
set(test_script "")
foreach(test_name ${test_names})
    string(STRIP "${test_name}" test_name)
    if(test_name STREQUAL "" OR test_name STREQUAL "Unit tests:")
        continue()
    endif()
    list(FIND discovered_names "${test_name}" duplicate_index)
    if(NOT duplicate_index EQUAL -1)
        message(FATAL_ERROR
            "Duplicate Acutest case ${test_name} in ${TEST_TARGET}")
    endif()
    list(APPEND discovered_names "${test_name}")

    set(ctest_name "unit.${TEST_TARGET}.${test_name}")
    acutest_quote("${ctest_name}" quoted_ctest_name)
    acutest_quote("${TEST_EXECUTABLE}" quoted_executable)
    acutest_quote("${test_name}" quoted_test_name)
    acutest_quote("${TEST_LABELS}" quoted_labels)

    set(quoted_executor "")
    foreach(executor_argument ${TEST_EXECUTOR})
        acutest_quote("${executor_argument}" quoted_argument)
        set(quoted_executor "${quoted_executor} ${quoted_argument}")
    endforeach()

    set(test_script "${test_script}add_test(${quoted_ctest_name}${quoted_executor} ${quoted_executable} ${quoted_test_name})\n")
    set(test_script "${test_script}set_tests_properties(${quoted_ctest_name} PROPERTIES LABELS ${quoted_labels} TIMEOUT ${TEST_TIMEOUT})\n")
endforeach()

if(NOT discovered_names)
    if(NOT TEST_ALLOW_EMPTY)
        message(FATAL_ERROR
            "Acutest discovery found no cases in ${TEST_TARGET}")
    endif()
    message(STATUS "Acutest discovery found no cases in ${TEST_TARGET}")
endif()

set(temporary_file "${CTEST_FILE}.tmp")
file(WRITE "${temporary_file}" "${test_script}")
file(RENAME "${temporary_file}" "${CTEST_FILE}")
