# https://cristianadam.eu/20190501/bundling-together-static-libraries-with-cmake/
function(bundle_static_library tgt_name bundled_tgt_name library_name)
  list(APPEND static_libs ${tgt_name})
  set(dep_libs "")

  function(_recursively_collect_dependencies input_target)
    set(_input_link_libraries LINK_LIBRARIES)
    get_target_property(_input_type ${input_target} TYPE)
    if (${_input_type} STREQUAL "INTERFACE_LIBRARY")
      set(_input_link_libraries INTERFACE_LINK_LIBRARIES)
    endif()
    get_target_property(public_dependencies ${input_target} ${_input_link_libraries})
    foreach(dependency IN LISTS public_dependencies)
      if(TARGET ${dependency})
        get_target_property(alias ${dependency} ALIASED_TARGET)
        if (TARGET ${alias})
          set(dependency ${alias})
        endif()
        get_target_property(_type ${dependency} TYPE)
        if (${_type} STREQUAL "STATIC_LIBRARY")
          list(APPEND static_libs ${dependency})
        endif()

        get_property(library_already_added
          GLOBAL PROPERTY _${tgt_name}_static_bundle_${dependency})
        if (NOT library_already_added)
          set_property(GLOBAL PROPERTY _${tgt_name}_static_bundle_${dependency} ON)
          _recursively_collect_dependencies(${dependency})
        endif()
      elseif(dependency)
        list(APPEND dep_libs ${dependency})
      endif()
    endforeach()
    set(static_libs ${static_libs} PARENT_SCOPE)
    set(dep_libs ${dep_libs} PARENT_SCOPE)
  endfunction()

  _recursively_collect_dependencies(${tgt_name})

  list(REMOVE_DUPLICATES static_libs)
  list(REMOVE_DUPLICATES dep_libs)

  foreach(tgt IN LISTS static_libs)
    list(APPEND static_libs_objects $<TARGET_OBJECTS:${tgt}>)
  endforeach()

  add_library(${bundled_tgt_name} STATIC ${static_libs_objects})
  set_target_properties(${bundled_tgt_name} PROPERTIES
    INTERFACE_INCLUDE_DIRECTORIES $<TARGET_PROPERTY:${tgt_name},INTERFACE_INCLUDE_DIRECTORIES>
    INTERFACE_LINK_LIBRARIES "${dep_libs}"
    OUTPUT_NAME "${library_name}"
    SYMLINK_NAME "${library_name}.o"
  )
  add_custom_command(TARGET ${bundled_tgt_name} POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E create_symlink "$<TARGET_FILE_NAME:${bundled_tgt_name}>" "$<TARGET_FILE_DIR:${bundled_tgt_name}>/$<TARGET_PROPERTY:${bundled_tgt_name},SYMLINK_NAME>"
  )
endfunction()
