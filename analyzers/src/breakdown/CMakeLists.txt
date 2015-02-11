project (breakdown)
aux_source_directory (${CMAKE_SOURCE_DIR}/analyzers/src/breakdown SRC_TEST_LIST)
add_library (${PROJECT_NAME} SHARED ${SRC_TEST_LIST})
set_target_properties (breakdown
                       PROPERTIES LIBRARY_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/analyzers"
                       NO_SONAME ON)
install (TARGETS breakdown LIBRARY DESTINATION lib/nfstrace)
