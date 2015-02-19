project (cifs)
aux_source_directory (${CMAKE_SOURCE_DIR}/analyzers/src/cifs SRC_TEST_LIST)
add_library (${PROJECT_NAME} SHARED ${SRC_TEST_LIST})
set_target_properties (cifs
                       PROPERTIES LIBRARY_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/analyzers"
                       NO_SONAME ON)
install (TARGETS cifs LIBRARY DESTINATION lib/nfstrace)
