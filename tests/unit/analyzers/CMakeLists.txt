add_subdirectory (json)
add_subdirectory (breakdown)

project (unit_test_parse)
aux_source_directory ("." SRC_TEST_LIST)
aux_source_directory (${CMAKE_SOURCE_DIR}/src/protocols/cifs SRC_TEST_LIST)
aux_source_directory (${CMAKE_SOURCE_DIR}/src/protocols/cifs2 SRC_TEST_LIST)
aux_source_directory (${CMAKE_SOURCE_DIR}/src/protocols/nfs SRC_TEST_LIST)
aux_source_directory (${CMAKE_SOURCE_DIR}/src/protocols/netbios SRC_TEST_LIST)
add_executable (${PROJECT_NAME} ${SRC_TEST_LIST}
    ${CMAKE_SOURCE_DIR}/src/analysis/cifs_parser.cpp
    ${CMAKE_SOURCE_DIR}/src/utils/out.cpp
    ${CMAKE_SOURCE_DIR}/src/utils/log.cpp
    ${CMAKE_SOURCE_DIR}/src/utils/sessions.cpp
)
target_link_libraries (${PROJECT_NAME} ${GMOCK_LIBRARIES})
add_test (${PROJECT_NAME} ${PROJECT_NAME})
