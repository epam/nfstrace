project (unit_test_breakdown)
aux_source_directory ("." SRC_LIST)
aux_source_directory ("${CMAKE_SOURCE_DIR}/analyzers/src/breakdown" SRC_LIST)
aux_source_directory (${CMAKE_SOURCE_DIR}/src/protocols/cifs SRC_LIST)
aux_source_directory (${CMAKE_SOURCE_DIR}/src/protocols/nfs SRC_LIST)
aux_source_directory (${CMAKE_SOURCE_DIR}/src/protocols/nfs3 SRC_LIST)
aux_source_directory (${CMAKE_SOURCE_DIR}/src/protocols/nfs4 SRC_LIST)
aux_source_directory (${CMAKE_SOURCE_DIR}/src/utils SRC_LIST)

include_directories (${CMAKE_SOURCE_DIR}/analyzers/src/breakdown)

add_executable(${PROJECT_NAME} ${SRC_LIST})
target_link_libraries (${PROJECT_NAME} ${GMOCK_LIBRARIES} ${CMAKE_DL_LIBS})
add_test (${PROJECT_NAME} ${PROJECT_NAME})
