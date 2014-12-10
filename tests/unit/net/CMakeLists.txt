project (unit_test_net)
aux_source_directory ("." SRC_LIST)
add_executable (${PROJECT_NAME} ${SRC_LIST}
        ${CMAKE_SOURCE_DIR}/src/net/tcp_endpoint.cpp
        ${CMAKE_SOURCE_DIR}/src/net/abstract_tcp_service.cpp
        ${CMAKE_SOURCE_DIR}/src/utils/log.cpp
        ${CMAKE_SOURCE_DIR}/src/utils/out.cpp)
target_link_libraries (${PROJECT_NAME} ${GMOCK_LIBRARIES})
add_test (${PROJECT_NAME} ${PROJECT_NAME})
