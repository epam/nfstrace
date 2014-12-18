set (CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} "${CMAKE_SOURCE_DIR}/cmake")
find_package (JSON)

if (JSON_FOUND)
    project (unit_test_json_analyzer)
    aux_source_directory ("." SRC_LIST)
    add_executable (${PROJECT_NAME} ${SRC_LIST}
            ${CMAKE_SOURCE_DIR}/analyzers/src/json/json_analyzer.cpp
            ${CMAKE_SOURCE_DIR}/analyzers/src/json/json_tcp_service.cpp
            ${CMAKE_SOURCE_DIR}/src/net/abstract_tcp_service.cpp
            ${CMAKE_SOURCE_DIR}/src/net/ip_endpoint.cpp
            ${CMAKE_SOURCE_DIR}/src/utils/log.cpp
            ${CMAKE_SOURCE_DIR}/src/utils/out.cpp)
    include_directories (${JSON_INCLUDE_DIRS} ${CMAKE_SOURCE_DIR}/analyzers/src/json)
    target_link_libraries (${PROJECT_NAME} ${JSON_LIBRARIES} ${GMOCK_LIBRARIES})
    add_test (${PROJECT_NAME} ${PROJECT_NAME})
else ()
    message (WARNING "JSON library not found - JSON-service unit-tests are not available!")
endif ()
