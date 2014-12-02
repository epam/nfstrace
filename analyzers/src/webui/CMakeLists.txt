set (CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} "${CMAKE_SOURCE_DIR}/cmake")
find_package (JSON)

if (JSON_FOUND)
    project (webui)
    aux_source_directory ("." SRC_LIST)
    add_library (${PROJECT_NAME} SHARED ${SRC_LIST}
            ../../../src/net/abstract_tcp_service.cpp
            ../../../src/net/tcp_endpoint.cpp)
    set_target_properties(${PROJECT_NAME} PROPERTIES
            LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/analyzers) # direct output to nfstrace common binary dir
    include_directories (${JSON_INCLUDE_DIRS})
    target_link_libraries (${PROJECT_NAME} ${JSON_LIBRARIES})
    install (TARGETS ${PROJECT_NAME} LIBRARY DESTINATION lib)
else ()
    message (WARNING "JSON library not found - WebUI plugin is not available!")
endif ()
