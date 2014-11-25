project (webui)
add_library (${PROJECT_NAME} SHARED webui_analyzer.cpp
        ../../../src/net/abstract_tcp_service.cpp
        ../../../src/net/tcp_endpoint.cpp)
set_target_properties(${PROJECT_NAME} PROPERTIES
        LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/analyzers) # direct output to nfstrace common binary dir
target_link_libraries (${PROJECT_NAME} jsoncpp)
install (TARGETS ${PROJECT_NAME} LIBRARY DESTINATION lib)
