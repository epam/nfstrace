set(NET_TEST_EXECUTABLE test_net)
aux_source_directory("." SRC_TEST_LIST)
add_executable(${NET_TEST_EXECUTABLE} ${SRC_TEST_LIST}
	${CMAKE_SOURCE_DIR}/src/net/tcp_endpoint.cpp
	${CMAKE_SOURCE_DIR}/src/net/abstract_tcp_service.cpp)
target_link_libraries(${NET_TEST_EXECUTABLE} ${GMOCK_LIBRARIES})
add_test(test_net ${NET_TEST_EXECUTABLE})
