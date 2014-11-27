if ("${GMOCK_SOURCE_DIR}" STREQUAL "")
    message ("GMOCK_SOURCE_DIR variable not set - unit-tests are not available. Use '-DGMOCK_SOURCE_DIR=<path_to_gmock_sources>' param for CMake")
else ()
    # Clang and GCC 4.9+ cause errors on GMock/GTest compilation, so we are adding following flags to suppress them
    set (CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wno-missing-field-initializers -Wno-sign-compare -Wno-unused-private-field")
    set (gmock_force_shared_crt true CACHE INTERNAL "")
    set (BUILD_SHARED_LIBS false CACHE INTERNAL "")
    add_subdirectory (${GMOCK_SOURCE_DIR} ${CMAKE_BINARY_DIR}/gmock)
    set (GMOCK_LIBRARIES gmock)
    set (GMOCK_INCLUDE_DIRS "${GMOCK_SOURCE_DIR}/include"
	"${GMOCK_SOURCE_DIR}/gtest/include")
    include_directories (${CMAKE_SOURCE_DIR}/src ${GMOCK_INCLUDE_DIRS} ${GMOCK_SOURCE_DIR})

    add_subdirectory (utils)
endif ()
