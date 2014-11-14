set (NAME_INCLUDE "false" CACHE PATH "Path to gmock source distribution, for make it subproject")

set (GMOCK_SOURCE_DIR "gmock-1.7.0")
set (GMOCK_FOUND true)
set (gmock_force_shared_crt true CACHE INTERNAL "")
set (BUILD_SHARED_LIBS false CACHE INTERNAL "")
add_subdirectory (${GMOCK_SOURCE_DIR} ${CMAKE_BINARY_DIR}/gmock)
set (GMOCK_LIBRARIES gmock)
set (GMOCK_INCLUDE_DIRS "${GMOCK_SOURCE_DIR}/include"
	"${GMOCK_SOURCE_DIR}/gtest/include")

include_directories ("${CMAKE_SOURCE_DIR}/src")

if (GMOCK_FOUND)
    message (STATUS "Google mocks found, unit mocks are available")
    include_directories (${GMOCK_INCLUDE_DIRS} ${GMOCK_SOURCE_DIR})

    add_subdirectory (utils)
    #add_subdirectory (analysis)
    #add_subdirectory (api)
    #add_subdirectory (controller)
    #add_subdirectory (filtration)
    #add_subdirectory (protocols)
else ()
    message (WARNING "No google mocks found so unit mocks are not available")
endif ()
