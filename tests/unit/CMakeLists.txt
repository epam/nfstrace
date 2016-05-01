if ("${GTEST_SOURCE_DIR}" STREQUAL "")
    message (WARNING "GTEST_SOURCE_DIR variable not set - unit-tests are not available. Use
    '-DGTEST_SOURCE_DIR=<path_to_nfstrace>/third_party/googletest' param for CMake")
else ()
    # Clang and GCC 4.9+ cause errors on GMock/GTest compilation, so we are adding following flags to suppress them
    set (CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wno-missing-field-initializers")
    if ("${CMAKE_CXX_COMPILER_ID}" STREQUAL "Clang")
        set (CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wno-unused-private-field")
    endif ()
    set (gmock_force_shared_crt true CACHE INTERNAL "")
    set (BUILD_SHARED_LIBS false CACHE INTERNAL "")
    add_definitions (-DGTEST_HAS_PTHREAD=1) # It fixes BUG in GTests in BSD
    add_subdirectory (${GTEST_SOURCE_DIR}/googlemock  ${CMAKE_BINARY_DIR}/gmock)
    set (GMOCK_LIBRARIES gmock gmock_main)
    set (GTEST_INCLUDE_DIRS
        "${GTEST_SOURCE_DIR}/googletest/include"
        "${GTEST_SOURCE_DIR}/googlemock/include")

    include_directories (${CMAKE_SOURCE_DIR}/src ${GTEST_INCLUDE_DIRS})

    add_subdirectory (utils)
    add_subdirectory (analyzers)
    add_subdirectory (protocols)
    add_subdirectory (filtration)
endif ()
