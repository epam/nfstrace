cmake_minimum_required (VERSION 2.8.12)
project (nfstrace)

# check compiler and packages ==================================================
if ("${CMAKE_CXX_COMPILER_ID}" STREQUAL "GNU")
    if (CMAKE_CXX_COMPILER_VERSION VERSION_LESS 4.8)
        message (FATAL_ERROR "GCC version must be at least 4.8")
    endif ()
elseif ("${CMAKE_CXX_COMPILER_ID}" STREQUAL "Clang")
    if (CMAKE_CXX_COMPILER_VERSION VERSION_LESS 3.3)
        message (FATAL_ERROR "Clang version must be at least 3.3")
    endif ()
else ()
    message (WARNING "Compilation by ${CMAKE_CXX_COMPILER_ID} ${CMAKE_CXX_COMPILER_VERSION} isn't tested")
endif ()

find_package(Threads REQUIRED) # POSIX Threads

find_path(PCAP_ROOT_DIR
          NAMES include/pcap.h)

find_library(PCAP_LIBRARY
             NAMES pcap
             HINTS ${PCAP_ROOT_DIR}/lib)

if ("${PCAP_LIBRARY}" STREQUAL "PCAP_LIBRARY-NOTFOUND")
    message (FATAL_ERROR "Could NOT find PCAP")
endif ()

# build application ============================================================
set (CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++11 -pedantic -Wall -Werror -Wextra -fPIC -fvisibility=hidden")
set (CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -Wl,--export-dynamic")

if ("${CMAKE_CXX_COMPILER_ID}" STREQUAL "GNU")
    set (CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} --coverage -O0")
endif ()

# Read version string from file
file(STRINGS VERSION NST_VERSION)

string (REPLACE "." ";" VERSION_LIST ${NST_VERSION})
list(GET VERSION_LIST 0 NST_V_MAJOR)
list(GET VERSION_LIST 1 NST_V_MINOR)
list(GET VERSION_LIST 2 NST_V_PATCH)

set (NST_VERSION_FULL "${PROJECT_NAME} ${NST_VERSION} (${CMAKE_BUILD_TYPE})")

string(TIMESTAMP COMPILATION_DATE "%Y-%m-%d")

include_directories (src)
file (GLOB_RECURSE SRCS "src/*.cpp")
set  (LIBS  ${CMAKE_DL_LIBS}            # libdl with dlopen()
            ${CMAKE_THREAD_LIBS_INIT}   # libpthread
            ${PCAP_LIBRARY}             # libpcap
            )

configure_file(docs/nfstrace.8.in              ${PROJECT_SOURCE_DIR}/docs/nfstrace.8)
configure_file(src/api/plugin_api.h.in         ${PROJECT_SOURCE_DIR}/src/api/plugin_api.h)
configure_file(src/controller/build_info.h.in  ${PROJECT_SOURCE_DIR}/src/controller/build_info.h)

add_executable        (${PROJECT_NAME} ${SRCS})
target_link_libraries (${PROJECT_NAME} ${LIBS})

# build watch analyzer==========================================================
add_subdirectory(analyzers)

# testing ======================================================================
enable_testing ()
add_subdirectory (tests)

# installation of main application =============================================
install (TARGETS "${PROJECT_NAME}" RUNTIME DESTINATION bin)

# installation of api headers ==================================================
file (GLOB headers "src/api/*.h")
install (FILES ${headers} DESTINATION include/nfstrace/api)

# installation of man page =====================================================
install (FILES ${PROJECT_SOURCE_DIR}/docs/nfstrace.8 DESTINATION share/man/man8)

# build packages ===============================================================
set (CPACK_PACKAGE_VERSION ${NST_VERSION})
set (CPACK_PACKAGING_INSTALL_PREFIX "/usr")
set (CPACK_PACKAGE_DESCRIPTION_SUMMARY "NFS tracing/monitoring/capturing/statistic tool")
set (CPACK_PACKAGE_CONTACT "Nfstrace developers <nfstrace@epam.com>")

set (CPACK_RPM_PACKAGE_GROUP "Applications/Internet")
set (CPACK_RPM_PACKAGE_LICENSE "GPLv2")
set (CPACK_RPM_PACKAGE_VENDOR "EPAM Systems")
set (CPACK_RPM_EXCLUDE_FROM_AUTO_FILELIST_ADDITION /usr/share/man /usr/share/man/man8)
set (CPACK_RPM_PACKAGE_REQUIRES "libpcap >= 1.3.0-1")

set (CPACK_DEBIAN_PACKAGE_SECTION "admin")
set (CPACK_DEBIAN_PACKAGE_DEPENDS "libpcap0.8 (>=1.3.0-1)")

include (CPack)

# coverage =====================================================================
if ("${CMAKE_CXX_COMPILER_ID}" STREQUAL "GNU")
    find_program (GCOVR_PATH gcovr)

    if (GCOVR_PATH)
        add_custom_target (coverage
                           COMMAND ${GCOVR_PATH} --xml -r \"${CMAKE_SOURCE_DIR}\" --object-directory \"${CMAKE_BINARY_DIR}\" -o coverage.xml 2>&1 >/dev/null
                           WORKING_DIRECTORY ${CMAKE_PROJECT_DIR})
    endif ()
endif ()

# documentation ================================================================
find_program (DOXYGEN_PATH doxygen)

if (DOXYGEN_PATH)
    add_custom_target (documentation
                       COMMAND ${DOXYGEN_PATH} Doxyfile
                       WORKING_DIRECTORY ${CMAKE_SOURCE_DIR})
endif ()

# code style ===================================================================
find_program (ASTYLE_PATH astyle)

if (ASTYLE_PATH)
    add_custom_target (codestyle
                       COMMAND ${ASTYLE_PATH} --options=${CMAKE_SOURCE_DIR}/astyle.cfg '*.cpp' '*.h'
                       WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}/src)
endif ()
