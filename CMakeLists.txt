cmake_minimum_required (VERSION 3.0)
project (nfstrace)

# check compiler and packages ==================================================
if ("${CMAKE_CXX_COMPILER_ID}" STREQUAL "GNU")
    if (CMAKE_CXX_COMPILER_VERSION VERSION_LESS 5.1)
        message (FATAL_ERROR "GCC version must be at least 5.1")
    endif ()
elseif ("${CMAKE_CXX_COMPILER_ID}" STREQUAL "Clang")
    if (CMAKE_CXX_COMPILER_VERSION VERSION_LESS 3.5)
        message (FATAL_ERROR "Clang version must be at least 3.5")
    endif ()
else ()
    message (WARNING "Compilation by ${CMAKE_CXX_COMPILER_ID} ${CMAKE_CXX_COMPILER_VERSION} isn't tested")
endif ()

include(cmake/options.cmake)

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
set (CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++14 -pedantic -Wall -Werror -Wextra -Wno-invalid-offsetof -fPIC -fvisibility=hidden")
set (CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -Wl,--export-dynamic")

if ("${CMAKE_CXX_COMPILER_ID}" STREQUAL "GNU" AND "${INCLUDE_COVERAGE_INFO}")
    set (CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} --coverage -O0")
endif ()

# Read version string from file
file (STRINGS VERSION NST_VERSION)

string (REPLACE "." ";" VERSION_LIST ${NST_VERSION})
list (GET VERSION_LIST 0 NST_V_MAJOR)
list (GET VERSION_LIST 1 NST_V_MINOR)
list (GET VERSION_LIST 2 NST_V_PATCH)

set (NST_VERSION_FULL "${PROJECT_NAME} ${NST_VERSION} (${CMAKE_BUILD_TYPE})")

if (DEFINED ENV{SOURCE_DATE_EPOCH})
    execute_process(
      COMMAND "date" "-u" "-d" "@$ENV{SOURCE_DATE_EPOCH}" "+%Y-%m-%d"
      OUTPUT_VARIABLE COMPILATION_DATE
      OUTPUT_STRIP_TRAILING_WHITESPACE)
else ()
    string (TIMESTAMP COMPILATION_DATE "%Y-%m-%d")
endif ()

include_directories (src)

# nfstrace executable ==========================================================
file (GLOB_RECURSE SRCS "src/*.cpp")
set (LIBS ${CMAKE_DL_LIBS}          # libdl with dlopen()
          ${CMAKE_THREAD_LIBS_INIT} # libpthread
          ${PCAP_LIBRARY}           # libpcap
          )

configure_file (docs/nfstrace.8.in              ${PROJECT_SOURCE_DIR}/docs/nfstrace.8)
configure_file (src/api/plugin_api.h.in         ${PROJECT_SOURCE_DIR}/src/api/plugin_api.h)
configure_file (src/controller/build_info.h.in  ${PROJECT_SOURCE_DIR}/src/controller/build_info.h)

add_executable (${PROJECT_NAME} ${SRCS})
target_link_libraries (${PROJECT_NAME} ${LIBS})

# analyzer plugins =============================================================
add_subdirectory (analyzers)

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
include ("cmake/packaging.cmake")

# coverage =====================================================================
if ("${CMAKE_CXX_COMPILER_ID}" STREQUAL "GNU" AND "${INCLUDE_COVERAGE_INFO}")
    find_program (GCOVR_PATH gcovr)

    if (GCOVR_PATH)
        add_custom_target (coverage
                           COMMAND ${GCOVR_PATH} --xml -r \"${CMAKE_SOURCE_DIR}\" --object-directory \"${CMAKE_BINARY_DIR}\" -o coverage.xml 2>&1 >/dev/null
                           WORKING_DIRECTORY ${CMAKE_BINARY_DIR})
        add_custom_target (coverage-html
                           COMMAND ${GCOVR_PATH} --html --html-details -r \"${CMAKE_SOURCE_DIR}\" --object-directory \"${CMAKE_BINARY_DIR}\" -o coverage.html 2>&1 >/dev/null
                           WORKING_DIRECTORY ${CMAKE_BINARY_DIR})
    else ()
        message (WARNING "'gcovr' executable not found - coverage report is not available.")
    endif ()
endif ()

# documentation ================================================================
add_subdirectory (docs)

# code style ===================================================================
include ("cmake/codeformat.cmake")

# valgrind reports =============================================================
include ("cmake/valgrind.cmake")
