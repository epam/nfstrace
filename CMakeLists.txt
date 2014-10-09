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
set (CMAKE_EXE_LINKER_FLAGS "-Wl,--export-dynamic")

if ("${CMAKE_CXX_COMPILER_ID}" STREQUAL "GNU")
    set (CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} --coverage -O0")
endif ()

set (NST_V_MAJOR "0")
set (NST_V_MINOR "3")
set (NST_V_PATCH "0")
set (NST_VERSION "${NST_V_MAJOR}.${NST_V_MINOR}.${NST_V_PATCH}")
set (NST_VERSION_FULL "${PROJECT_NAME} ${NST_VERSION} (${CMAKE_BUILD_TYPE})")

string(TIMESTAMP COMPILATION_DATE "%Y-%m-%d")

include_directories (src)
file (GLOB_RECURSE SRCS "src/*.cpp")
set  (LIBS  ${CMAKE_DL_LIBS}            # libdl with dlopen()
            ${CMAKE_THREAD_LIBS_INIT}   # libpthread
            ${PCAP_LIBRARY}             # libpcap
            )

configure_file(docs/man/nfstrace.8.in          ${PROJECT_SOURCE_DIR}/docs/man/nfstrace.8)
configure_file(src/api/plugin_api.h.in         ${PROJECT_SOURCE_DIR}/src/api/plugin_api.h)
configure_file(src/controller/build_info.h.in  ${PROJECT_SOURCE_DIR}/src/controller/build_info.h)

add_executable        (${PROJECT_NAME} ${SRCS})
target_link_libraries (${PROJECT_NAME} ${LIBS})

# build analyzers ==============================================================
add_library (breakdown    MODULE analyzers/src/breakdown/breakdown_analyzer.cpp)
add_library (ofws         MODULE analyzers/src/ofws/ofws_analyzer.cpp)
add_library (ofdws        MODULE analyzers/src/ofdws/ofdws_analyzer.cpp
                                 analyzers/src/ofdws/file_rw_op.cpp)
add_library (testanalyzer MODULE analyzers/src/test/test_analyzer.cpp)
set_target_properties (breakdown ofws ofdws testanalyzer
                       PROPERTIES LIBRARY_OUTPUT_DIRECTORY "analyzers")

# build tests ==================================================================
add_subdirectory (tests)

# installation of main application and plugins =================================
install (TARGETS ${PROJECT_NAME} breakdown ofws ofdws
         RUNTIME DESTINATION bin
         LIBRARY DESTINATION lib)

# installation of api headers ==================================================
file (GLOB headers "src/api/*.h")
install (FILES ${headers} DESTINATION include/nfstrace/api)

# installation of man page =====================================================
install (FILES ${PROJECT_SOURCE_DIR}/docs/man/nfstrace.8 DESTINATION share/man/man8)

# build packages ===============================================================
set (CPACK_PACKAGE_VERSION ${NST_VERSION})
set (CPACK_GENERATOR "RPM;DEB;TGZ")
set (CPACK_PACKAGING_INSTALL_PREFIX "/")
set (CPACK_PACKAGE_DESCRIPTION_SUMMARY "NFS tracing/monitoring/capturing/statistic tool")
set (CPACK_PACKAGE_CONTACT "Nfstrace developers <nfstrace@epam.com>")

set (CPACK_RPM_PACKAGE_GROUP "Applications/Internet")
set (CPACK_RPM_PACKAGE_LICENSE "GPLv2")
set (CPACK_RPM_PACKAGE_VENDOR "EPAM Systems")
set (CPACK_RPM_EXCLUDE_FROM_AUTO_FILELIST_ADDITION /bin /include /lib /share /share/man)
set (CPACK_RPM_PACKAGE_REQUIRES "libpcap >= 1.3.0-1")

set (CPACK_DEBIAN_PACKAGE_SECTION "admin")
set (CPACK_DEBIAN_PACKAGE_DEPENDS "libc6 (>= 2.3.1-6), libgcc1 (>= 1:3.4.2-12), libpcap (>=1.3.0-1)")

include (CPack)

# testing ======================================================================
enable_testing ()

# script for verification processing of compressed .pcap.bz2 traces by diff
set (check_pcapbz2 ${CMAKE_BINARY_DIR}/check-compressed-trace.sh)
file (WRITE ${check_pcapbz2}
"bzcat \"$1\" | ./${PROJECT_NAME} --mode=stat -a ./analyzers/libbreakdown.so -I - -v 0 >\"$2\"\n"
"diff -uN \"$3\" \"$2\"\n"
"exit $?"
)

# script for processing of cmpress .pcap.bz by DRAIN mode and precessing result with STAT mode and verification result by diff with default
set (check_drain ${CMAKE_BINARY_DIR}/check-compressed-drane.sh)
file (WRITE ${check_drain}
"bzcat \"$1\" | ./${PROJECT_NAME} --mode=drain -I - -O - -v 0 | ./${PROJECT_NAME} --mode=stat -a ./analyzers/libbreakdown.so -I - -v 0 >\"$2\"\n"
"diff -uN \"$3\" \"$2\"\n"
"exit $?"
)

# script for check output symbols
set (check_out ${CMAKE_BINARY_DIR}/check-out.sh)
file (WRITE ${check_out}
"bzcat \"$1\" | ./${PROJECT_NAME} --mode=stat -v 2 -T -a ./analyzers/libbreakdown.so -I - -O -  | grep --color='auto' -P -n '[^\\x00-\\x7F]' | wc -c | if [ $1 -gt 0 ]; then exit 1; else exit 0; fi "
)

# add test for each .pcap.bz2 trace
file (GLOB traces "traces/*.pcap.bz2")
foreach (trace ${traces})
    get_filename_component (name ${trace} NAME)
    get_filename_component (path ${trace} PATH)
    set (result ${CMAKE_BINARY_DIR}/Testing/Temporary/${name}.res)
    set (reference ${path}/references/${name}.ref)
    add_test (NAME  stat:${name}
              COMMAND sh ${check_pcapbz2} ${trace} ${result} ${reference} )
    add_test (NAME drain:${name}
              COMMAND sh ${check_drain}   ${trace} ${result} ${reference} )
    add_test (NAME   out:${name}
              COMMAND sh ${check_out} ${trace} )
endforeach ()

# coverage =====================================================================
if ("${CMAKE_CXX_COMPILER_ID}" STREQUAL "GNU")
    find_program(GCOVR_PATH gcovr)

    if(GCOVR_PATH)
        add_custom_target(coverage
                          COMMAND ${GCOVR_PATH} --xml -r \"${CMAKE_SOURCE_DIR}\" --object-directory \"${CMAKE_BINARY_DIR}\" -o coverage.xml
                          WORKING_DIRECTORY ${CMAKE_PROJECT_DIR})
    endif ()
endif ()
