cmake_minimum_required (VERSION 2.8.10)
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
#TODO: integrate FindPCAP.cmake
#find_package(PCAP REQUIRED) # libpcap

# build application ============================================================
set (CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++11 -pedantic -Wall -Werror -Wextra -fPIC -fvisibility=hidden")
set (CMAKE_EXE_LINKER_FLAGS "-Wl,--export-dynamic")

set (NST_V_MAJOR "0")
set (NST_V_MINOR "2")
set (NST_V_PATCH "2")
set (NST_VERSION "${NST_V_MAJOR}.${NST_V_MINOR}.${NST_V_PATCH}")
set (NST_VERSION_FULL "${PROJECT_NAME} ${NST_VERSION} (${CMAKE_BUILD_TYPE})")

include_directories (src)
file (GLOB_RECURSE SRCS "src/*.cpp")
set  (LIBS  ${CMAKE_DL_LIBS}            # libdl with dlopen()
            ${CMAKE_THREAD_LIBS_INIT}   # libpthread
            pcap                        # libpcap
            )

configure_file(src/api/plugin_api.h.in
               ${PROJECT_SOURCE_DIR}/src/api/plugin_api.h)
configure_file(src/controller/build_info.h.in
               ${PROJECT_SOURCE_DIR}/src/controller/build_info.h)

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
#install (TARGETS ${PROJECT_NAME} breakdown ofws ofdws
install (TARGETS ${PROJECT_NAME} breakdown
         RUNTIME DESTINATION bin
         LIBRARY DESTINATION lib/nfstrace)

# installation of api headers ==================================================
file (GLOB headers "src/api/*.h")
install (FILES ${headers} DESTINATION include/nfstrace/api)

# build packages ===============================================================
set (CPACK_PACKAGE_VERSION ${NST_VERSION})
set (CPACK_DEBIAN_PACKAGE_MAINTAINER "Pavel Karneliuk")
set (CPACK_GENERATOR "RPM;DEB;TGZ")
set (CPACK_PACKAGING_INSTALL_PREFIX "/")
set (CPACK_RPM_SPEC_MORE_DEFINE "%define ignore \#")
set (CPACK_RPM_USER_FILELIST "%ignore /bin" "%ignore /include" "%ignore /lib")
set (CPACK_DEBIAN_PACKAGE_DEPENDS "libc6 (>= 2.3.1-6), libgcc1 (>= 1:3.4.2-12), gcc(>= 4.8), libpcap-dev (>=1.3.0-1)")
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
endforeach ()
