cmake_minimum_required (VERSION 2.8.10)
project (nfstrace)

# check compiler and packages ==================================================
if ("${CMAKE_CXX_COMPILER_ID}" STREQUAL "GNU")   # require at least gcc 4.8
    if (CMAKE_CXX_COMPILER_VERSION VERSION_LESS 4.8)
        message (FATAL_ERROR "GCC version must be at least 4.8!")
    endif ()
else ()
    message (WARNING "Compilation has only been tested with GCC 4.8")
endif ()

find_package(Threads REQUIRED) # POSIX Threads
#TODO: integrate FindPCAP.cmake
#find_package(PCAP REQUIRED) # libpcap

# build application ============================================================
set (CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++11 -pedantic -Wall -Werror -Wextra -fPIC")
set (PROJECT_VERSION "0.2")
set (NST_BUILD_VERSION  "${PROJECT_NAME} ${PROJECT_VERSION} (${CMAKE_BUILD_TYPE})")
set (NST_BUILD_PLATFORM "${CMAKE_SYSTEM}")
set (NST_BUILD_COMPILER "${CMAKE_CXX_COMPILER_ID} ${CMAKE_CXX_COMPILER_VERSION}")

include_directories (src)
file (GLOB_RECURSE SRCS "src/*.cpp")
set  (LIBS  ${CMAKE_DL_LIBS}            # libdl with dlopen()
            ${CMAKE_THREAD_LIBS_INIT}   # libpthread
            pcap                        # libpcap
            )

add_definitions (-DNST_BUILD_VERSION=${NST_BUILD_VERSION};
                 -DNST_BUILD_PLATFORM=${NST_BUILD_PLATFORM};
                 -DNST_BUILD_COMPILER=${NST_BUILD_COMPILER})

add_executable        (${PROJECT_NAME} ${SRCS})
target_link_libraries (${PROJECT_NAME} ${LIBS})

# build analyzers ==============================================================
add_library (breakdown    SHARED analyzers/src/breakdown/breakdown_analyzer.cpp)
add_library (ofws         SHARED analyzers/src/ofws/ofws_analyzer.cpp)
add_library (ofdws        SHARED analyzers/src/ofdws/ofdws_analyzer.cpp
                                 analyzers/src/ofdws/file_rw_op.cpp)
add_library (testanalyzer SHARED analyzers/src/test/test_analyzer.cpp)
set_target_properties (breakdown ofws ofdws testanalyzer
                       PROPERTIES LIBRARY_OUTPUT_DIRECTORY "analyzers")

# build tests ==================================================================
add_subdirectory (tests)

# installation of main application and plugins =================================
install(TARGETS ${PROJECT_NAME} breakdown ofws ofdws
        RUNTIME DESTINATION bin
        LIBRARY DESTINATION lib/nfstrace)

# installation of api headers ==================================================
file(GLOB headers "src/api/*.h")
install(FILES ${headers} DESTINATION include/nfstrace/api)

# build packages ===============================================================
set(CPACK_PACKAGE_VERSION ${PROJECT_VERSION})
set(CPACK_DEBIAN_PACKAGE_MAINTAINER "Pavel Karneliuk")
set(CPACK_GENERATOR "RPM;DEB;TGZ")
set(CPACK_PACKAGING_INSTALL_PREFIX "/")
set(CPACK_DEBIAN_PACKAGE_DEPENDS "libc6 (>= 2.3.1-6), libgcc1 (>= 1:3.4.2-12), gcc(>= 4.8), libpcap-dev (>=1.3.0-1)")
include(CPack)

# testing ======================================================================
enable_testing ()

# script for verification processing of compressed .pcap.bz2 traces by diff
set (check_pcapbz2 ${CMAKE_BINARY_DIR}/check-compressed-trace.sh)
file (WRITE ${check_pcapbz2}
"bzcat $1 | ./${PROJECT_NAME} --mode=stat -a ./analyzers/libbreakdown.so -I - -v 0 >$2 2>&1\n"
"diff -uN $3 $2\n"
"exit $?"
)

# add test for each .pcap.bz2 trace
file (GLOB traces "traces/*.pcap.bz2")
foreach (trace ${traces})
    get_filename_component (name ${trace} NAME)
    get_filename_component (path ${trace} PATH)
    set (result ${CMAKE_BINARY_DIR}/Testing/Temporary/${name}.res)
    set (reference ${path}/references/${name}.ref)

    add_test (NAME ${name}
              COMMAND sh ${check_pcapbz2} ${trace} ${result} ${reference} )
endforeach ()

