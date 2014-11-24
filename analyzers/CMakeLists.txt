cmake_minimum_required (VERSION 2.8.12)
project (analyzers)

set (CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++11 -pedantic -Wall -Wextra")
#-Werror

include_directories (../src/) # access to Plugin API
include_directories (src)
file (GLOB_RECURSE UTILS src/utils/*.cpp)

#add_library (breakdown    SHARED ${UTILS} src/breakdown/breakdown_analyzer.cpp)
#add_library (ofws         SHARED ${UTILS} src/ofws/ofws_analyzer.cpp)
#add_library (ofdws        SHARED ${UTILS} src/ofdws/ofdws_analyzer.cpp src/ofdws/file_rw_op.cpp)
#add_library (testanalyzer SHARED ${UTILS} src/test/test_analyzer.cpp)
add_subdirectory (src/watch)
