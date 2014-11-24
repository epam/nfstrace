cmake_minimum_required (VERSION 2.8.12)
project (analyzers)

set (CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++11 -pedantic -Wall -Wextra")
#-Werror

include_directories (../src/) # access to Plugin API
include_directories (src)
file (GLOB_RECURSE UTILS src/utils/*.cpp)

add_subdirectory (src/watch)
