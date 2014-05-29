cmake_minimum_required (VERSION 2.8.10)
project (tests)

include_directories (../src/)

file (GLOB tests "*")
foreach (test ${tests})
    get_filename_component (name ${test} NAME)
    if (IS_DIRECTORY ${test}
      AND NOT(${name} STREQUAL CMakeFiles)) # cmake 2.8.12 fix
        get_filename_component (name ${test} NAME)
        file (GLOB SRCS "${test}/*.cpp")

        add_executable        (${name} ${SRCS})
        target_link_libraries (${name} ${LIBS}) # libs from main CMakeList.txt
    endif ()
endforeach ()
