
include_directories (../src/)

file (GLOB tests "*")
foreach (test ${tests})
    get_filename_component (name ${test} NAME)
    if (IS_DIRECTORY ${test}
      AND NOT(${name} STREQUAL CMakeFiles))
        set (CMAKE_RUNTIME_OUTPUT_DIRECTORY "${test}")
        get_filename_component (name ${test} NAME)
        file (GLOB SRCS "${test}/*.cpp")
        add_executable        (${name} ${SRCS})
        target_link_libraries (${name} ${LIBS}) # libs from root CMakeList.txt
    endif ()
endforeach ()
