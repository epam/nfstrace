cmake_minimum_required (VERSION 2.8.12)
project (watch)

# check system dependencies instructions =======================================
set (CURSES_NEED_NCURSES TRUE)
find_package (Curses) # find ncurses library

# build instructions ===========================================================
if (CURSES_FOUND)
    include_directories (${CMAKE_CURRENT_SOURCE_DIR})
    include_directories (${CURSES_INCLUDE_DIR})
    file (GLOB_RECURSE UTILS ../utils/*.cpp)
    file (GLOB_RECURSE SRCS ./*.cpp)
    add_library (${PROJECT_NAME} SHARED ${UTILS} ${SRCS})
    set_target_properties(${PROJECT_NAME}
                          PROPERTIES LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/analyzers # direct output to nfstrace common binary dir
                          NO_SONAME ON)
    target_link_libraries (${PROJECT_NAME} ${CURSES_LIBRARIES})
    install (TARGETS watch LIBRARY DESTINATION lib/nfstrace)
else ()
    message (WARNING "CURSES library not found - libwatch plugin is not available!")
endif ()
