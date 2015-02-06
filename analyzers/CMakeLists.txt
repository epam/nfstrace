cmake_minimum_required (VERSION 2.8.12)

# build analyzers ==============================================================
add_library (breakdown    MODULE src/breakdown/breakdown_analyzer.cpp)
add_library (testanalyzer MODULE src/test/test_analyzer.cpp)

set_target_properties (breakdown testanalyzer
                       PROPERTIES LIBRARY_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/analyzers"
                       NO_SONAME ON)
add_subdirectory (src/watch)
add_subdirectory (src/cifs)

# installation of plugins ======================================================
install (TARGETS breakdown LIBRARY DESTINATION lib/nfstrace)
