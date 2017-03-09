cmake_minimum_required (VERSION 3.0)

# build analyzers ==============================================================
add_library (testanalyzer MODULE src/test/test_analyzer.cpp)

set_target_properties (testanalyzer
                       PROPERTIES LIBRARY_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/analyzers"
                       NO_SONAME ON)
# installation of plugins ======================================================
install (TARGETS testanalyzer LIBRARY DESTINATION lib/nfstrace)

# build analyzers (new way) ====================================================
add_subdirectory (src/watch)
add_subdirectory (src/breakdown)
add_subdirectory (src/json)
