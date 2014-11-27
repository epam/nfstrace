cmake_minimum_required (VERSION 2.8.12)

# build analyzers ==============================================================
add_library (breakdown    MODULE src/breakdown/breakdown_analyzer.cpp)
add_library (ofws         MODULE src/ofws/ofws_analyzer.cpp)
add_library (ofdws        MODULE src/ofdws/ofdws_analyzer.cpp
                                 src/ofdws/file_rw_op.cpp)
add_library (testanalyzer MODULE src/test/test_analyzer.cpp)
set_target_properties (breakdown ofws ofdws testanalyzer
                       PROPERTIES LIBRARY_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/analyzers"
                       NO_SONAME ON)
add_subdirectory (src/watch)

# installation of plugins ======================================================
install (TARGETS breakdown ofws ofdws LIBRARY DESTINATION lib/nfstrace)
