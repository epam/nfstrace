# Profiling
option(PROFILING "help string describing option" OFF)
if (PROFILING)
    add_definitions(-DPROFILING)
else ()
    message(STATUS "To enable code self-profiling set option PROFILING=ON")
endif()
