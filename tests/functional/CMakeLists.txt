set (CHECK_TRACE_SCRIPT "check-compressed-trace.sh")
configure_file ("${CHECK_TRACE_SCRIPT}.in" "${CHECK_TRACE_SCRIPT}")
set (CHECK_DRANE_SCRIPT "check-compressed-drane.sh")
configure_file ("${CHECK_DRANE_SCRIPT}.in" "${CHECK_DRANE_SCRIPT}")
set (CHECK_OUTPUT_SCRIPT "check-output.sh")
configure_file ("${CHECK_OUTPUT_SCRIPT}.in" "${CHECK_OUTPUT_SCRIPT}")

# Adding trace/drane/output tests for each .pcap.bz2 trace
file (GLOB traces "${CMAKE_SOURCE_DIR}/traces/*.pcap.bz2")
foreach (trace ${traces})
    get_filename_component (name ${trace} NAME)
    get_filename_component (path ${trace} PATH)
    set (result ${CMAKE_BINARY_DIR}/Testing/Temporary/${name}.res)
    set (reference ${path}/references/${name}.ref)

    add_test (NAME stat:${name} COMMAND sh ${CHECK_TRACE_SCRIPT} ${trace} ${result} ${reference})
    add_test (NAME drain:${name} COMMAND sh ${CHECK_DRANE_SCRIPT} ${trace} ${result} ${reference})
    add_test (NAME out:${name} COMMAND sh ${CHECK_OUTPUT_SCRIPT} ${trace})
endforeach ()

add_subdirectory (json-service)
