set (ANALYZER "breakdown")

set (CHECK_TRACE_SCRIPT_BASE "check-compressed-trace")
set (CHECK_TRACE_SCRIPT "${CHECK_TRACE_SCRIPT_BASE}-${ANALYZER}.sh")
configure_file ("${CHECK_TRACE_SCRIPT_BASE}.sh.in" "${CHECK_TRACE_SCRIPT}")

set (CHECK_DRANE_SCRIPT_BASE "check-compressed-drane")
set (CHECK_DRANE_SCRIPT "${CHECK_DRANE_SCRIPT_BASE}-${ANALYZER}.sh")
configure_file ("${CHECK_DRANE_SCRIPT_BASE}.sh.in" "${CHECK_DRANE_SCRIPT}")

set (CHECK_OUTPUT_SCRIPT_BASE "check-output")
set (CHECK_OUTPUT_SCRIPT "${CHECK_OUTPUT_SCRIPT_BASE}-${ANALYZER}.sh")
configure_file ("${CHECK_OUTPUT_SCRIPT_BASE}.sh.in" "${CHECK_OUTPUT_SCRIPT}")

set (CHECK_COMMAND_SCRIPT_BASE "check-command")
set (CHECK_COMMAND_SCRIPT "${CHECK_COMMAND_SCRIPT_BASE}-${ANALYZER}.sh")
configure_file ("${CHECK_COMMAND_SCRIPT_BASE}.sh.in" "${CHECK_COMMAND_SCRIPT}")

# Adding trace/drane/output tests for each .pcap.bz2 trace
file (GLOB traces "${CMAKE_SOURCE_DIR}/traces/*.pcap.bz2")
foreach (trace ${traces})
	get_filename_component (name ${trace} NAME)
	get_filename_component (path ${trace} PATH)
	set (result ${CMAKE_BINARY_DIR}/Testing/Temporary/${name}-${ANALYZER}.res)
	set (reference ${path}/references/${ANALYZER}/${name}.ref)

	add_test (NAME functional_stat:${name} COMMAND sh ${CHECK_TRACE_SCRIPT} ${trace} ${result} ${reference})
	add_test (NAME functional_drain:${name} COMMAND sh ${CHECK_DRANE_SCRIPT} ${trace} ${result} ${reference})
	add_test (NAME functional_out:${name} COMMAND sh ${CHECK_OUTPUT_SCRIPT} ${trace})
	add_test (NAME functional_command:${name} COMMAND sh ${CHECK_COMMAND_SCRIPT} ${trace})
endforeach ()

