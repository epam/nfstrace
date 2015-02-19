find_program (VALGRIND_PATH valgrind)

if (VALGRIND_PATH)
    add_custom_target (memcheck-report)
    add_custom_target (memcheck-report-xml)
    add_custom_target (helgrind-report)
    add_custom_target (helgrind-report-xml)

    foreach (PROTOCOL IN ITEMS "nfsv3" "nfsv4")
        # Preparing trace file
        set (ARCHIVED_TRACE_FILENAME "${CMAKE_SOURCE_DIR}/traces/breakdown/eth-ipv4-tcp-${PROTOCOL}.pcap.bz2")
        set (TRACE_FILENAME "${CMAKE_BINARY_DIR}/eth-ipv4-tcp-${PROTOCOL}.pcap")
        set (UNZIP_TRACE_TARGET_NAME "${PROTOCOL}_trace")
        add_custom_target (${UNZIP_TRACE_TARGET_NAME}
                COMMAND bzcat ${ARCHIVED_TRACE_FILENAME} > ${TRACE_FILENAME}
                DEPENDS ${ARCHIVED_TRACE_FILENAME})
        add_dependencies (memcheck-report ${UNZIP_TRACE_TARGET_NAME})
        add_dependencies (memcheck-report-xml ${UNZIP_TRACE_TARGET_NAME})
        add_dependencies (helgrind-report ${UNZIP_TRACE_TARGET_NAME})
        add_dependencies (helgrind-report-xml ${UNZIP_TRACE_TARGET_NAME})

        # Memcheck report
        add_custom_command (TARGET memcheck-report
                            POST_BUILD
                            COMMAND valgrind --tool=memcheck --leak-check=full --show-reachable=yes 
                                    --undef-value-errors=yes --track-origins=no --child-silent-after-fork=no 
                                    --trace-children=no --log-file=${CMAKE_BINARY_DIR}/valgrind.nfstrace.%p.drain.${PROTOCOL}.memcheck.log
                                    ${CMAKE_BINARY_DIR}/nfstrace --mode=drain -b 20 -Q 4096 -M 512
                                    -I ${TRACE_FILENAME})
        add_custom_command (TARGET memcheck-report
                            POST_BUILD
                            COMMAND valgrind --tool=memcheck --leak-check=full --show-reachable=yes
                                    --undef-value-errors=yes --track-origins=no --child-silent-after-fork=no 
                                    --trace-children=no --log-file=${CMAKE_BINARY_DIR}/valgrind.nfstrace.%p.stat.${PROTOCOL}.memcheck.log
                                    ${CMAKE_BINARY_DIR}/nfstrace --mode=stat -a ${CMAKE_BINARY_DIR}/analyzers/libbreakdown.so
                                    -b 20 -Q 4096 -M 512 -I ${TRACE_FILENAME})

        # Memcheck report (XML)
        add_custom_command (TARGET memcheck-report-xml
                            POST_BUILD
                            COMMAND valgrind --tool=memcheck --leak-check=full --show-reachable=yes 
                                    --undef-value-errors=yes --track-origins=no --child-silent-after-fork=no 
                                    --trace-children=no --xml=yes --xml-file=${CMAKE_BINARY_DIR}/valgrind.nfstrace.%p.drain.${PROTOCOL}.memcheck.xml 
                                    ${CMAKE_BINARY_DIR}/nfstrace --mode=drain -b 20 -Q 4096 -M 512
                                    -I ${TRACE_FILENAME})
        add_custom_command (TARGET memcheck-report-xml
                            POST_BUILD
                            COMMAND valgrind --tool=memcheck --leak-check=full --show-reachable=yes
                                    --undef-value-errors=yes --track-origins=no --child-silent-after-fork=no 
                                    --trace-children=no --xml=yes --xml-file=${CMAKE_BINARY_DIR}/valgrind.nfstrace.%p.stat.${PROTOCOL}.memcheck.xml 
                                    ${CMAKE_BINARY_DIR}/nfstrace --mode=stat -a ${CMAKE_BINARY_DIR}/analyzers/libbreakdown.so
                                    -b 20 -Q 4096 -M 512 -I ${TRACE_FILENAME})

        # Helgrind report
        add_custom_command (TARGET helgrind-report
                            POST_BUILD
                            COMMAND valgrind --tool=helgrind --child-silent-after-fork=no --trace-children=no
                                    --log-file=${CMAKE_BINARY_DIR}/valgrind.nfstrace.%p.drain.${PROTOCOL}.helgrind.log
                                    ${CMAKE_BINARY_DIR}/nfstrace --mode=drain -b 20 -Q 4096 -M 512
                                    -I ${TRACE_FILENAME})
        add_custom_command (TARGET helgrind-report
                            POST_BUILD
                            COMMAND valgrind --tool=helgrind --child-silent-after-fork=no --trace-children=no
                                    --log-file=${CMAKE_BINARY_DIR}/valgrind.nfstrace.%p.stat.${PROTOCOL}.helgrind.log
                                    ${CMAKE_BINARY_DIR}/nfstrace --mode=stat -a ${CMAKE_BINARY_DIR}/analyzers/libbreakdown.so
                                    -b 20 -Q 4096 -M 512 -I ${TRACE_FILENAME})

        # Helgrind report (XML)
        add_custom_command (TARGET helgrind-report-xml
                            POST_BUILD
                            COMMAND valgrind --tool=helgrind --child-silent-after-fork=no --trace-children=no
                                    --xml=yes --xml-file=${CMAKE_BINARY_DIR}/valgrind.nfstrace.%p.drain.${PROTOCOL}.helgrind.xml
                                    ${CMAKE_BINARY_DIR}/nfstrace --mode=drain -b 20 -Q 4096 -M 512
                                    -I ${TRACE_FILENAME})
        add_custom_command (TARGET helgrind-report-xml
                            POST_BUILD
                            COMMAND valgrind --tool=helgrind --child-silent-after-fork=no --trace-children=no
                                    --xml=yes --xml-file=${CMAKE_BINARY_DIR}/valgrind.nfstrace.%p.stat.${PROTOCOL}.helgrind.xml
                                    ${CMAKE_BINARY_DIR}/nfstrace --mode=stat -a ${CMAKE_BINARY_DIR}/analyzers/libbreakdown.so
                                    -b 20 -Q 4096 -M 512 -I ${TRACE_FILENAME})
    endforeach ()
endif ()
