add_custom_target (documentation)

find_package (Doxygen)
if (DOXYGEN_FOUND)
    add_custom_target (documentation-doxygen
                       COMMAND ${DOXYGEN_EXECUTABLE} Doxyfile
                       WORKING_DIRECTORY ${CMAKE_SOURCE_DIR})
    add_dependencies (documentation documentation-doxygen)
endif ()

find_package (LATEX COMPONENTS PDFLATEX)
file (GLOB_RECURSE TEXS "*.tex")
if (TEXS AND LATEX_PDFLATEX_FOUND)
    foreach (tex ${TEXS})
        get_filename_component (name ${tex} NAME_WE)
        set (pdf "${name}.pdf")
        list (APPEND PDFS ${pdf})
        set(args ${tex} -quiet -interaction=nonstopmode -disable-installer -aux-directory=${CMAKE_CURRENT_BINARY_DIR})
        add_custom_command (OUTPUT ${pdf}
                            COMMAND ${PDFLATEX_COMPILER} ${args}
                            COMMAND makeglossaries ${name}
                            COMMAND ${PDFLATEX_COMPILER} ${args}
                            COMMAND ${PDFLATEX_COMPILER} ${args}
                            DEPENDS ${tex}
                            WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
                            COMMENT "Converting ${tex} to ${pdf}" VERBATIM)
    endforeach ()
    add_custom_target (documentation-pdflatex DEPENDS ${PDFS} SOURCES ${TEXS})
    add_dependencies (documentation documentation-pdflatex)
endif ()
