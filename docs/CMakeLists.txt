add_custom_target (documentation)

find_program (DOXYGEN_PATH doxygen)
if (DOXYGEN_PATH)
    add_custom_target (documentation-doxygen
                       COMMAND ${DOXYGEN_PATH} Doxyfile
                       WORKING_DIRECTORY ${CMAKE_SOURCE_DIR})
    add_dependencies (documentation documentation-doxygen)
else ()
    message (WARNING "Doxygen is not found - source-code documentation is not available")
endif ()

find_package (LATEX COMPONENTS PDFLATEX)
if (LATEX_PDFLATEX_FOUND)
    message(STATUS "Available LaTeX pdf compiler: ${PDFLATEX_COMPILER}")
    add_custom_target (documentation-pdflatex
                       COMMAND ${PDFLATEX_COMPILER} --version
                       WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR})
    add_dependencies (documentation documentation-pdflatex)
endif ()
