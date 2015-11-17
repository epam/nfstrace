add_custom_target (documentation)

find_package (Doxygen)
if (DOXYGEN_FOUND)
    add_custom_target (documentation-doxygen
                       COMMAND ${DOXYGEN_EXECUTABLE} Doxyfile
                       WORKING_DIRECTORY ${CMAKE_SOURCE_DIR})
    add_dependencies (documentation documentation-doxygen)
endif ()

find_package (LATEX COMPONENTS PDFLATEX)
if (LATEX_PDFLATEX_FOUND)
    add_custom_target (documentation-pdflatex
                       COMMAND ${PDFLATEX_COMPILER} --version
                       WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR})
    add_dependencies (documentation documentation-pdflatex)
endif ()
