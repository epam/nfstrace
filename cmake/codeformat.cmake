find_program (clangformat clang-format)
if (clangformat)
    execute_process (COMMAND ${clangformat} -version OUTPUT_VARIABLE version_string)
    string (REGEX MATCH "([0-9]\\.[0-9]\\.?[0-9]?)" version "${version_string}")
    if (${version} VERSION_LESS "3.9")
        message (STATUS "Found ${version_string} less that required clang-format 3.9")
    else()
        add_custom_target (clang-format
            COMMAND find analyzers src tests docs -name '*.h' -o -name '*.cpp' | xargs ${clangformat} -i -style=file
            WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
            COMMENT "Reformat sources by clang-format"
            SOURCES ${CMAKE_SOURCE_DIR}/.clang-format)
    endif()
endif()
