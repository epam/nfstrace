find_path(JSON_INCLUDE_DIR NAMES json-c/json.h json/json.h)
find_library(JSON_LIBRARY NAMES json-c json)

include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(JSON DEFAULT_MSG
    JSON_LIBRARY
    JSON_INCLUDE_DIR
)

if(JSON_FOUND)
    set(JSON_LIBRARIES ${JSON_LIBRARY})
    set(JSON_INCLUDE_DIRS ${JSON_INCLUDE_DIR}/json-c ${JSON_INCLUDE_DIR}/json)
endif()

mark_as_advanced(
    JSON_LIBRARY
    JSON_INCLUDE_DIR
)
