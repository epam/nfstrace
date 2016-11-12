# - Find json
# Find the native JSON headers and libraries.
# This module defines
#  JSON_INCLUDE_DIRS - the json include directory
#  JSON_LIBRARIES    - the libraries needed to use json
#  JSON_FOUND        - system has the json library
#
#  Copyright (c) 2013 Mathieu Malaterre <mathieu.malaterre@gmail.com>
#
#  Redistribution and use is allowed according to the terms of the New
#  BSD license.
#  For details see the accompanying COPYING-CMAKE-SCRIPTS file.

# See:
# https://github.com/json-c/json-c/wiki
# $ sudo apt-get install libjson0-dev
# in sid:
# $ sudo apt-get install libjson-c-dev


#[[
Debian and Ubuntu have json-c in /usr/include/json-c and jsoncpp in /usr/include/jsoncpp/json
Arch and Fedora have json-c in /usr/include/json-c and jsoncpp in /usr/include/json
Searching for json_c_version.h avoids finding json.h of jsoncpp.
]]
find_path(JSON_INCLUDE_DIR NAMES json_c_version.h json.h PATHS /usr/include/json-c /usr/include/json)
find_library(JSON_LIBRARY NAMES json-c json)

include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(JSON DEFAULT_MSG
        JSON_LIBRARY JSON_INCLUDE_DIR
        )

if(JSON_FOUND)
    set(JSON_LIBRARIES ${JSON_LIBRARY})
    set(JSON_INCLUDE_DIRS ${JSON_INCLUDE_DIR})
endif()

mark_as_advanced(
        JSON_LIBRARY
        JSON_INCLUDE_DIRS
)
