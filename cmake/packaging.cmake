set (CPACK_PACKAGE_VENDOR "EPAM Systems")
set (CPACK_PACKAGE_VERSION ${NST_VERSION})
set (CPACK_PACKAGING_INSTALL_PREFIX "/usr")
set (CPACK_PACKAGE_DESCRIPTION_SUMMARY "NFS tracing/monitoring/capturing/statistic tool")
set (CPACK_PACKAGE_CONTACT "Nfstrace developers <nfstrace@epam.com>")

set (CPACK_RPM_PACKAGE_GROUP "Applications/Internet")
set (CPACK_RPM_PACKAGE_LICENSE "GPLv2")
set (CPACK_RPM_EXCLUDE_FROM_AUTO_FILELIST_ADDITION /usr/share/man /usr/share/man/man8)
set (CPACK_RPM_PACKAGE_REQUIRES "libpcap >= 1.3.0-1")
if (${CMAKE_SYSTEM_NAME} MATCHES "Linux" AND EXISTS "/etc/os-release")
    execute_process (
        COMMAND grep "^NAME=" /etc/os-release
        COMMAND sed -e "s/NAME=//g"
        COMMAND sed -e "s/\"//g"
        RESULT_VARIABLE DIFINE_LINUX_DISTRO_RESULT
        OUTPUT_VARIABLE LINUX_DISTRO
    )
    if (NOT ${DIFINE_LINUX_DISTRO_RESULT} EQUAL 0)
        message (FATAL_ERROR "Linux distro identification error")
    endif ()
endif ()
# libjson package has different names on different RPM-based distros
if (${LINUX_DISTRO} MATCHES "openSUSE")
    set (CPACK_RPM_PACKAGE_REQUIRES "libjson-c2 >= 0.11")
elseif (${LINUX_DISTRO} MATCHES "ALT Linux")
    set (CPACK_RPM_PACKAGE_REQUIRES "libjson-c >= 0.11")
else ()
    # CentOS/Fedora/etc.
    set (CPACK_RPM_PACKAGE_REQUIRES "json-c >= 0.11")
endif ()

set (CPACK_DEBIAN_PACKAGE_SECTION "admin")
set (CPACK_DEBIAN_PACKAGE_DEPENDS "libpcap0.8 (>=1.3.0-1), libjson-c2 (>=0.11)")

include (CPack)
