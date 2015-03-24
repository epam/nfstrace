#!/bin/sh
#
# Author: Ilya Storozhilov
# Description: Main CI-cycle script
# Copyright (c) 2013-2014 EPAM Systems
#
#    This file is part of Nfstrace.
#
#    Nfstrace is free software: you can redistribute it and/or modify
#    it under the terms of the GNU General Public License as published by
#    the Free Software Foundation, version 2 of the License.
#
#    Nfstrace is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#    GNU General Public License for more details.
#
#    You should have received a copy of the GNU General Public License
#    along with Nfstrace.  If not, see <http://www.gnu.org/licenses/>.

# Platform identification

PLATFORM=$(uname)
if [ $? -ne 0 ] ; then
    echo ">>> Platform identification error"
    exit 1
fi
if [ "$PLATFORM" = "Linux" ] ; then
    OS_RELEASE_FILE="/etc/os-release"
    if [ ! -r "$OS_RELEASE_FILE" ] ; then
        echo ">>> Linux distro identification error: file '$OS_RELEASE_FILE' not found" >&2
        exit 1
    fi
    LINUX_DISTRO=$(grep "^NAME=" "$OS_RELEASE_FILE" | sed -e 's/NAME=//g' | sed -e 's/"//g')
    echo ">>> Running CI-cycle on '$LINUX_DISTRO' platform"
else
    echo ">>> Running CI-cycle on '$PLATFORM' platform"
fi

# Pulling environment variables using default values

: ${WORKSPACE:="$(pwd)/$(dirname $0)/.."}

# Processing CLI arguments

SKIP_CPPCHECK=false
SKIP_SCAN_BUILD=false
SKIP_MEMCHECK=false
SKIP_PACKAGING=false

for CLI_OPT in "$@" ; do
    case $CLI_OPT in
        --skip-cppcheck) SKIP_CPPCHECK=true ;;
        --skip-scan-build) SKIP_SCAN_BUILD=true ;;
        --skip-memcheck) SKIP_MEMCHECK=true ;;
        --skip-packaging) SKIP_PACKAGING=true ;; 
    esac
done

# Generating cppcheck report

if [ "$SKIP_CPPCHECK" = true ] ; then
    echo ">>> Skipping cppcheck report generation"
else
    cd $WORKSPACE
    echo ">>> Generating cppcheck report"
    cppcheck --enable=all --std=c++11 --inconclusive --xml --xml-version=2 src analyzers/src 2> cppcheck.xml
    if [ $? -ne 0 ] ; then
        echo ">>> Cppcheck report generation error"
        exit 1
    fi
fi

# Generating scan-build report

if [ "$SKIP_SCAN_BUILD" = true ] ; then
    echo ">>> Skipping scan-build report generation"
elif [ "$LINUX_DISTRO" = "openSUSE" ] ; then
    echo ">>> Will not generate scan-build report - OpenSUSE is not supported at the moment"
else
    SCAN_BUILD_TMPDIR=$(mktemp -d /tmp/scan-build.XXXXXX)
    SCAN_BUILD_ARCHIVE=$WORKSPACE/scan-build-archive
    SCAN_BUILD_DIR=$WORKSPACE/scan-build

    if [ "$PLATFORM" = "FreeBSD" ] ; then
        CCC_ANALYZER=ccc-analyzer35
        CXX_ANALYZER=c++-analyzer35
        SCAN_BUILD=/usr/local/llvm35/bin/scan-build
    elif [ "$LINUX_DISTRO" = "Ubuntu" ] ; then
        # Different Ubuntu versions have different locations for CLang analyser binaries
        CCC_ANALYZER=$(find /usr/share/clang/ -name ccc-analyzer)
        if [ $? -ne 0 ] ; then
            echo ">>> Scan-build C language analyzer executable lookup error"
            exit 1
        fi
        CXX_ANALYZER=$(find /usr/share/clang/ -name c++-analyzer)
        if [ $? -ne 0 ] ; then
            echo ">>> Scan-build C++ language analyzer executable lookup error"
            exit 1
        fi
        SCAN_BUILD=scan-build
    elif [ "$LINUX_DISTRO" = "ALT Linux" ] ; then
        CCC_ANALYZER=/usr/lib64/clang-analyzer/scan-build/ccc-analyzer
        CXX_ANALYZER=/usr/lib64/clang-analyzer/scan-build/c++-analyzer
        SCAN_BUILD=scan-build
    elif [ "$LINUX_DISTRO" = "CentOS Linux" ] ; then
        CCC_ANALYZER=/usr/libexec/clang-analyzer/scan-build/ccc-analyzer
        CXX_ANALYZER=/usr/libexec/clang-analyzer/scan-build/c++-analyzer
        SCAN_BUILD=scan-build
    else
        echo ">>> WARNING: Scan-build binaries supposed to be in PATH environment variable due to unknown platform"
        CCC_ANALYZER=ccc-analyzer
        CXX_ANALYZER=c++-analyzer
        SCAN_BUILD=scan-build
    fi

    echo ">>> Generating scan-build report"
    rm -rf $SCAN_BUILD_DIR
    if [ $? -ne 0 ] ; then
        echo ">>> Scan-build directory removal error"
        exit 1
    fi
    mkdir $SCAN_BUILD_DIR
    if [ $? -ne 0 ] ; then
        echo ">>> Scan-build directory creation error"
        exit 1
    fi
    cd $SCAN_BUILD_DIR
    cmake -DCMAKE_BUILD_TYPE=Debug \
            -DCMAKE_C_COMPILER=$CCC_ANALYZER \
            -DCMAKE_CXX_COMPILER=$CXX_ANALYZER ../
    if [ $? -ne 0 ] ; then
        echo ">>> Scan-build configuration error"
        exit 1
    fi
    $SCAN_BUILD --use-analyzer=/usr/bin/clang++ \
            -analyze-headers \
            -o ${SCAN_BUILD_TMPDIR} \
            -enable-checker alpha.core \
            -enable-checker alpha.cplusplus \
            -enable-checker alpha.deadcode \
            -enable-checker alpha.security \
            -enable-checker alpha.unix \
            -enable-checker security \
            make
    if [ $? -ne 0 ] ; then
        echo ">>> Scan-build report generation error"
        exit 1
    fi
    # Get the directory name of the report created by scan-build
    SCAN_BUILD_REPORT=$(find $SCAN_BUILD_TMPDIR -maxdepth 1 -not -empty -not -name `basename $SCAN_BUILD_TMPDIR`)
    if [ $? -ne 0 ] ; then
        echo ">>> Scan-build report output directory identification error"
        exit 1
    fi
    if [ -z "$SCAN_BUILD_REPORT" ]; then
        echo ">>> No scan-build report has been generated"
    else
        echo ">>> Scan-build report has been generated in '$SCAN_BUILD_REPORT' directory"
        if [ ! -d "$SCAN_BUILD_ARCHIVE" ]; then
            mkdir "$SCAN_BUILD_ARCHIVE"
            if [ $? -ne 0 ] ; then
                echo ">>> Scan-build report archive directory creation error"
                exit 1
            fi
        else
            rm -rf $SCAN_BUILD_ARCHIVE/*
            if [ $? -ne 0 ] ; then
                echo ">>> Scan-build report archive directory cleanup error"
                exit 1
            fi
        fi
        echo ">>> Archiving scan-build report to '$SCAN_BUILD_ARCHIVE' directory"
        mv $SCAN_BUILD_REPORT/* $SCAN_BUILD_ARCHIVE/
        if [ $? -ne 0 ] ; then
            echo ">>> Scan-build report archiving error"
            exit 1
        fi
        rm -rf "$SCAN_BUILD_TMPDIR"
    fi
fi

# Doing Debug build

DEBUG_BUILD_DIR=$WORKSPACE/debug
echo ">>> Doing Debug build in '$DEBUG_BUILD_DIR' directory"
rm -rf $DEBUG_BUILD_DIR
if [ $? -ne 0 ] ; then
    echo ">>> Debug build directory removal error"
    exit 1
fi
mkdir $DEBUG_BUILD_DIR
if [ $? -ne 0 ] ; then
    echo ">>> Debug build directory creation error"
    exit 1
fi
cd $DEBUG_BUILD_DIR

cmake -DCMAKE_BUILD_TYPE=Debug -DGMOCK_SOURCE_DIR="$HOME/gmock-1.7.0" ../
if [ $? -ne 0 ] ; then
    echo ">>> Debug build configuration error"
    exit 1
fi
make
if [ $? -ne 0 ] ; then
    echo ">>> Debug build compilation error"
    exit 1
fi
CTEST_OUTPUT_ON_FAILURE=TRUE make test
if [ $? -ne 0 ] ; then
    echo ">>> Running tests on Debug build error"
    exit 1
fi
if [ "$PLATFORM" = "FreeBSD" ] ; then
    # TODO: Support for code coverage on FreeBSD
    echo ">>> Coverage report generation is not supported on FreeBSD at the moment"
else
    make coverage
    if [ $? -ne 0 ] ; then
        echo ">>> Code coverage report creation error"
        exit 1
    fi
fi

# Running valgrind/memcheck

if [ "$SKIP_MEMCHECK" = true ] ; then
    echo ">>> Skipping valgrind/memcheck report generation"
elif [ "$PLATFORM" = "FreeBSD" ] ; then
    # TODO: Valgrind causes error on FreeBSD, see https://bugs.kde.org/show_bug.cgi?id=306235
    echo ">>> Valgrind/memcheck report generation is not supported on FreeBSD, see https://bugs.kde.org/show_bug.cgi?id=306235"
elif [ "$LINUX_DISTRO" = "ALT Linux" ] ; then
    # TODO: Jenkins causes error on ALT Linux on publish valgrind report phase
    echo ">>> Valgrind/memcheck report generation is not supported on ALT Linux"
else
    echo ">>> Generating valgrind/memcheck report"
    make memcheck-report-xml
fi

# Doing Release build

RELEASE_BUILD_DIR=$WORKSPACE/release
echo ">>> Doing Release build in '$RELEASE_BUILD_DIR' directory"
cd $WORKSPACE
rm -rf $RELEASE_BUILD_DIR
if [ $? -ne 0 ] ; then
    echo ">>> Release build directory removal error"
    exit 1
fi
mkdir $RELEASE_BUILD_DIR
if [ $? -ne 0 ] ; then
    echo ">>> Release build directory creation error"
    exit 1
fi
cd $RELEASE_BUILD_DIR
cmake -DCMAKE_BUILD_TYPE=Release -DGMOCK_SOURCE_DIR="$HOME/gmock-1.7.0" ../
if [ $? -ne 0 ] ; then
    echo ">>> Release build configuration error"
    exit 1
fi
make
if [ $? -ne 0 ] ; then
    echo ">>> Release build compilation error"
    exit 1
fi
CTEST_OUTPUT_ON_FAILURE=TRUE make test
if [ $? -ne 0 ] ; then
    echo ">>> Running tests on Release build error"
    exit 1
fi

# Packaging

if [ "$SKIP_PACKAGING" = true ] ; then
    echo ">>> Skipping packaging"
elif [ "$LINUX_DISTRO" = "ALT Linux" ] ; then
    # TODO: Packaging support on ALT Linux
    echo ">>> Packaging is not supported on ALT Linux at the moment"
elif [ "$LINUX_DISTRO" = "Ubuntu" -o "$LINUX_DISTRO" = "Debian" ] ; then
    echo ">>> Making DEB-package"
    cpack -G DEB
    if [ $? -ne 0 ] ; then
        echo ">>> Making DEB-package error"
        exit 1
    fi
    echo ">>> Installing DEB-package"
    sudo dpkg -i *.deb
    if [ $? -ne 0 ] ; then
        echo ">>> Installing DEB-package error"
        exit 1
    fi
    echo ">>> Uninstalling DEB-package"
    sudo dpkg -r nfstrace
    if [ $? -ne 0 ] ; then
        echo ">>> Uninstalling DEB-package error"
        exit 1
    fi
#elif [ "$LINUX_DISTRO" = "CentOS Linux" -o "$LINUX_DISTRO" = "openSUSE" -o "$LINUX_DISTRO" = "ALT Linux" ] ; then
elif [ "$LINUX_DISTRO" = "CentOS Linux" -o "$LINUX_DISTRO" = "openSUSE" ] ; then
    echo ">>> Making RPM-package"
    cpack -G RPM
    echo ">>> Installing RPM-package"
    sudo rpm -i nfstrace*.rpm
    echo ">>> Uninstalling RPM-package"
    sudo rpm -e nfstrace
else
    echo ">>> Making archived package"
    make package
    if [ $? -ne 0 ] ; then
        echo ">>> Making archived package error"
        exit 1
    fi
    echo ">>> Installing NFSTrace"
    sudo make install
    if [ $? -ne 0 ] ; then
        echo ">>> NFSTrace installation error"
        exit 1
    fi
    echo ">>> Uninstalling NFSTrace"
    sudo xargs rm < install_manifest.txt
    if [ $? -ne 0 ] ; then
        echo ">>> NFSTrace uninstallation error"
        exit 1
    fi
fi
