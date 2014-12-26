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
    echo "Platform identification error"
    exit 1
fi
if [ "$PLATFORM" = "Linux" ] ; then
    OS_RELEASE_FILE="/etc/os-release"
    if [ ! -r "$OS_RELEASE_FILE" ] ; then
        echo "Linux distro identification error: file '$OS_RELEASE_FILE' not found" >&2
        exit 1
    fi
    LINUX_DISTRO=$(grep "^NAME=" "$OS_RELEASE_FILE" | sed -e 's/NAME=//g' | sed -e 's/"//g')
fi

# Pulling environment
: ${WORKSPACE:="$(pwd)/$(dirname $0)/.."}

# Doing static analysis of the source-code

cd $WORKSPACE
if [ "$PLATFORM" = "Linux" -a "$LINUX_DISTRO" = "ALT Linux" ] ; then
    # TODO: Run cppcheck on ALT Linux
    echo "Will not generate cppcheck report on ALT Linux"
else
    echo "Generating cppcheck report"
    cppcheck --enable=all --std=c++11 --inconclusive --xml --xml-version=2 src analyzers/src 2> cppcheck.xml
    if [ $? -ne 0 ] ; then
        echo "Cppcheck report generation error"
        exit 1
    fi
fi

# Doing Debug build

DEBUG_BUILD_DIR=$WORKSPACE/debug
echo "Doing Debug build in '$DEBUG_BUILD_DIR' directory"
rm -rf $DEBUG_BUILD_DIR
if [ $? -ne 0 ] ; then
    echo "Debug build directory removal error"
    exit 1
fi
mkdir $DEBUG_BUILD_DIR
if [ $? -ne 0 ] ; then
    echo "Debug build directory creation error"
    exit 1
fi
cd $DEBUG_BUILD_DIR
cmake -DCMAKE_BUILD_TYPE=Debug -DGMOCK_SOURCE_DIR="$HOME/gmock-1.7.0" ../
if [ $? -ne 0 ] ; then
    echo "Debug build configuration error"
    exit 1
fi
make
if [ $? -ne 0 ] ; then
    echo "Debug build compilation error"
    exit 1
fi
CTEST_OUTPUT_ON_FAILURE=TRUE ctest -R unit*
if [ $? -ne 0 ] ; then
    echo "Running unit-tests on Debug build error"
    exit 1
fi
if [ "$PLATFORM" = "FreeBSD" ] ; then
    # TODO: Support for code coverage in FreeBSD
    echo "Will not generate coverage report on FreeBSD"
else
    make coverage
fi
if [ $? -ne 0 ] ; then
    echo "Code coverage report creation error"
    exit 1
fi
CTEST_OUTPUT_ON_FAILURE=TRUE ctest -E unit*
if [ $? -ne 0 ] ; then
    echo "Running functional tests on Debug build error"
    exit 1
fi

# Doing Release build

RELEASE_BUILD_DIR=$WORKSPACE/release
echo "Doing Release build in '$RELEASE_BUILD_DIR' directory"
cd $WORKSPACE
rm -rf $RELEASE_BUILD_DIR
if [ $? -ne 0 ] ; then
    echo "Release build directory removal error"
    exit 1
fi
mkdir $RELEASE_BUILD_DIR
if [ $? -ne 0 ] ; then
    echo "Release build directory creation error"
    exit 1
fi
cd $RELEASE_BUILD_DIR
cmake -DCMAKE_BUILD_TYPE=Release -DGMOCK_SOURCE_DIR="$HOME/gmock-1.7.0" ../
if [ $? -ne 0 ] ; then
    echo "Release build configuration error"
    exit 1
fi
make
if [ $? -ne 0 ] ; then
    echo "Release build compilation error"
    exit 1
fi
CTEST_OUTPUT_ON_FAILURE=TRUE make test
if [ $? -ne 0 ] ; then
    echo "Running tests on Release build error"
    exit 1
fi

# Packaging
# TODO: Install/uninstall package on ALT Linux (see below)

if [ "$LINUX_DISTRO" = "Ubuntu" -o "$LINUX_DISTRO" = "Debian" ] ; then
    echo "Making DEB-package"
    cpack -G DEB
    if [ $? -ne 0 ] ; then
        echo "Making DEB-package error"
        exit 1
    fi
    echo "Installing DEB-package"
    sudo dpkg -i *.deb
    if [ $? -ne 0 ] ; then
        echo "Installing DEB-package error"
        exit 1
    fi
    echo "Uninstalling DEB-package"
    sudo dpkg -r nfstrace
    if [ $? -ne 0 ] ; then
        echo "Uninstalling DEB-package error"
        exit 1
    fi
elif [ "$LINUX_DISTRO" = "CentOS Linux" -o "$LINUX_DISTRO" = "openSUSE" -o "$LINUX_DISTRO" = "ALT Linux" ] ; then
    if [ "$LINUX_DISTRO" = "ALT Linux" ] ; then
        # TODO: Remove it
        exit 0
    fi
    echo "Making RPM-package"
    cpack -G RPM
    echo "Installing RPM-package"
    sudo rpm -i nfstrace*.rpm
    echo "Uninstalling RPM-package"
    sudo rpm -e nfstrace
else
    echo "Making archived package"
    make package
    if [ $? -ne 0 ] ; then
        echo "Making archived package error"
        exit 1
    fi
    echo "Installing NFSTrace"
    sudo make install
    if [ $? -ne 0 ] ; then
        echo "NFSTrace installation error"
        exit 1
    fi
    echo "Uninstalling NFSTrace"
    sudo xargs rm < install_manifest.txt
    if [ $? -ne 0 ] ; then
        echo "NFSTrace uninstallation error"
        exit 1
    fi
fi
