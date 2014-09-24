NFSTRACE
===============================================================================

The nfstrace tool performs live Ethernet 1Gbps - 10Gbps packet’s capturing and 
helps to determine NFS procedures in raw network traffic. It performs packets capturing,
filtration, dumping traces, compression, statistical analysis, visualization and
provides API for custom analysis modules.

The nfstrace supports following protocols: Ethernet – IPv4|IPv6 – UDP|TCP – NFSv3|NFSv4.

Detailed technical description you can find in *docs/NFSTRACE.Releasenotes.pdf*
or on the following [page](https://docs.google.com/document/d/185ghjXQOhYllzZzmAi2VJg38lk2tnAchGvmgW0ua9Wo/edit?usp=sharing)

Problems, bugs, questions, desirable enhancements, etc. should be sent to <nfstrace@epam.com>

### Original authors:
Vitali  Adamenka ([vitali_adamenka@epam.com](mailto:vitali_adamenka@epam.com))

Yauheni Azaranka ([yauheni_azaranka@epam.com](mailto:yaheni_azaranka@epam.com))

Alexey  Costroma ([alexey_costroma@epam.com](mailto:alexey_costroma@epam.com))

Dzianis Huznou ([dzianis_huznou@epam.com](mailto:dzianis_huznou@epam.com))

Pavel   Karneliuk ([pavel_karneliuk@epam.com](mailto:pavel_karneliuk@epam.com))

Mikhail Litvinets ([mikhail_litvinets@epam.com](mailto:mikhail_litvinets@epam.com))


### Build by CMake

Create a build directory in top-level directory:

    $ mkdir ./release

Change into your build directory:

    $ cd ./release

Run cmake pointing it to the directory of the top-level CMakeLists.txt.

The *-DCMAKE_BUILD_TYPE=Release* produces release configuration.

Other configurations(*Debug, MinSizeRel, RelWithDebInfo*) are avaliable likewise.

CMake will check compiler, libraries and generate build scripts for main
application, analyzers and tests. All files will be created in current directory.

Note: In FreeBSD 8.4 your need to install gcc >= 4.8 and edit */etc/libmap.conf*
according to this [page](http://www.freebsd.org/doc/en/articles/custom-gcc/article.html)

    $ cmake -DCMAKE_BUILD_TYPE=Release ../

After that, you can start to build application:

    $ make

Binaries will be created in current directory

### Build by CMake with special compiler

Set up environment variables with path to the compiler:

for Linux:

    $ export CC="/usr/bin/gcc"
    $ export CXX="/usr/bin/g++"

for FreeBSD:

    $ setenv CC "/usr/local/bin/gcc48"
    $ setenv CXX "/usr/local/bin/g++48"

Then build by CMake as described above or pass these variables to shell
directly for cmake command, f.e.:

    $ CC="/usr/bin/gcc48" CXX="/usr/bin/g++48" cmake -DCMAKE_BUILD_TYPE=Release ../

### Installation by CMake

Create a build directory in top-level directory:

    $ mkdir ./release

Change into your build directory:

    $ cd ./release

Run CMake to generate build scripts main application and it's plugins

(Note: Use */usr* or */usr/local* for most cases):

    $ cmake -DCMAKE_INSTALL_PREFIX=/your/path ../

Run make. It will build and install nfstrace and it's plugins and plugin api
headers in */usr/bin*, */usr/lib/nfstrace/* and
*/usr/include/nfstrace* respectively:

    $ sudo make install

### Test by CMake

Build application and run following command from build directory:

    $ make test

Scripts will compare output of processing traces with reference results.

### Version

0.3.0

### Copyright

Copyright (c) 2013, 2014 EPAM Systems

### License

Nfstrace is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, version 2 of the License.

Nfstrace is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with Nfstrace.
If not, [see](http://www.gnu.org/licenses/).
