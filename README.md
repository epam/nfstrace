[![License](https://img.shields.io/github/license/epam/nfstrace.svg)](http://opensource.org/licenses/GPL-2.0)
[![Language](https://img.shields.io/badge/language-C++11-blue.svg)](https://isocpp.org)
[![Release](https://img.shields.io/github/release/epam/nfstrace.svg)](https://github.com/epam/nfstrace/releases/latest)
[![Issues](https://img.shields.io/github/issues/epam/nfstrace.svg)](https://github.com/epam/nfstrace/issues?q=is%3Aopen+is%3Aissue)
NFSTRACE ![NFSTRACE Logo](docs/logo64.png "Logo")
========

`nfstrace` is an NFS and CIFS tracing/monitoring/capturing/analyzing tool.

It performs live Ethernet 1 Gbps - 10 Gbps packets capturing and helps to
determine NFS/CIFS procedures in raw network traffic. Furthermore, it performs
filtration, dumping, compression, statistical analysis, visualization and
provides the API for custom pluggable analysis modules.

`nfstrace` is written in C++11 programming language and currently supports the
following protocols:

- Ethernet
- IPv4 | IPv6
- UPD | TCP
- NFSv3 | NFSv4 | NFSv4.1 | CIFSv1 | CIFSv2

`nfstrace` has been tested on the following GNU/Linux and FreeBSD systems:

- Debian Sid [packages](https://packages.debian.org/unstable/main/nfstrace) [build-logs](https://buildd.debian.org/status/logs.php?pkg=nfstrace)
- Fedora 20
- OpenSUSE 13.2
- Ubuntu 14.04/14.10
- CentOS 7
- Arch Linux
- FreeBSD 10.1
- Alt Linux 7.0.5

You can find more detailed description at `docs/nfstrace_manual.pdf`

Problems, bugs, questions, desirable enhancements, etc. should be sent to
<nfstrace@epam.com>

External Dependencies
--------

- PCAP library (core component)
- json library (used for libjson.so plugin)
- Curses (used for libwatch.so plugin)
- GMock (used for testing)

Building
--------

Since `nfstrace` is written in C++11 you have to use `gcc` >= 4.8 or
`clang` >= 3.3.  Additionally, you need to install development version of
`libpcap` (version 1.3 or newer).

You can build `nfstrace` using [CMake](http://cmake.org) (version 2.8.12 or
newer). From the top level project's directory run:

    $ mkdir release
    $ cd release
    $ cmake -DCMAKE_BUILD_TYPE=release ../
    $ make

If you want to use specific compiler you can set the `CC` and `CXX` environment
variables:

    $ CC="path/to/clang" CXX="path/to/clang++" cmake -DCMAKE_BUILD_TYPE=release ../

If you want to specify different installation prefix:

    $ cmake -DCMAKE_INSTALL_PREFIX=/your/path ../


Installation
------------

By default `nfstrace` will be installed to `/usr/`.
After you build `nfstrace` simply run:

    $ sudo make install

If you're using rpm- or debian based Linux distribution you can try to generate
package for your system using `cpack`. Please note that you need rpm or debian
tools to be installed.

In order to generate rpm package:

    $ cpack -G RPM

In order to generate deb package:

    $ cpack -G DEB

After that you'll be able to install generated package using your package
manager.


Testing
-------

There are prepared dumps in `traces/` directory so you can perform quick sanity
check with the following command:

    $ make test

Please note that `ctest` is required in order to run tests, on some platforms
it is packaged separately from `cmake`.

Scripts will run `nfstrace` in different modes and compare its output with
reference results.


Authors
-------

Vitali  Adamenka    ([vitali_adamenka@epam.com](mailto:vitali_adamenka@epam.com))

Yauheni Azaranka    ([yauheni_azaranka@epam.com](mailto:yaheni_azaranka@epam.com))

Alexey  Costroma    ([alexey_costroma@epam.com](mailto:alexey_costroma@epam.com))

Dzianis Huznou      ([dzianis_huznou@epam.com](mailto:dzianis_huznou@epam.com))

Pavel   Karneliuk   ([pavel_karneliuk@epam.com](mailto:pavel_karneliuk@epam.com))

Andrey  Kuznetsov   ([andrey_kuznetsov@epam.com](mailto:andrey_kuznetsov@epam.com))

Mikhail Litvinets   ([mikhail_litvinets@epam.com](mailto:mikhail_litvinets@epam.com))

Ilya    Storozhilov ([ilya_storozhilov@epam.com](mailto:ilya_storozhilov@epam.com))


License
-------

Copyright (c) 2015 EPAM Systems

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
