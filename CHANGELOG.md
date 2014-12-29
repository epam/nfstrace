0.3.2
=====
- new libjson plugin that outputs gathered statistics as json (via TCP);
- fix endianess bug on mips/powerpc/s390x/sparc;
- fix build issue on debian/kFreeBSD;
- add missing dependencies to cpack configuration;
- new `nfstrace` cli option: list available plugins and/or available interfaces.

0.3.1
=====
- new experimental `libwatch.so` plugin with functionality similar to the
  `nfswatch` utility;
- logging system:
    - path to log is no longer hardcoded;
    - timestamp is automatically added to the name of log;
    - SIGHUP handling in order to support log rotation mechanism;
- gtest/gmock integration;
- proper location for PAMs (`{install prefix}/lib/nfstrace/`);
- fixes in documentation, new sources are partially documented in doxygen style;
- minor bug fixes.
