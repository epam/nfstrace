#/bin/sh

ROOT=$(dirname $0)/../..
APP=$ROOT/release/nfstrace
MOD=$ROOT/release/analyzers

echo '
-Information:-------------------------------------------------------------------
This script demonstrates live capturing NFS traffic over TCP or UDP to port 2049
from eth0 interface and dumping packets with NFS traffic to dump.pcap file and
compression of this file by external tool like bzip2 after end of capturing.

The compression of dump file performes by external tool passed by -C option.
This way is similar to tcpdump -Z option.
The output file may be open by any external tool (like Wireshark) to inspect
collected packets after unzipping.

After that, we extract data from compressed archive by bzcat and redirect output
via pipe to the application. The application works in statistic mode and reads
packets from stdin (-I - option) and performs analysis of filtered packets
by Operation Breakdown analyser.

Capturing from network interface requires superuser privileges.
The bzip2 and bzcat tools are used too.
Exit via Interrupt(Control-C) signal and wait finish of compression.
--------------------------------------------------------------------------------
'

# Dumping to dump.pcap file with compression output by bzip2 after end of capturing
$APP --mode=dump                                           \
     --interface=eth0                                      \
     --filtration="ip and port 2049"                       \
     -O dump.pcap                                          \
     -C "bzip2 -f -9"

# Extract dump.pcap from dump.pcap.bz2 and analyse data
# of dump.pcap file from stdin by libbreakdown.so module
bzcat dump.pcap.bz2 | $APP --mode=stat                     \
     -I -                                                  \
     --analysis=$MOD/libbreakdown.so
