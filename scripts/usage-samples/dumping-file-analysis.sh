#/bin/sh

ROOT=$(dirname $0)/../..
APP=$ROOT/release/nfstrace
MOD=$ROOT/release/analyzers

echo '
-Information:-------------------------------------------------------------------
This script demonstrates live capturing NFS traffic over TCP or UDP to port 2049
from eth0 interface and dumping packets with NFS traffic to dump.pcap file.

The output file may be open by any external tool (like Wireshark) to inspect
collected packets.

After that, the application runs in statistic mode to analyse filtered packets
by Operation Breakdown analyser.

Capturing from network interface requires superuser privileges.
Exit via Interrupt(Control-C) signal.
--------------------------------------------------------------------------------
'

# Dumping to dump.pcap file
$APP --mode=dump                                           \
     --interface=eth0                                      \
     --filtration="ip and port 2049"                       \
     -O dump.pcap

# Analyse dump.pcap file by libbreakdown.so module
$APP --mode=stat                                           \
     -I dump.pcap                                          \
     --analysis=$MOD/libbreakdown.so
