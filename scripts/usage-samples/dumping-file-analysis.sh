#/bin/sh

ROOT=$(dirname $0)/../..
APP=$ROOT/release/nfstrace
MOD=$ROOT/analyzers/release

echo '
-Information:-------------------------------------------------------------------
This script demonstrates live capturing NFS traffic over TCP or UDP to port 2049
from eth0 interface and dumping packets with NFS traffic to dump.pcap file.

The output file may be open by any external tool (like Wireshark) to inspect
collected packets.

After that, the application runs in statistic mode to analyse filtered packets
by Operation Breakdown analyser.

Capturing from network interface requires superuser privileges.
Exit via Interrupt(Control-C) or Quit(Control-\) signal.
--------------------------------------------------------------------------------
'

# Dumping to dump.pcap file
$APP --mode=dump                                           \
     --interface=eth0                                      \
     --filter="tcp or udp port 2049"                       \
     -O dump.pcap

# Analyse dump.pcap file by libbreakdown.so module
$APP --mode=stat                                           \
     -I dump.pcap                                          \
     --analyzer=$MOD/libbreakdown.so
