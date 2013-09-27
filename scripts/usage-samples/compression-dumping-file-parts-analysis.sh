#/bin/sh

ROOT=$(dirname $0)/../..
APP=$ROOT/release/nfstrace
MOD=$ROOT/analyzers/release

echo '
-Information:-------------------------------------------------------------------
This script demonstrates live capturing NFS traffic over TCP or UDP to port 2049
from eth0 interface and dumping packets with NFS traffic to dump.pcap file and
compression of this file by external tool like bzip2 after end of capturing.

The dump file may be large. Th -D option was designed for this case. It defines
a size limit(in Mb) of parts for splitting dump file.

So, the compression of dump file performes by external tool passed by -C option
on each part of dump file. This way is similar to tcpdump -Z option.
The output archives may be merged and opened by any external tool (like Wireshark)
to inspect collected packets after unzipping.

The parts of dump file must be merged in right sequence.
The parts must follow by main dump.pcap.

After that, we extract data from compressed archives by bzcat and redirect output
via pipe to the application. The application works in statistic mode and reads
packets from stdin (-I - option) and performs analysis of filtered packets
by Operation Breakdown analyser.

Capturing from network interface requires superuser privileges.
The bzip2 and bzcat tools are used too.
Exit via Interrupt(Control-C) or Quit(Control-\) signal and wait finish of compression.
--------------------------------------------------------------------------------
'

# Dumping to dump.pcap file with compression output by bzip2 after end of capturing
$APP --mode=dump                                           \
     --interface=eth0                                      \
     --filter="tcp or udp port 2049"                       \
     -O dump.pcap                                          \
     -D 1                                                  \
     -C "bzip2 -f -9"

sleep 10 # wait end of compression process

PARTS=$(ls -tcr dump.pcap-*.bz2) # list of parts in right order 1,2,3,4,...n

# Extract dump.pcap from main compressed file and list of compressed parts.
# Then analyse data of dump.pcap file from stdin by libbreakdown.so module.
bzcat dump.pcap.bz2 $PARTS | $APP --mode=stat              \
     -I -                                                  \
     --analyzer=$MOD/libbreakdown.so
