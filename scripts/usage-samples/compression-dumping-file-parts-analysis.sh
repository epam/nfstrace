#/bin/sh

ROOT=$(dirname $0)/../..
APP=$ROOT/release/nfstrace
MOD=$ROOT/release/analyzers

echo '
-Information:-------------------------------------------------------------------
This script demonstrates live capturing NFS traffic over TCP or UDP to port 2049
from eth0 interface and dumping packets with NFS traffic to dump.pcap file and
compression of this file by external tool like bzip2 after end of capturing.

The dump file may be large. The -D option was designed for this case. It defines
a size limit(in Mb) of parts for splitting dump file.

So, the compression of dump file performes by external tool passed by -C option
on each part of dump file. This way is similar to tcpdump -Z option.
The output archives may be merged and opened by any external tool(like Wireshark)
to inspect collected packets after unzipping.

The parts of dump file must be merged in right sequence starting by dump.pcap.

After that, we extract data from compressed archives by bzcat and redirect output
via pipe to the application. The application works in statistic mode(--mode=stat)
and reads packets from stdin (-I - option) and performs analysis of filtered 
packets by Operation Breakdown analyser.

Capturing from network interface requires superuser privileges.
The bzip2 and bzcat tools are used too.
Exit via Interrupt(Control-C) signal and wait finish of compression.
--------------------------------------------------------------------------------
'

# Dumping to dump.pcap file with compression output by bzip2 after end of capturing
$APP --mode=dump                                           \
     --filtration="ip and port 2049"                       \
     -O dump.pcap                                          \
     -D 1                                                  \
     -C "bzip2 -f -9"

echo "wait end of compression all parts (10 seconds)"
sleep 10 # wait end of compression process

# list of parts in right order: dump.pcap.bz2 dump.pcap-1.bz2 dump.pcap-2.bz2
PARTS=$(ls dump.pcap*.bz2 | sort -n -t - -k 2)
echo "
The list of compressed parts:
$PARTS
"

# Extract dump.pcap from main compressed file and list of compressed parts.
# Then analyse data of dump.pcap file from stdin by libbreakdown.so module.
bzcat $PARTS | $APP --mode=stat                            \
     -I -                                                  \
     --analysis=$MOD/libbreakdown.so
