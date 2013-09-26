#/bin/sh

APP=../../release/nfstrace
MODULES=../../analyzers/release

echo '
-Information:-------------------------------------------------------------------
This script demonstrates live capturing NFS traffic over TCP or UDP to port 2049
from eth0 network interface and traces out filtered NFS procedures to console.
Capturing from network interface requires superuser privileges.
Exit via Interrupt(Control-C) or Quit(Control-\) signal.
--------------------------------------------------------------------------------
'

$APP --mode=live                                           \
     --interface=eth0                                      \
     --filter="tcp or udp port 2049"                       \
     --verbose
