#/bin/sh

ROOT=$(dirname $0)/../..
APP=$ROOT/release/nfstrace
MOD=$ROOT/release/analyzers

echo '
-Information:-------------------------------------------------------------------
This script demonstrates live capturing NFS traffic over TCP or UDP to port 2049
from eth0 network interface and performs Operation Breakdown analysis filtered 
NFS procedures by pluggable module libbreakdown.so.
Capturing from network interface requires superuser privileges.
Exit via Interrupt(Control-C) signal.
--------------------------------------------------------------------------------
'

$APP --mode=live                                           \
     --interface=eth0                                      \
     --filtration="ip and port 2049"                       \
     --analysis=$MOD/libbreakdown.so
