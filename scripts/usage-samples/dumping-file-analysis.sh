#/bin/sh
#------------------------------------------------------------------------------
#    Copyright (c) 2013 EPAM Systems
#------------------------------------------------------------------------------
#
#    This file is part of Nfstrace.
#
#    Nfstrace is free software: you can redistribute it and/or modify
#    it under the terms of the GNU General Public License as published by
#    the Free Software Foundation, version 2 of the License.
#
#    Nfstrace is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#    GNU General Public License for more details.
#
#    You should have received a copy of the GNU General Public License
#    along with Nfstrace.  If not, see <http://www.gnu.org/licenses/>.
#------------------------------------------------------------------------------

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
     --filtration="ip and port 2049"                       \
     -O dump.pcap

# Analyse dump.pcap file by libbreakdown.so module
$APP --mode=stat                                           \
     -I dump.pcap                                          \
     --analysis=$MOD/libbreakdown.so
