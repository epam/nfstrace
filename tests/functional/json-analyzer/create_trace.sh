#!/bin/sh
#
# JSON-service functional test trace file creation script
# Author: Ilya Storozhilov
# Description: JSON-service functional test launcher script
# Copyright (c) 2013-2014 EPAM Systems
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

if [ "$#" -lt 2 ] ; then
    echo "Usage: $(basename $0) <nfs_dir> <trace_file.pcap>"
    exit 1
fi

NFS_DIR=$1
FILES_AMOUNT=5
FILES_SIZE="20K"
SLEEP_DELAY="0.1"

# Starting tcpdump
CURRENT_USER=$(whoami)
sudo tcpdump -i eth0 -w "$2" -Z $CURRENT_USER "port 2049" &
TCPDUMP_PID=$!
sleep 0.5

# Making FS-operations
for file_no in $(seq 1 $FILES_AMOUNT) ; do
    REMOTE_FILE="$NFS_DIR/test_file_$file_no"
    dd if=/dev/urandom of=$REMOTE_FILE bs=${FILES_SIZE} count=1
    sleep $SLEEP_DELAY
    LOCAL_FILE=$(mktemp)
    cp -v $REMOTE_FILE $LOCAL_FILE
    sleep $SLEEP_DELAY
    rm -f $LOCAL_FILE
    sleep $SLEEP_DELAY
done
ls -lh $NFS_DIR/
sleep $SLEEP_DELAY
rm -fv $NFS_DIR/*
sleep 0.5

# Stopping tcpdump
sudo kill $TCPDUMP_PID
wait $TCPDUMP_PID

# Compressing trace file
bzip2 -f "$2"
