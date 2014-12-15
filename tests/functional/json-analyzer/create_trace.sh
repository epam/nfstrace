#!/bin/sh
#
# Author: Ilya Storozhilov
# Description: JSON-service functional test trace file creation script
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
TARGET_DIR="$NFS_DIR/nfstrace"
FILES_AMOUNT=5
FILES_SIZE="20K"
SLEEP_DELAY="0.1"

# Starting tcpdump
CURRENT_USER=$(whoami)
sudo tcpdump -i eth0 -w "$2" -Z $CURRENT_USER "port 2049" &
#sudo netsniff-ng --in eth0 --out "$2" --silent --filter "port 2049" &
SNIFFER_PID=$!
sleep 0.5

mkdir $TARGET_DIR
sleep $SLEEP_DELAY
# Making FS-operations
for file_no in $(seq 1 $FILES_AMOUNT) ; do
    REMOTE_FILE="$TARGET_DIR/test_file_$file_no"
    dd if=/dev/urandom of=$REMOTE_FILE bs=${FILES_SIZE} count=1
    sleep $SLEEP_DELAY
    chmod a+w $REMOTE_FILE
    sleep $SLEEP_DELAY
    REMOTE_FILE_HARD_LINK_NAME="$REMOTE_FILE.hard_link"
    ln $REMOTE_FILE $REMOTE_FILE_HARD_LINK_NAME
    sleep $SLEEP_DELAY
    REMOTE_FILE_SOFT_LINK_NAME="$REMOTE_FILE.soft_link"
    ln -s $REMOTE_FILE $REMOTE_FILE_SOFT_LINK_NAME
    sleep $SLEEP_DELAY
    REMOTE_FILE_SOFT_LINK_RENAMED="$REMOTE_FILE.soft_link.renamed"
    mv $REMOTE_FILE_SOFT_LINK_NAME $REMOTE_FILE_SOFT_LINK_RENAMED
    sleep $SLEEP_DELAY
    LOCAL_FILE=$(mktemp)
    cp -v $REMOTE_FILE $LOCAL_FILE
    sleep $SLEEP_DELAY
    rm -f $LOCAL_FILE
    sleep $SLEEP_DELAY
done
df -h
sleep $SLEEP_DELAY
ls -lh $TARGET_DIR/
sleep $SLEEP_DELAY
rm -fv $TARGET_DIR/*
sleep $SLEEP_DELAY
rmdir $TARGET_DIR
sleep 0.5

# Stopping tcpdump
sudo kill $SNIFFER_PID
wait $SNIFFER_PID

# Compressing trace file
bzip2 -f "$2"
