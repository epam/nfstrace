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
SCR=$ROOT/analyzers/nst.sh
PLT=$ROOT/analyzers/breakdown.plt
DATA=$ROOT/traces/2sessions-tcp-wsize32k-tcp-wsize512k.pcap.bz2

echo "
-Information:-------------------------------------------------------------------
This script demonstrates ability to plot graphical representation of data 
collected by Operation Breakdown analyzer via gnuplot utility.

$SCR 
    provide collected by analyzers data to analyzer specific $PLT.
$PLT 
    gnuplot-script, familiar with output data format of Operation Breakdown analyzer.
    It generates *.png graphical files from *.dat files.

Dependencies:
-gnuplot should be installed.
--------------------------------------------------------------------------------
"

bzcat $DATA | $APP -m stat -I - -a $MOD/libbreakdown.so
$SCR -a $PLT -d . -p 'breakdown*.dat' -v
