#/bin/sh

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
