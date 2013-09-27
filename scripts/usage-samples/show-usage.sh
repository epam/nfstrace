#/bin/sh

ROOT=$(dirname $0)/../..
APP=$ROOT/release/nfstrace
MOD=$ROOT/analyzers/release

echo '
-Information:-------------------------------------------------------------------
This script demonstrates avaliable options for the application and attached 
pluggable analysis modules.
--------------------------------------------------------------------------------
'

$APP --help                             \
     --analyzer=$MOD/libbreakdown.so    \
     --analyzer=$MOD/libofws.so         \
     --analyzer=$MOD/libofdws.so
