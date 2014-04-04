#/bin/sh

ROOT=$(dirname $0)/../..
APP=$ROOT/release/nfstrace
MOD=$ROOT/release/analyzers

echo '
-Information:-------------------------------------------------------------------
This script demonstrates avaliable options for the application and attached 
pluggable analysis modules.
--------------------------------------------------------------------------------
'

$APP --help                             \
     --analysis=$MOD/libbreakdown.so    \
     --analysis=$MOD/libofws.so         \
     --analysis=$MOD/libofdws.so
