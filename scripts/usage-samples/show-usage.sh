#/bin/sh

APP=../../release/nfstrace
MODULES=../../analyzers/release

echo '
-Information:-------------------------------------------------------------------
This script demonstrates avaliable options for the application and attached 
pluggable analysis modules.
--------------------------------------------------------------------------------
'

$APP --help                                 \
     --analyzer=$MODULES/libbreakdown.so    \
     --analyzer=$MODULES/libofws.so         \
     --analyzer=$MODULES/libofdws.so
