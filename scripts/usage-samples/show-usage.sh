#/bin/sh

APP=../../release/nfstrace
MODULES=../../analyzers/release

echo 'This script demonstrates avaliable options for application and pluggable analysis modules'

$APP --help                                 \
     --analyzer=$MODULES/libbreakdown.so    \
     --analyzer=$MODULES/libofws.so         \
     --analyzer=$MODULES/libofdws.so
