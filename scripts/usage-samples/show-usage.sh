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
This script demonstrates avaliable options for the application and attached 
pluggable analysis modules.
--------------------------------------------------------------------------------
'

$APP --help                             \
     --analysis=$MOD/libbreakdown.so    \
     --analysis=$MOD/libofws.so         \
     --analysis=$MOD/libofdws.so
