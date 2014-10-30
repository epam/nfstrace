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
#
#------------------------------------------------------------------------------
set bmargin 7
set xtics scale 0
set output o_file 
set ytics nomirror
set terminal png size 1600,1200
set title system(sprintf("head -1 \"%s\"",i_file))
set xtics   ("NULL" 0, "COMPOUND" 1, "ILLEGAL" 2, "ACCESS" 3, "CLOSE" 4, "COMMIT" 5, "CREATE" 6, "DELEGPURGE" 7, "DELEGRETURN" 8, "GETATTR" 9, "GETFH" 10, "LINK" 11, "LOCK" 12, "LOCKT" 13, "LOCKU" 14, "LOOKUP" 15, "LOOKUPP" 16, "NVERIFY" 17, "OPEN" 18, "OPENATTR" 19, "OPEN_CONFIRM" 20, "OPEN_DOWNGRADE" 21, "PUTFH" 22, "PUTPUBFH" 23, "PUTROOTFH" 24, "READ" 25, "READDIR" 26, "READLINK" 27, "REMOVE" 28, "RENAME" 29, "RENEW" 30, "RESTOREFH" 31, "SAVEFH" 32, "SECINFO" 33, "SETATTR" 34, "SETCLIENTID" 35, "SETCLIENTID_CONFIRM" 36, "VERIFY" 37, "WRITE" 38, "RELEASE_LOCKOWNER" 39, "GET_DIR_DELEGATION" 40) rotate
plot i_file every ::1 using 3 with boxes title "Requests per nfs-operation", i_file every::1 using :3:2 with labels notitle offset 0,0.5
