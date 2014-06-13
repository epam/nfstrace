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
set xtics   ("NULL" 0, "GETATTR" 1, "SETATTR" 2, "LOOKUP" 3, "ACCESS" 4, "READLINK" 5, "READ" 6, "WRITE" 7, "CREATE" 8, "MKDIR" 9, "SYMLINK" 10, "MKNOD" 11, "REMOVE" 12, "RMDIR" 13, "RENAME" 14, "LINK" 15, "READDIR" 16, "READDIRPLUS" 17, "FSSTAT" 18, "FSINFO" 19, "PATHCONF" 20, "COMMIT" 21) rotate
plot i_file every ::1 using 3 with boxes title "Requests per nfs-operation", i_file every::1 using :3:2 with labels notitle offset 0,0.5
