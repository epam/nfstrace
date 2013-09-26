set bmargin 7
set xtics scale 0
set output o_file 
set ytics nomirror
set terminal png size 1600,1200
set title system(sprintf("head -1 %s",i_file))
set xtics   ("NULL" 0, "GETATTR" 1, "SETATTR" 2, "LOOKUP" 3, "ACCESS" 4, "READLINK" 5, "READ" 6, "WRITE" 7, "CREATE" 8, "MKDIR" 9, "SYMLINK" 10, "MKNOD" 11, "REMOVE" 12, "RMDIR" 13, "RENAME" 14, "LINK" 15, "READDIR" 16, "READDIRPLUS" 17, "FSSTAT" 18, "FSINFO" 19, "PATHCONF" 20, "COMMIT" 21) rotate
plot i_file every ::1 using 3 with boxes title "Requests per nfs-operation", i_file every::1 using :3:2 with labels notitle offset 0,0.5
