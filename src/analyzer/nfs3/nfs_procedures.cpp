//------------------------------------------------------------------------------
//// Author: Dzianis Huznou
//// Description: Enumeration of the NFS procedures.
//// Copyright (c) 2013 EPAM Systems. All Rights Reserved.
////------------------------------------------------------------------------------
#include "nfs_procedures.h"
//------------------------------------------------------------------------------
//------------------------------------------------------------------------------
namespace NST
{
namespace analyzer 
{
namespace NFS3
{
    
const char* Proc::titles[Proc::num] = {
      "NULL",       "GETATTR",      "SETATTR",  "LOOKUP",
      "ACCESS",     "READLINK",     "READ",     "WRITE",
      "CREATE",     "MKDIR",        "SYMLINK",  "MKNOD",
      "REMOVE",     "RMDIR",        "RENAME",   "LINK",
      "READDIR",    "READDIRPLUS",  "FSSTAT",   "FSINFO",
      "PATHCONF",   "COMMIT"
};

} // namespace NFS3
} // namespace analyzer 
} // namespace NST
//------------------------------------------------------------------------------
