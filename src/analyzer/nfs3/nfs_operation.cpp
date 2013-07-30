//------------------------------------------------------------------------------
// Author: Dzianis Huznou
// Description: Base structure for nfs-info.
// Copyright (c) 2013 EPAM Systems. All Rights Reserved.
//------------------------------------------------------------------------------
#include "nfs_operation.h"
//------------------------------------------------------------------------------
//------------------------------------------------------------------------------
namespace NST
{
namespace analyzer
{
namespace NFS3
{

const char* Proc::Titles[Proc::num] =
{
  "NULL",       "GETATTR",      "SETATTR",  "LOOKUP",
  "ACCESS",     "READLINK",     "READ",     "WRITE",
  "CREATE",     "MKDIR",        "SYMLINK",  "MKNOD",
  "REMOVE",     "RMDIR",        "RENAME",   "LINK",
  "READDIR",    "READDIRPLUS",  "FSSTAT",   "FSINFO",
  "PATHCONF",   "COMMIT"
};

std::ostream& operator<<(std::ostream& out, const Proc::Enum proc)
{
    return out << Proc::Titles[proc];
}

} // namespace NFS3
} // namespace filter
} // namespace NST
//------------------------------------------------------------------------------
