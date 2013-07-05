#include "nfs_procedures.h"

namespace NST
{
namespace filter 
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
} // namespace filter
} // namespace NST

