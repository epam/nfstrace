#include "nfs_struct.h"

namespace NST
{
namespace filter 
{
namespace NFS3
{
    
const char* Proc::titles[Proc::num] = {
      "null",       "getattr",      "setattr",  "lookup",
      "access",     "readlink",     "read",     "write",
      "create",     "mkdir",        "symlink",  "mknod",
      "remove",     "rmdir",        "rename",   "link",
      "readdir",    "readdirplus",  "fsstat",   "fsinfo",
      "pathconf",   "commit"
};


} // namespace NFS3
} // namespace filter
} // namespace NST

