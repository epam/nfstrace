#include "print_analyzer.h"

namespace NST
{
namespace analyzer 
{
    
const char* ProcNFS3::titles[ProcNFS3::num] = {
      "null",       "getattr",      "setattr",  "lookup",
      "access",     "readlink",     "read",     "write",
      "create",     "mkdir",        "symlink",  "mknod",
      "remove",     "rmdir",        "rename",   "link",
      "readdir",    "readdirplus",  "fsstat",   "fsinfo",
      "pathconf",   "commit",
};

} // namespace analyzer
} // namespace NST
