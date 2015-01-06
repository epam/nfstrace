//------------------------------------------------------------------------------
// Author: Dzianis Huznou (Alexey Costroma)
// Description: Helpers for parsing NFS structures.
// Copyright (c) 2014 EPAM Systems
//------------------------------------------------------------------------------
/*
    This file is part of Nfstrace.

    Nfstrace is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, version 2 of the License.

    Nfstrace is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with Nfstrace.  If not, see <http://www.gnu.org/licenses/>.
*/
//------------------------------------------------------------------------------
#define NST_PUBLIC __attribute__ ((visibility("default")))
#ifndef NFS3_UTILS_H
#define NFS3_UTILS_H
//------------------------------------------------------------------------------
#include <cassert>
#include <ostream>

#include "api/nfs_types.h"
#include "api/nfs3_types_rpcgen.h"

#include "protocols/xdr/xdr_decoder.h"
#include "protocols/rpc/rpc_header.h"
//------------------------------------------------------------------------------
using namespace NST::API::NFS3;
using namespace NST::protocols::xdr;
//------------------------------------------------------------------------------
namespace NST
{
namespace protocols
{
namespace NFS3
{

using ProcEnumNFS3 = API::ProcEnumNFS3;

using Validator = rpc::RPCProgramValidator
                <
                    100003,                 // SunRPC/NFS program
                    3,                      // v3
                    ProcEnumNFS3::NFS_NULL, // NFSPROC3_NULL
                    ProcEnumNFS3::COMMIT    // NFSPROC3_COMMIT
                >;

// Procedure 0: NULL - Do nothing
inline auto proc_t_of(NULL3args&)->decltype(&xdr_NULL3args)
{
    return &xdr_NULL3args;
}

inline auto proc_t_of(NULL3res&)->decltype(&xdr_NULL3res)
{
    return &xdr_NULL3res;
}

// Procedure 1: GETATTR - Get file attributes
inline auto proc_t_of(GETATTR3args&)->decltype(&xdr_GETATTR3args)
{
    return &xdr_GETATTR3args;
}

inline auto proc_t_of(GETATTR3res&)->decltype(&xdr_GETATTR3res)
{
    return &xdr_GETATTR3res;
}

// Procedure 2: SETATTR - Set file attributes
inline auto proc_t_of(SETATTR3args&)->decltype(&xdr_SETATTR3args)
{
    return &xdr_SETATTR3args;
}

inline auto proc_t_of(SETATTR3res&)->decltype(&xdr_SETATTR3res)
{
    return &xdr_SETATTR3res;
}

// Procedure 3: LOOKUP -  Lookup filename
inline auto proc_t_of(LOOKUP3args&)->decltype(&xdr_LOOKUP3args)
{
    return &xdr_LOOKUP3args;
}

inline auto proc_t_of(LOOKUP3res&)->decltype(&xdr_LOOKUP3res)
{
    return &xdr_LOOKUP3res;
}

// Procedure 4: ACCESS - Check Access Permission
inline auto proc_t_of(ACCESS3args&)->decltype(&xdr_ACCESS3args)
{
    return &xdr_ACCESS3args;
}

inline auto proc_t_of(ACCESS3res&)->decltype(&xdr_ACCESS3res)
{
    return &xdr_ACCESS3res;
}

// Procedure 5: READLINK - Read from symbolic link
inline auto proc_t_of(READLINK3args&)->decltype(&xdr_READLINK3args)
{
    return &xdr_READLINK3args;
}

inline auto proc_t_of(READLINK3res&)->decltype(&xdr_READLINK3res)
{
    return &xdr_READLINK3res;
}

// Procedure 6: READ - Read From file
inline auto proc_t_of(READ3args&)->decltype(&xdr_READ3args)
{
    return &xdr_READ3args;
}

inline auto proc_t_of(READ3res&)->decltype(&xdr_READ3res)
{
    return &xdr_READ3res;
}

// Procedure 7: WRITE - Write to file
inline auto proc_t_of(WRITE3args&)->decltype(&xdr_WRITE3args)
{
    return &xdr_WRITE3args;
}

inline auto proc_t_of(WRITE3res&)->decltype(&xdr_WRITE3res)
{
    return &xdr_WRITE3res;
}

// Procedure 8: CREATE - Create a file
inline auto proc_t_of(CREATE3args&)->decltype(&xdr_CREATE3args)
{
    return &xdr_CREATE3args;
}

inline auto proc_t_of(CREATE3res&)->decltype(&xdr_CREATE3res)
{
    return &xdr_CREATE3res;
}

// Procedure 9: MKDIR - Create a directory
inline auto proc_t_of(MKDIR3args&)->decltype(&xdr_MKDIR3args)
{
    return &xdr_MKDIR3args;
}

inline auto proc_t_of(MKDIR3res&)->decltype(&xdr_MKDIR3res)
{
    return &xdr_MKDIR3res;
}

// Procedure 10: SYMLINK - Create a symbolic link
inline auto proc_t_of(SYMLINK3args&)->decltype(&xdr_SYMLINK3args)
{
    return &xdr_SYMLINK3args;
}

inline auto proc_t_of(SYMLINK3res&)->decltype(&xdr_SYMLINK3res)
{
    return &xdr_SYMLINK3res;
}

// Procedure 11: MKNOD - Create a special device
inline auto proc_t_of(MKNOD3args&)->decltype(&xdr_MKNOD3args)
{
    return &xdr_MKNOD3args;
}

inline auto proc_t_of(MKNOD3res&)->decltype(&xdr_MKNOD3res)
{
    return &xdr_MKNOD3res;
}

// Procedure 12: REMOVE - Remove a File
inline auto proc_t_of(REMOVE3args&)->decltype(&xdr_REMOVE3args)
{
    return &xdr_REMOVE3args;
}

inline auto proc_t_of(REMOVE3res&)->decltype(&xdr_REMOVE3res)
{
    return &xdr_REMOVE3res;
}

// Procedure 13: RMDIR - Remove a Directory
inline auto proc_t_of(RMDIR3args&)->decltype(&xdr_RMDIR3args)
{
    return &xdr_RMDIR3args;
}

inline auto proc_t_of(RMDIR3res&)->decltype(&xdr_RMDIR3res)
{
    return &xdr_RMDIR3res;
}

// Procedure 14: RENAME - Rename a File or Directory
inline auto proc_t_of(RENAME3args&)->decltype(&xdr_RENAME3args)
{
    return &xdr_RENAME3args;
}

inline auto proc_t_of(RENAME3res&)->decltype(&xdr_RENAME3res)
{
    return &xdr_RENAME3res;
}

// Procedure 15: LINK - Create Link to an object
inline auto proc_t_of(LINK3args&)->decltype(&xdr_LINK3args)
{
    return &xdr_LINK3args;
}

inline auto proc_t_of(LINK3res&)->decltype(&xdr_LINK3res)
{
    return &xdr_LINK3res;
}

// Procedure 16: READDIR - Read From Directory
inline auto proc_t_of(READDIR3args&)->decltype(&xdr_READDIR3args)
{
    return &xdr_READDIR3args;
}

inline auto proc_t_of(READDIR3res&)->decltype(&xdr_READDIR3res)
{
    return &xdr_READDIR3res;
}

// Procedure 17: READDIRPLUS - Extended read from directory
inline auto proc_t_of(READDIRPLUS3args&)->decltype(&xdr_READDIRPLUS3args)
{
    return &xdr_READDIRPLUS3args;
}

inline auto proc_t_of(READDIRPLUS3res&)->decltype(&xdr_READDIRPLUS3res)
{
    return &xdr_READDIRPLUS3res;
}

// Procedure 18: FSSTAT - Get dynamic file system information
inline auto proc_t_of(FSSTAT3args&)->decltype(&xdr_FSSTAT3args)
{
    return &xdr_FSSTAT3args;
}

inline auto proc_t_of(FSSTAT3res&)->decltype(&xdr_FSSTAT3res)
{
    return &xdr_FSSTAT3res;
}

// Procedure 19: FSINFO - Get static file system Information
inline auto proc_t_of(FSINFO3args&)->decltype(&xdr_FSINFO3args)
{
    return &xdr_FSINFO3args;
}

inline auto proc_t_of(FSINFO3res&)->decltype(&xdr_FSINFO3res)
{
    return &xdr_FSINFO3res;
}

// Procedure 20: PATHCONF - Retrieve POSIX information
inline auto proc_t_of(PATHCONF3args&)->decltype(&xdr_PATHCONF3args)
{
    return &xdr_PATHCONF3args;
}

inline auto proc_t_of(PATHCONF3res&)->decltype(&xdr_PATHCONF3res)
{
    return &xdr_PATHCONF3res;
}

// Procedure 21: COMMIT - Commit cached data on a server to stable storage
inline auto proc_t_of(COMMIT3args&)->decltype(&xdr_COMMIT3args)
{
    return &xdr_COMMIT3args;
}

inline auto proc_t_of(COMMIT3res&)->decltype(&xdr_COMMIT3res)
{
    return &xdr_COMMIT3res;
}

extern "C"
NST_PUBLIC
const char* print_nfs3_procedures(const ProcEnumNFS3::NFSProcedure proc);

std::ostream& operator<<(std::ostream& out, const ProcEnumNFS3::NFSProcedure proc);

void print_mode3(std::ostream& out, const uint32 val);
void print_access3(std::ostream& out, const uint32 val);
std::ostream& operator<<(std::ostream& out, const nfsstat3& obj);
std::ostream& operator<<(std::ostream& out, const ftype3& obj);
std::ostream& operator<<(std::ostream& out, const specdata3& obj);
std::ostream& operator<<(std::ostream& out, const nfs_fh3& obj);
std::ostream& operator<<(std::ostream& out, const nfstime3& obj);
std::ostream& operator<<(std::ostream& out, const fattr3& obj);
std::ostream& operator<<(std::ostream& out, const post_op_attr& obj);
std::ostream& operator<<(std::ostream& out, const wcc_attr& obj);
std::ostream& operator<<(std::ostream& out, const pre_op_attr& obj);
std::ostream& operator<<(std::ostream& out, const wcc_data& obj);
std::ostream& operator<<(std::ostream& out, const post_op_fh3& obj);
std::ostream& operator<<(std::ostream& out, const time_how& obj);
std::ostream& operator<<(std::ostream& out, const set_mode3& obj);
std::ostream& operator<<(std::ostream& out, const set_uid3& obj);
std::ostream& operator<<(std::ostream& out, const set_gid3& obj);
std::ostream& operator<<(std::ostream& out, const set_size3& obj);
std::ostream& operator<<(std::ostream& out, const set_atime& obj);
std::ostream& operator<<(std::ostream& out, const set_mtime& obj);
std::ostream& operator<<(std::ostream& out, const sattr3& obj);
std::ostream& operator<<(std::ostream& out, const diropargs3& obj);
std::ostream& operator<<(std::ostream& out, const sattrguard3& obj);
std::ostream& operator<<(std::ostream& out, const stable_how& obj);
std::ostream& operator<<(std::ostream& out, const createmode3& obj);
std::ostream& operator<<(std::ostream& out, const createhow3& obj);
std::ostream& operator<<(std::ostream& out, const symlinkdata3& obj);
std::ostream& operator<<(std::ostream& out, const devicedata3& obj);
std::ostream& operator<<(std::ostream& out, const mknoddata3& obj);
std::ostream& operator<<(std::ostream& out, const entry3& obj);
std::ostream& operator<<(std::ostream& out, const dirlist3& obj);
std::ostream& operator<<(std::ostream& out, const entryplus3& obj);
std::ostream& operator<<(std::ostream& out, const dirlistplus3& obj);

} // namespace NFS3
} // namespace protocols
} // namespace NST
//------------------------------------------------------------------------------
#endif//NFS3_UTILS_H
//------------------------------------------------------------------------------
