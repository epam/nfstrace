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
namespace NST
{
namespace protocols
{
namespace NFS3
{

namespace NFS3 = NST::API::NFS3;

using ProcEnumNFS3 = API::ProcEnumNFS3;

using Validator = rpc::RPCProgramValidator
                <
                    100003,                 // SunRPC/NFS program
                    3,                      // v3
                    ProcEnumNFS3::NFS_NULL, // NFSPROC3_NULL
                    ProcEnumNFS3::COMMIT    // NFSPROC3_COMMIT
                >;

// Procedure 0: NULL - Do nothing
inline auto proc_t_of(NFS3::NULL3args&)->decltype(&NFS3::xdr_NULL3args)
{
    return &NFS3::xdr_NULL3args;
}

inline auto proc_t_of(NFS3::NULL3res&)->decltype(&NFS3::xdr_NULL3res)
{
    return &NFS3::xdr_NULL3res;
}

// Procedure 1: GETATTR - Get file attributes
inline auto proc_t_of(NFS3::GETATTR3args&)->decltype(&NFS3::xdr_GETATTR3args)
{
    return &NFS3::xdr_GETATTR3args;
}

inline auto proc_t_of(NFS3::GETATTR3res&)->decltype(&NFS3::xdr_GETATTR3res)
{
    return &NFS3::xdr_GETATTR3res;
}

// Procedure 2: SETATTR - Set file attributes
inline auto proc_t_of(NFS3::SETATTR3args&)->decltype(&NFS3::xdr_SETATTR3args)
{
    return &NFS3::xdr_SETATTR3args;
}

inline auto proc_t_of(NFS3::SETATTR3res&)->decltype(&NFS3::xdr_SETATTR3res)
{
    return &NFS3::xdr_SETATTR3res;
}

// Procedure 3: LOOKUP -  Lookup filename
inline auto proc_t_of(NFS3::LOOKUP3args&)->decltype(&NFS3::xdr_LOOKUP3args)
{
    return &NFS3::xdr_LOOKUP3args;
}

inline auto proc_t_of(NFS3::LOOKUP3res&)->decltype(&NFS3::xdr_LOOKUP3res)
{
    return &NFS3::xdr_LOOKUP3res;
}

// Procedure 4: ACCESS - Check Access Permission
inline auto proc_t_of(NFS3::ACCESS3args&)->decltype(&NFS3::xdr_ACCESS3args)
{
    return &NFS3::xdr_ACCESS3args;
}

inline auto proc_t_of(NFS3::ACCESS3res&)->decltype(&NFS3::xdr_ACCESS3res)
{
    return &NFS3::xdr_ACCESS3res;
}

// Procedure 5: READLINK - Read from symbolic link
inline auto proc_t_of(NFS3::READLINK3args&)->decltype(&NFS3::xdr_READLINK3args)
{
    return &NFS3::xdr_READLINK3args;
}

inline auto proc_t_of(NFS3::READLINK3res&)->decltype(&NFS3::xdr_READLINK3res)
{
    return &NFS3::xdr_READLINK3res;
}

// Procedure 6: READ - Read From file
inline auto proc_t_of(NFS3::READ3args&)->decltype(&NFS3::xdr_READ3args)
{
    return &NFS3::xdr_READ3args;
}

inline auto proc_t_of(NFS3::READ3res&)->decltype(&NFS3::xdr_READ3res)
{
    return &NFS3::xdr_READ3res;
}

// Procedure 7: WRITE - Write to file
inline auto proc_t_of(NFS3::WRITE3args&)->decltype(&NFS3::xdr_WRITE3args)
{
    return &NFS3::xdr_WRITE3args;
}

inline auto proc_t_of(NFS3::WRITE3res&)->decltype(&NFS3::xdr_WRITE3res)
{
    return &NFS3::xdr_WRITE3res;
}

// Procedure 8: CREATE - Create a file
inline auto proc_t_of(NFS3::CREATE3args&)->decltype(&NFS3::xdr_CREATE3args)
{
    return &NFS3::xdr_CREATE3args;
}

inline auto proc_t_of(NFS3::CREATE3res&)->decltype(&NFS3::xdr_CREATE3res)
{
    return &NFS3::xdr_CREATE3res;
}

// Procedure 9: MKDIR - Create a directory
inline auto proc_t_of(NFS3::MKDIR3args&)->decltype(&NFS3::xdr_MKDIR3args)
{
    return &NFS3::xdr_MKDIR3args;
}

inline auto proc_t_of(NFS3::MKDIR3res&)->decltype(&NFS3::xdr_MKDIR3res)
{
    return &NFS3::xdr_MKDIR3res;
}

// Procedure 10: SYMLINK - Create a symbolic link
inline auto proc_t_of(NFS3::SYMLINK3args&)->decltype(&NFS3::xdr_SYMLINK3args)
{
    return &NFS3::xdr_SYMLINK3args;
}

inline auto proc_t_of(NFS3::SYMLINK3res&)->decltype(&NFS3::xdr_SYMLINK3res)
{
    return &NFS3::xdr_SYMLINK3res;
}

// Procedure 11: MKNOD - Create a special device
inline auto proc_t_of(NFS3::MKNOD3args&)->decltype(&NFS3::xdr_MKNOD3args)
{
    return &NFS3::xdr_MKNOD3args;
}

inline auto proc_t_of(NFS3::MKNOD3res&)->decltype(&NFS3::xdr_MKNOD3res)
{
    return &NFS3::xdr_MKNOD3res;
}

// Procedure 12: REMOVE - Remove a File
inline auto proc_t_of(NFS3::REMOVE3args&)->decltype(&NFS3::xdr_REMOVE3args)
{
    return &NFS3::xdr_REMOVE3args;
}

inline auto proc_t_of(NFS3::REMOVE3res&)->decltype(&NFS3::xdr_REMOVE3res)
{
    return &NFS3::xdr_REMOVE3res;
}

// Procedure 13: RMDIR - Remove a Directory
inline auto proc_t_of(NFS3::RMDIR3args&)->decltype(&NFS3::xdr_RMDIR3args)
{
    return &NFS3::xdr_RMDIR3args;
}

inline auto proc_t_of(NFS3::RMDIR3res&)->decltype(&NFS3::xdr_RMDIR3res)
{
    return &NFS3::xdr_RMDIR3res;
}

// Procedure 14: RENAME - Rename a File or Directory
inline auto proc_t_of(NFS3::RENAME3args&)->decltype(&NFS3::xdr_RENAME3args)
{
    return &NFS3::xdr_RENAME3args;
}

inline auto proc_t_of(NFS3::RENAME3res&)->decltype(&NFS3::xdr_RENAME3res)
{
    return &NFS3::xdr_RENAME3res;
}

// Procedure 15: LINK - Create Link to an object
inline auto proc_t_of(NFS3::LINK3args&)->decltype(&NFS3::xdr_LINK3args)
{
    return &NFS3::xdr_LINK3args;
}

inline auto proc_t_of(NFS3::LINK3res&)->decltype(&NFS3::xdr_LINK3res)
{
    return &NFS3::xdr_LINK3res;
}

// Procedure 16: READDIR - Read From Directory
inline auto proc_t_of(NFS3::READDIR3args&)->decltype(&NFS3::xdr_READDIR3args)
{
    return &NFS3::xdr_READDIR3args;
}

inline auto proc_t_of(NFS3::READDIR3res&)->decltype(&NFS3::xdr_READDIR3res)
{
    return &NFS3::xdr_READDIR3res;
}

// Procedure 17: READDIRPLUS - Extended read from directory
inline auto proc_t_of(NFS3::READDIRPLUS3args&)->decltype(&NFS3::xdr_READDIRPLUS3args)
{
    return &NFS3::xdr_READDIRPLUS3args;
}

inline auto proc_t_of(NFS3::READDIRPLUS3res&)->decltype(&NFS3::xdr_READDIRPLUS3res)
{
    return &NFS3::xdr_READDIRPLUS3res;
}

// Procedure 18: FSSTAT - Get dynamic file system information
inline auto proc_t_of(NFS3::FSSTAT3args&)->decltype(&NFS3::xdr_FSSTAT3args)
{
    return &NFS3::xdr_FSSTAT3args;
}

inline auto proc_t_of(NFS3::FSSTAT3res&)->decltype(&NFS3::xdr_FSSTAT3res)
{
    return &NFS3::xdr_FSSTAT3res;
}

// Procedure 19: FSINFO - Get static file system Information
inline auto proc_t_of(NFS3::FSINFO3args&)->decltype(&NFS3::xdr_FSINFO3args)
{
    return &NFS3::xdr_FSINFO3args;
}

inline auto proc_t_of(NFS3::FSINFO3res&)->decltype(&NFS3::xdr_FSINFO3res)
{
    return &NFS3::xdr_FSINFO3res;
}

// Procedure 20: PATHCONF - Retrieve POSIX information
inline auto proc_t_of(NFS3::PATHCONF3args&)->decltype(&NFS3::xdr_PATHCONF3args)
{
    return &NFS3::xdr_PATHCONF3args;
}

inline auto proc_t_of(NFS3::PATHCONF3res&)->decltype(&NFS3::xdr_PATHCONF3res)
{
    return &NFS3::xdr_PATHCONF3res;
}

// Procedure 21: COMMIT - Commit cached data on a server to stable storage
inline auto proc_t_of(NFS3::COMMIT3args&)->decltype(&NFS3::xdr_COMMIT3args)
{
    return &NFS3::xdr_COMMIT3args;
}

inline auto proc_t_of(NFS3::COMMIT3res&)->decltype(&NFS3::xdr_COMMIT3res)
{
    return &NFS3::xdr_COMMIT3res;
}

extern "C"
NST_PUBLIC
const char* print_nfs3_procedures(const ProcEnumNFS3::NFSProcedure proc);

std::ostream& operator<<(std::ostream& out, const ProcEnumNFS3::NFSProcedure proc);

void print_mode3(std::ostream& out, const NFS3::uint32 val);
void print_access3(std::ostream& out, const NFS3::uint32 val);
std::ostream& operator<<(std::ostream& out, const NFS3::nfsstat3& obj);
std::ostream& operator<<(std::ostream& out, const NFS3::ftype3& obj);
std::ostream& operator<<(std::ostream& out, const NFS3::specdata3& obj);
std::ostream& operator<<(std::ostream& out, const NFS3::nfs_fh3& obj);
std::ostream& operator<<(std::ostream& out, const NFS3::nfstime3& obj);
std::ostream& operator<<(std::ostream& out, const NFS3::fattr3& obj);
std::ostream& operator<<(std::ostream& out, const NFS3::post_op_attr& obj);
std::ostream& operator<<(std::ostream& out, const NFS3::wcc_attr& obj);
std::ostream& operator<<(std::ostream& out, const NFS3::pre_op_attr& obj);
std::ostream& operator<<(std::ostream& out, const NFS3::wcc_data& obj);
std::ostream& operator<<(std::ostream& out, const NFS3::post_op_fh3& obj);
std::ostream& operator<<(std::ostream& out, const NFS3::time_how& obj);
std::ostream& operator<<(std::ostream& out, const NFS3::set_mode3& obj);
std::ostream& operator<<(std::ostream& out, const NFS3::set_uid3& obj);
std::ostream& operator<<(std::ostream& out, const NFS3::set_gid3& obj);
std::ostream& operator<<(std::ostream& out, const NFS3::set_size3& obj);
std::ostream& operator<<(std::ostream& out, const NFS3::set_atime& obj);
std::ostream& operator<<(std::ostream& out, const NFS3::set_mtime& obj);
std::ostream& operator<<(std::ostream& out, const NFS3::sattr3& obj);
std::ostream& operator<<(std::ostream& out, const NFS3::diropargs3& obj);
std::ostream& operator<<(std::ostream& out, const NFS3::sattrguard3& obj);
std::ostream& operator<<(std::ostream& out, const NFS3::stable_how& obj);
std::ostream& operator<<(std::ostream& out, const NFS3::createmode3& obj);
std::ostream& operator<<(std::ostream& out, const NFS3::createhow3& obj);
std::ostream& operator<<(std::ostream& out, const NFS3::symlinkdata3& obj);
std::ostream& operator<<(std::ostream& out, const NFS3::devicedata3& obj);
std::ostream& operator<<(std::ostream& out, const NFS3::mknoddata3& obj);
std::ostream& operator<<(std::ostream& out, const NFS3::entry3& obj);
std::ostream& operator<<(std::ostream& out, const NFS3::dirlist3& obj);
std::ostream& operator<<(std::ostream& out, const NFS3::entryplus3& obj);
std::ostream& operator<<(std::ostream& out, const NFS3::dirlistplus3& obj);

} // namespace NFS3
} // namespace protocols
} // namespace NST
//------------------------------------------------------------------------------
#endif//NFS3_UTILS_H
//------------------------------------------------------------------------------
