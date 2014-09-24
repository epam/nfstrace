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
#include "protocols/xdr/xdr_reader.h"
#include "protocols/rpc/rpc_header.h"
//------------------------------------------------------------------------------
using namespace NST::API;
using namespace NST::protocols::xdr;
//------------------------------------------------------------------------------
namespace NST
{
namespace protocols
{
namespace NFS3
{

using Validator = rpc::RPCProgramValidator
                <
                    100003,                 // SunRPC/NFS program
                    3,                      // v3
                    ProcEnumNFS3::NFS_NULL, // NFSPROC3_NULL
                    ProcEnumNFS3::COMMIT    // NFSPROC3_COMMIT
                >;

// Procedure 0: NULL - Do nothing
inline auto proc_t_of(rpcgen::NULL3args&)->decltype(&rpcgen::xdr_NULL3args)
{
    return &rpcgen::xdr_NULL3args;
}

inline auto proc_t_of(rpcgen::NULL3res&)->decltype(&rpcgen::xdr_NULL3res)
{
    return &rpcgen::xdr_NULL3res;
}

// Procedure 1: GETATTR - Get file attributes
inline auto proc_t_of(rpcgen::GETATTR3args&)->decltype(&rpcgen::xdr_GETATTR3args)
{
    return &rpcgen::xdr_GETATTR3args;
}

inline auto proc_t_of(rpcgen::GETATTR3res&)->decltype(&rpcgen::xdr_GETATTR3res)
{
    return &rpcgen::xdr_GETATTR3res;
}

// Procedure 2: SETATTR - Set file attributes
inline auto proc_t_of(rpcgen::SETATTR3args&)->decltype(&rpcgen::xdr_SETATTR3args)
{
    return &rpcgen::xdr_SETATTR3args;
}

inline auto proc_t_of(rpcgen::SETATTR3res&)->decltype(&rpcgen::xdr_SETATTR3res)
{
    return &rpcgen::xdr_SETATTR3res;
}

// Procedure 3: LOOKUP -  Lookup filename
inline auto proc_t_of(rpcgen::LOOKUP3args&)->decltype(&rpcgen::xdr_LOOKUP3args)
{
    return &rpcgen::xdr_LOOKUP3args;
}

inline auto proc_t_of(rpcgen::LOOKUP3res&)->decltype(&rpcgen::xdr_LOOKUP3res)
{
    return &rpcgen::xdr_LOOKUP3res;
}

// Procedure 4: ACCESS - Check Access Permission
inline auto proc_t_of(rpcgen::ACCESS3args&)->decltype(&rpcgen::xdr_ACCESS3args)
{
    return &rpcgen::xdr_ACCESS3args;
}

inline auto proc_t_of(rpcgen::ACCESS3res&)->decltype(&rpcgen::xdr_ACCESS3res)
{
    return &rpcgen::xdr_ACCESS3res;
}

// Procedure 5: READLINK - Read from symbolic link
inline auto proc_t_of(rpcgen::READLINK3args&)->decltype(&rpcgen::xdr_READLINK3args)
{
    return &rpcgen::xdr_READLINK3args;
}

inline auto proc_t_of(rpcgen::READLINK3res&)->decltype(&rpcgen::xdr_READLINK3res)
{
    return &rpcgen::xdr_READLINK3res;
}

// Procedure 6: READ - Read From file
inline auto proc_t_of(rpcgen::READ3args&)->decltype(&rpcgen::xdr_READ3args)
{
    return &rpcgen::xdr_READ3args;
}

inline auto proc_t_of(rpcgen::READ3res&)->decltype(&rpcgen::xdr_READ3res)
{
    return &rpcgen::xdr_READ3res;
}

// Procedure 7: WRITE - Write to file
inline auto proc_t_of(rpcgen::WRITE3args&)->decltype(&rpcgen::xdr_WRITE3args)
{
    return &rpcgen::xdr_WRITE3args;
}

inline auto proc_t_of(rpcgen::WRITE3res&)->decltype(&rpcgen::xdr_WRITE3res)
{
    return &rpcgen::xdr_WRITE3res;
}

// Procedure 8: CREATE - Create a file
inline auto proc_t_of(rpcgen::CREATE3args&)->decltype(&rpcgen::xdr_CREATE3args)
{
    return &rpcgen::xdr_CREATE3args;
}

inline auto proc_t_of(rpcgen::CREATE3res&)->decltype(&rpcgen::xdr_CREATE3res)
{
    return &rpcgen::xdr_CREATE3res;
}

// Procedure 9: MKDIR - Create a directory
inline auto proc_t_of(rpcgen::MKDIR3args&)->decltype(&rpcgen::xdr_MKDIR3args)
{
    return &rpcgen::xdr_MKDIR3args;
}

inline auto proc_t_of(rpcgen::MKDIR3res&)->decltype(&rpcgen::xdr_MKDIR3res)
{
    return &rpcgen::xdr_MKDIR3res;
}

// Procedure 10: SYMLINK - Create a symbolic link
inline auto proc_t_of(rpcgen::SYMLINK3args&)->decltype(&rpcgen::xdr_SYMLINK3args)
{
    return &rpcgen::xdr_SYMLINK3args;
}

inline auto proc_t_of(rpcgen::SYMLINK3res&)->decltype(&rpcgen::xdr_SYMLINK3res)
{
    return &rpcgen::xdr_SYMLINK3res;
}

// Procedure 11: MKNOD - Create a special device
inline auto proc_t_of(rpcgen::MKNOD3args&)->decltype(&rpcgen::xdr_MKNOD3args)
{
    return &rpcgen::xdr_MKNOD3args;
}

inline auto proc_t_of(rpcgen::MKNOD3res&)->decltype(&rpcgen::xdr_MKNOD3res)
{
    return &rpcgen::xdr_MKNOD3res;
}

// Procedure 12: REMOVE - Remove a File
inline auto proc_t_of(rpcgen::REMOVE3args&)->decltype(&rpcgen::xdr_REMOVE3args)
{
    return &rpcgen::xdr_REMOVE3args;
}

inline auto proc_t_of(rpcgen::REMOVE3res&)->decltype(&rpcgen::xdr_REMOVE3res)
{
    return &rpcgen::xdr_REMOVE3res;
}

// Procedure 13: RMDIR - Remove a Directory
inline auto proc_t_of(rpcgen::RMDIR3args&)->decltype(&rpcgen::xdr_RMDIR3args)
{
    return &rpcgen::xdr_RMDIR3args;
}

inline auto proc_t_of(rpcgen::RMDIR3res&)->decltype(&rpcgen::xdr_RMDIR3res)
{
    return &rpcgen::xdr_RMDIR3res;
}

// Procedure 14: RENAME - Rename a File or Directory
inline auto proc_t_of(rpcgen::RENAME3args&)->decltype(&rpcgen::xdr_RENAME3args)
{
    return &rpcgen::xdr_RENAME3args;
}

inline auto proc_t_of(rpcgen::RENAME3res&)->decltype(&rpcgen::xdr_RENAME3res)
{
    return &rpcgen::xdr_RENAME3res;
}

// Procedure 15: LINK - Create Link to an object
inline auto proc_t_of(rpcgen::LINK3args&)->decltype(&rpcgen::xdr_LINK3args)
{
    return &rpcgen::xdr_LINK3args;
}

inline auto proc_t_of(rpcgen::LINK3res&)->decltype(&rpcgen::xdr_LINK3res)
{
    return &rpcgen::xdr_LINK3res;
}

// Procedure 16: READDIR - Read From Directory
inline auto proc_t_of(rpcgen::READDIR3args&)->decltype(&rpcgen::xdr_READDIR3args)
{
    return &rpcgen::xdr_READDIR3args;
}

inline auto proc_t_of(rpcgen::READDIR3res&)->decltype(&rpcgen::xdr_READDIR3res)
{
    return &rpcgen::xdr_READDIR3res;
}

// Procedure 17: READDIRPLUS - Extended read from directory
inline auto proc_t_of(rpcgen::READDIRPLUS3args&)->decltype(&rpcgen::xdr_READDIRPLUS3args)
{
    return &rpcgen::xdr_READDIRPLUS3args;
}

inline auto proc_t_of(rpcgen::READDIRPLUS3res&)->decltype(&rpcgen::xdr_READDIRPLUS3res)
{
    return &rpcgen::xdr_READDIRPLUS3res;
}

// Procedure 18: FSSTAT - Get dynamic file system information
inline auto proc_t_of(rpcgen::FSSTAT3args&)->decltype(&rpcgen::xdr_FSSTAT3args)
{
    return &rpcgen::xdr_FSSTAT3args;
}

inline auto proc_t_of(rpcgen::FSSTAT3res&)->decltype(&rpcgen::xdr_FSSTAT3res)
{
    return &rpcgen::xdr_FSSTAT3res;
}

// Procedure 19: FSINFO - Get static file system Information
inline auto proc_t_of(rpcgen::FSINFO3args&)->decltype(&rpcgen::xdr_FSINFO3args)
{
    return &rpcgen::xdr_FSINFO3args;
}

inline auto proc_t_of(rpcgen::FSINFO3res&)->decltype(&rpcgen::xdr_FSINFO3res)
{
    return &rpcgen::xdr_FSINFO3res;
}

// Procedure 20: PATHCONF - Retrieve POSIX information
inline auto proc_t_of(rpcgen::PATHCONF3args&)->decltype(&rpcgen::xdr_PATHCONF3args)
{
    return &rpcgen::xdr_PATHCONF3args;
}

inline auto proc_t_of(rpcgen::PATHCONF3res&)->decltype(&rpcgen::xdr_PATHCONF3res)
{
    return &rpcgen::xdr_PATHCONF3res;
}

// Procedure 21: COMMIT - Commit cached data on a server to stable storage
inline auto proc_t_of(rpcgen::COMMIT3args&)->decltype(&rpcgen::xdr_COMMIT3args)
{
    return &rpcgen::xdr_COMMIT3args;
}

inline auto proc_t_of(rpcgen::COMMIT3res&)->decltype(&rpcgen::xdr_COMMIT3res)
{
    return &rpcgen::xdr_COMMIT3res;
}

extern "C"
NST_PUBLIC
const char* print_nfs3_procedures(const ProcEnumNFS3::NFSProcedure proc);

std::ostream& operator<<(std::ostream& out, const ProcEnumNFS3::NFSProcedure proc);

void print_mode3(std::ostream& out, const rpcgen::uint32 val);
void print_access3(std::ostream& out, const rpcgen::uint32 val);
std::ostream& operator<<(std::ostream& out, const rpcgen::nfsstat3& obj);
std::ostream& operator<<(std::ostream& out, const rpcgen::ftype3& obj);
std::ostream& operator<<(std::ostream& out, const rpcgen::specdata3& obj);
std::ostream& operator<<(std::ostream& out, const rpcgen::nfs_fh3& obj);
std::ostream& operator<<(std::ostream& out, const rpcgen::nfstime3& obj);
std::ostream& operator<<(std::ostream& out, const rpcgen::fattr3& obj);
std::ostream& operator<<(std::ostream& out, const rpcgen::post_op_attr& obj);
std::ostream& operator<<(std::ostream& out, const rpcgen::wcc_attr& obj);
std::ostream& operator<<(std::ostream& out, const rpcgen::pre_op_attr& obj);
std::ostream& operator<<(std::ostream& out, const rpcgen::wcc_data& obj);
std::ostream& operator<<(std::ostream& out, const rpcgen::post_op_fh3& obj);
std::ostream& operator<<(std::ostream& out, const rpcgen::time_how& obj);
std::ostream& operator<<(std::ostream& out, const rpcgen::set_mode3& obj);
std::ostream& operator<<(std::ostream& out, const rpcgen::set_uid3& obj);
std::ostream& operator<<(std::ostream& out, const rpcgen::set_gid3& obj);
std::ostream& operator<<(std::ostream& out, const rpcgen::set_size3& obj);
std::ostream& operator<<(std::ostream& out, const rpcgen::set_atime& obj);
std::ostream& operator<<(std::ostream& out, const rpcgen::set_mtime& obj);
std::ostream& operator<<(std::ostream& out, const rpcgen::sattr3& obj);
std::ostream& operator<<(std::ostream& out, const rpcgen::diropargs3& obj);
std::ostream& operator<<(std::ostream& out, const rpcgen::sattrguard3& obj);
std::ostream& operator<<(std::ostream& out, const rpcgen::stable_how& obj);
std::ostream& operator<<(std::ostream& out, const rpcgen::createmode3& obj);
std::ostream& operator<<(std::ostream& out, const rpcgen::createhow3& obj);
std::ostream& operator<<(std::ostream& out, const rpcgen::symlinkdata3& obj);
std::ostream& operator<<(std::ostream& out, const rpcgen::devicedata3& obj);
std::ostream& operator<<(std::ostream& out, const rpcgen::mknoddata3& obj);
std::ostream& operator<<(std::ostream& out, const rpcgen::entry3& obj);
std::ostream& operator<<(std::ostream& out, const rpcgen::dirlist3& obj);
std::ostream& operator<<(std::ostream& out, const rpcgen::entryplus3& obj);
std::ostream& operator<<(std::ostream& out, const rpcgen::dirlistplus3& obj);

} // namespace NFS3
} // namespace protocols
} // namespace NST
//------------------------------------------------------------------------------
#endif//NFS3_UTILS_H
//------------------------------------------------------------------------------
