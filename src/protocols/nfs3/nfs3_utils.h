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
#ifndef NFS3_UTILS_H
#define NFS3_UTILS_H
//------------------------------------------------------------------------------
#include <cassert>
#include <ostream>

#include "api/nfs3_types_rpcgen.h"
#include "api/nfs_types.h"

#include "protocols/rpc/rpc_header.h"
#include "protocols/xdr/xdr_decoder.h"
//------------------------------------------------------------------------------
//------------------------------------------------------------------------------
namespace NST
{
namespace protocols
{
namespace NFS3
{
namespace NFS3 = NST::API::NFS3;

using ProcEnumNFS3 = API::ProcEnumNFS3;

using Validator = rpc::RPCProgramValidator<
    100003,                 // SunRPC/NFS program
    3,                      // v3
    ProcEnumNFS3::NFS_NULL, // NFSPROC3_NULL
    ProcEnumNFS3::COMMIT    // NFSPROC3_COMMIT
    >;

// clang-format off
bool_t xdr_uint64 (XDR *, NFS3::uint64*);
bool_t xdr_uint32 (XDR *, NFS3::uint32*);
bool_t xdr_int64 (XDR *, NFS3::int64*);
bool_t xdr_int32 (XDR *, NFS3::int32*);
bool_t xdr_filename3 (XDR *, NFS3::filename3*);
bool_t xdr_nfspath3 (XDR *, NFS3::nfspath3*);
bool_t xdr_fileid3 (XDR *, NFS3::fileid3*);
bool_t xdr_cookie3 (XDR *, NFS3::cookie3*);
bool_t xdr_cookieverf3 (XDR *, NFS3::cookieverf3);
bool_t xdr_createverf3 (XDR *, NFS3::createverf3);
bool_t xdr_writeverf3 (XDR *, NFS3::writeverf3);
bool_t xdr_uid3 (XDR *, NFS3::uid3*);
bool_t xdr_gid3 (XDR *, NFS3::gid3*);
bool_t xdr_size3 (XDR *, NFS3::size3*);
bool_t xdr_offset3 (XDR *, NFS3::offset3*);
bool_t xdr_mode3 (XDR *, NFS3::mode3*);
bool_t xdr_count3 (XDR *, NFS3::count3*);
bool_t xdr_nfsstat3 (XDR *, NFS3::nfsstat3*);
bool_t xdr_ftype3 (XDR *, NFS3::ftype3*);
bool_t xdr_specdata3 (XDR *, NFS3::specdata3*);
bool_t xdr_nfs_fh3 (XDR *, NFS3::nfs_fh3*);
bool_t xdr_nfstime3 (XDR *, NFS3::nfstime3*);
bool_t xdr_fattr3 (XDR *, NFS3::fattr3*);
bool_t xdr_post_op_attr (XDR *, NFS3::post_op_attr*);
bool_t xdr_wcc_attr (XDR *, NFS3::wcc_attr*);
bool_t xdr_pre_op_attr (XDR *, NFS3::pre_op_attr*);
bool_t xdr_wcc_data (XDR *, NFS3::wcc_data*);
bool_t xdr_post_op_fh3 (XDR *, NFS3::post_op_fh3*);
bool_t xdr_time_how (XDR *, NFS3::time_how*);
bool_t xdr_set_mode3 (XDR *, NFS3::set_mode3*);
bool_t xdr_set_uid3 (XDR *, NFS3::set_uid3*);
bool_t xdr_set_gid3 (XDR *, NFS3::set_gid3*);
bool_t xdr_set_size3 (XDR *, NFS3::set_size3*);
bool_t xdr_set_atime (XDR *, NFS3::set_atime*);
bool_t xdr_set_mtime (XDR *, NFS3::set_mtime*);
bool_t xdr_sattr3 (XDR *, NFS3::sattr3*);
bool_t xdr_diropargs3 (XDR *, NFS3::diropargs3*);
bool_t xdr_NULL3args (XDR *, NFS3::NULL3args*); // for compatibility
bool_t xdr_NULL3res (XDR *, NFS3::NULL3res*);   // for compatibility
bool_t xdr_GETATTR3args (XDR *, NFS3::GETATTR3args*);
bool_t xdr_GETATTR3resok (XDR *, NFS3::GETATTR3resok*);
bool_t xdr_GETATTR3res (XDR *, NFS3::GETATTR3res*);
bool_t xdr_sattrguard3 (XDR *, NFS3::sattrguard3*);
bool_t xdr_SETATTR3args (XDR *, NFS3::SETATTR3args*);
bool_t xdr_SETATTR3resok (XDR *, NFS3::SETATTR3resok*);
bool_t xdr_SETATTR3resfail (XDR *, NFS3::SETATTR3resfail*);
bool_t xdr_SETATTR3res (XDR *, NFS3::SETATTR3res*);
bool_t xdr_LOOKUP3args (XDR *, NFS3::LOOKUP3args*);
bool_t xdr_LOOKUP3resok (XDR *, NFS3::LOOKUP3resok*);
bool_t xdr_LOOKUP3resfail (XDR *, NFS3::LOOKUP3resfail*);
bool_t xdr_LOOKUP3res (XDR *, NFS3::LOOKUP3res*);
bool_t xdr_ACCESS3args (XDR *, NFS3::ACCESS3args*);
bool_t xdr_ACCESS3resok (XDR *, NFS3::ACCESS3resok*);
bool_t xdr_ACCESS3resfail (XDR *, NFS3::ACCESS3resfail*);
bool_t xdr_ACCESS3res (XDR *, NFS3::ACCESS3res*);
bool_t xdr_READLINK3args (XDR *, NFS3::READLINK3args*);
bool_t xdr_READLINK3resok (XDR *, NFS3::READLINK3resok*);
bool_t xdr_READLINK3resfail (XDR *, NFS3::READLINK3resfail*);
bool_t xdr_READLINK3res (XDR *, NFS3::READLINK3res*);
bool_t xdr_READ3args (XDR *, NFS3::READ3args*);
bool_t xdr_READ3resok (XDR *, NFS3::READ3resok*);
bool_t xdr_READ3resfail (XDR *, NFS3::READ3resfail*);
bool_t xdr_READ3res (XDR *, NFS3::READ3res*);
bool_t xdr_stable_how (XDR *, NFS3::stable_how*);
bool_t xdr_WRITE3args (XDR *, NFS3::WRITE3args*);
bool_t xdr_WRITE3resok (XDR *, NFS3::WRITE3resok*);
bool_t xdr_WRITE3resfail (XDR *, NFS3::WRITE3resfail*);
bool_t xdr_WRITE3res (XDR *, NFS3::WRITE3res*);
bool_t xdr_createmode3 (XDR *, NFS3::createmode3*);
bool_t xdr_createhow3 (XDR *, NFS3::createhow3*);
bool_t xdr_CREATE3args (XDR *, NFS3::CREATE3args*);
bool_t xdr_CREATE3resok (XDR *, NFS3::CREATE3resok*);
bool_t xdr_CREATE3resfail (XDR *, NFS3::CREATE3resfail*);
bool_t xdr_CREATE3res (XDR *, NFS3::CREATE3res*);
bool_t xdr_MKDIR3args (XDR *, NFS3::MKDIR3args*);
bool_t xdr_MKDIR3resok (XDR *, NFS3::MKDIR3resok*);
bool_t xdr_MKDIR3resfail (XDR *, NFS3::MKDIR3resfail*);
bool_t xdr_MKDIR3res (XDR *, NFS3::MKDIR3res*);
bool_t xdr_symlinkdata3 (XDR *, NFS3::symlinkdata3*);
bool_t xdr_SYMLINK3args (XDR *, NFS3::SYMLINK3args*);
bool_t xdr_SYMLINK3resok (XDR *, NFS3::SYMLINK3resok*);
bool_t xdr_SYMLINK3resfail (XDR *, NFS3::SYMLINK3resfail*);
bool_t xdr_SYMLINK3res (XDR *, NFS3::SYMLINK3res*);
bool_t xdr_devicedata3 (XDR *, NFS3::devicedata3*);
bool_t xdr_mknoddata3 (XDR *, NFS3::mknoddata3*);
bool_t xdr_MKNOD3args (XDR *, NFS3::MKNOD3args*);
bool_t xdr_MKNOD3resok (XDR *, NFS3::MKNOD3resok*);
bool_t xdr_MKNOD3resfail (XDR *, NFS3::MKNOD3resfail*);
bool_t xdr_MKNOD3res (XDR *, NFS3::MKNOD3res*);
bool_t xdr_REMOVE3args (XDR *, NFS3::REMOVE3args*);
bool_t xdr_REMOVE3resok (XDR *, NFS3::REMOVE3resok*);
bool_t xdr_REMOVE3resfail (XDR *, NFS3::REMOVE3resfail*);
bool_t xdr_REMOVE3res (XDR *, NFS3::REMOVE3res*);
bool_t xdr_RMDIR3args (XDR *, NFS3::RMDIR3args*);
bool_t xdr_RMDIR3resok (XDR *, NFS3::RMDIR3resok*);
bool_t xdr_RMDIR3resfail (XDR *, NFS3::RMDIR3resfail*);
bool_t xdr_RMDIR3res (XDR *, NFS3::RMDIR3res*);
bool_t xdr_RENAME3args (XDR *, NFS3::RENAME3args*);
bool_t xdr_RENAME3resok (XDR *, NFS3::RENAME3resok*);
bool_t xdr_RENAME3resfail (XDR *, NFS3::RENAME3resfail*);
bool_t xdr_RENAME3res (XDR *, NFS3::RENAME3res*);
bool_t xdr_LINK3args (XDR *, NFS3::LINK3args*);
bool_t xdr_LINK3resok (XDR *, NFS3::LINK3resok*);
bool_t xdr_LINK3resfail (XDR *, NFS3::LINK3resfail*);
bool_t xdr_LINK3res (XDR *, NFS3::LINK3res*);
bool_t xdr_READDIR3args (XDR *, NFS3::READDIR3args*);
bool_t xdr_entry3 (XDR *, NFS3::entry3*);
bool_t xdr_dirlist3 (XDR *, NFS3::dirlist3*);
bool_t xdr_READDIR3resok (XDR *, NFS3::READDIR3resok*);
bool_t xdr_READDIR3resfail (XDR *, NFS3::READDIR3resfail*);
bool_t xdr_READDIR3res (XDR *, NFS3::READDIR3res*);
bool_t xdr_READDIRPLUS3args (XDR *, NFS3::READDIRPLUS3args*);
bool_t xdr_entryplus3 (XDR *, NFS3::entryplus3*);
bool_t xdr_dirlistplus3 (XDR *, NFS3::dirlistplus3*);
bool_t xdr_READDIRPLUS3resok (XDR *, NFS3::READDIRPLUS3resok*);
bool_t xdr_READDIRPLUS3resfail (XDR *, NFS3::READDIRPLUS3resfail*);
bool_t xdr_READDIRPLUS3res (XDR *, NFS3::READDIRPLUS3res*);
bool_t xdr_FSSTAT3args (XDR *, NFS3::FSSTAT3args*);
bool_t xdr_FSSTAT3resok (XDR *, NFS3::FSSTAT3resok*);
bool_t xdr_FSSTAT3resfail (XDR *, NFS3::FSSTAT3resfail*);
bool_t xdr_FSSTAT3res (XDR *, NFS3::FSSTAT3res*);
bool_t xdr_FSINFO3args (XDR *, NFS3::FSINFO3args*);
bool_t xdr_FSINFO3resok (XDR *, NFS3::FSINFO3resok*);
bool_t xdr_FSINFO3resfail (XDR *, NFS3::FSINFO3resfail*);
bool_t xdr_FSINFO3res (XDR *, NFS3::FSINFO3res*);
bool_t xdr_PATHCONF3args (XDR *, NFS3::PATHCONF3args*);
bool_t xdr_PATHCONF3resok (XDR *, NFS3::PATHCONF3resok*);
bool_t xdr_PATHCONF3resfail (XDR *, NFS3::PATHCONF3resfail*);
bool_t xdr_PATHCONF3res (XDR *, NFS3::PATHCONF3res*);
bool_t xdr_COMMIT3args (XDR *, NFS3::COMMIT3args*);
bool_t xdr_COMMIT3resok (XDR *, NFS3::COMMIT3resok*);
bool_t xdr_COMMIT3resfail (XDR *, NFS3::COMMIT3resfail*);
bool_t xdr_COMMIT3res (XDR *, NFS3::COMMIT3res*);
// clang-format on

// Procedure 0: NULL - Do nothing
inline auto proc_t_of(NFS3::NULL3args&) -> decltype(&xdr_NULL3args)
{
    return &xdr_NULL3args;
}

inline auto proc_t_of(NFS3::NULL3res&) -> decltype(&xdr_NULL3res)
{
    return &xdr_NULL3res;
}

// Procedure 1: GETATTR - Get file attributes
inline auto proc_t_of(NFS3::GETATTR3args&) -> decltype(&xdr_GETATTR3args)
{
    return &xdr_GETATTR3args;
}

inline auto proc_t_of(NFS3::GETATTR3res&) -> decltype(&xdr_GETATTR3res)
{
    return &xdr_GETATTR3res;
}

// Procedure 2: SETATTR - Set file attributes
inline auto proc_t_of(NFS3::SETATTR3args&) -> decltype(&xdr_SETATTR3args)
{
    return &xdr_SETATTR3args;
}

inline auto proc_t_of(NFS3::SETATTR3res&) -> decltype(&xdr_SETATTR3res)
{
    return &xdr_SETATTR3res;
}

// Procedure 3: LOOKUP -  Lookup filename
inline auto proc_t_of(NFS3::LOOKUP3args&) -> decltype(&xdr_LOOKUP3args)
{
    return &xdr_LOOKUP3args;
}

inline auto proc_t_of(NFS3::LOOKUP3res&) -> decltype(&xdr_LOOKUP3res)
{
    return &xdr_LOOKUP3res;
}

// Procedure 4: ACCESS - Check Access Permission
inline auto proc_t_of(NFS3::ACCESS3args&) -> decltype(&xdr_ACCESS3args)
{
    return &xdr_ACCESS3args;
}

inline auto proc_t_of(NFS3::ACCESS3res&) -> decltype(&xdr_ACCESS3res)
{
    return &xdr_ACCESS3res;
}

// Procedure 5: READLINK - Read from symbolic link
inline auto proc_t_of(NFS3::READLINK3args&) -> decltype(&xdr_READLINK3args)
{
    return &xdr_READLINK3args;
}

inline auto proc_t_of(NFS3::READLINK3res&) -> decltype(&xdr_READLINK3res)
{
    return &xdr_READLINK3res;
}

// Procedure 6: READ - Read From file
inline auto proc_t_of(NFS3::READ3args&) -> decltype(&xdr_READ3args)
{
    return &xdr_READ3args;
}

inline auto proc_t_of(NFS3::READ3res&) -> decltype(&xdr_READ3res)
{
    return &xdr_READ3res;
}

// Procedure 7: WRITE - Write to file
inline auto proc_t_of(NFS3::WRITE3args&) -> decltype(&xdr_WRITE3args)
{
    return &xdr_WRITE3args;
}

inline auto proc_t_of(NFS3::WRITE3res&) -> decltype(&xdr_WRITE3res)
{
    return &xdr_WRITE3res;
}

// Procedure 8: CREATE - Create a file
inline auto proc_t_of(NFS3::CREATE3args&) -> decltype(&xdr_CREATE3args)
{
    return &xdr_CREATE3args;
}

inline auto proc_t_of(NFS3::CREATE3res&) -> decltype(&xdr_CREATE3res)
{
    return &xdr_CREATE3res;
}

// Procedure 9: MKDIR - Create a directory
inline auto proc_t_of(NFS3::MKDIR3args&) -> decltype(&xdr_MKDIR3args)
{
    return &xdr_MKDIR3args;
}

inline auto proc_t_of(NFS3::MKDIR3res&) -> decltype(&xdr_MKDIR3res)
{
    return &xdr_MKDIR3res;
}

// Procedure 10: SYMLINK - Create a symbolic link
inline auto proc_t_of(NFS3::SYMLINK3args&) -> decltype(&xdr_SYMLINK3args)
{
    return &xdr_SYMLINK3args;
}

inline auto proc_t_of(NFS3::SYMLINK3res&) -> decltype(&xdr_SYMLINK3res)
{
    return &xdr_SYMLINK3res;
}

// Procedure 11: MKNOD - Create a special device
inline auto proc_t_of(NFS3::MKNOD3args&) -> decltype(&xdr_MKNOD3args)
{
    return &xdr_MKNOD3args;
}

inline auto proc_t_of(NFS3::MKNOD3res&) -> decltype(&xdr_MKNOD3res)
{
    return &xdr_MKNOD3res;
}

// Procedure 12: REMOVE - Remove a File
inline auto proc_t_of(NFS3::REMOVE3args&) -> decltype(&xdr_REMOVE3args)
{
    return &xdr_REMOVE3args;
}

inline auto proc_t_of(NFS3::REMOVE3res&) -> decltype(&xdr_REMOVE3res)
{
    return &xdr_REMOVE3res;
}

// Procedure 13: RMDIR - Remove a Directory
inline auto proc_t_of(NFS3::RMDIR3args&) -> decltype(&xdr_RMDIR3args)
{
    return &xdr_RMDIR3args;
}

inline auto proc_t_of(NFS3::RMDIR3res&) -> decltype(&xdr_RMDIR3res)
{
    return &xdr_RMDIR3res;
}

// Procedure 14: RENAME - Rename a File or Directory
inline auto proc_t_of(NFS3::RENAME3args&) -> decltype(&xdr_RENAME3args)
{
    return &xdr_RENAME3args;
}

inline auto proc_t_of(NFS3::RENAME3res&) -> decltype(&xdr_RENAME3res)
{
    return &xdr_RENAME3res;
}

// Procedure 15: LINK - Create Link to an object
inline auto proc_t_of(NFS3::LINK3args&) -> decltype(&xdr_LINK3args)
{
    return &xdr_LINK3args;
}

inline auto proc_t_of(NFS3::LINK3res&) -> decltype(&xdr_LINK3res)
{
    return &xdr_LINK3res;
}

// Procedure 16: READDIR - Read From Directory
inline auto proc_t_of(NFS3::READDIR3args&) -> decltype(&xdr_READDIR3args)
{
    return &xdr_READDIR3args;
}

inline auto proc_t_of(NFS3::READDIR3res&) -> decltype(&xdr_READDIR3res)
{
    return &xdr_READDIR3res;
}

// Procedure 17: READDIRPLUS - Extended read from directory
inline auto proc_t_of(NFS3::READDIRPLUS3args&) -> decltype(&xdr_READDIRPLUS3args)
{
    return &xdr_READDIRPLUS3args;
}

inline auto proc_t_of(NFS3::READDIRPLUS3res&) -> decltype(&xdr_READDIRPLUS3res)
{
    return &xdr_READDIRPLUS3res;
}

// Procedure 18: FSSTAT - Get dynamic file system information
inline auto proc_t_of(NFS3::FSSTAT3args&) -> decltype(&xdr_FSSTAT3args)
{
    return &xdr_FSSTAT3args;
}

inline auto proc_t_of(NFS3::FSSTAT3res&) -> decltype(&xdr_FSSTAT3res)
{
    return &xdr_FSSTAT3res;
}

// Procedure 19: FSINFO - Get static file system Information
inline auto proc_t_of(NFS3::FSINFO3args&) -> decltype(&xdr_FSINFO3args)
{
    return &xdr_FSINFO3args;
}

inline auto proc_t_of(NFS3::FSINFO3res&) -> decltype(&xdr_FSINFO3res)
{
    return &xdr_FSINFO3res;
}

// Procedure 20: PATHCONF - Retrieve POSIX information
inline auto proc_t_of(NFS3::PATHCONF3args&) -> decltype(&xdr_PATHCONF3args)
{
    return &xdr_PATHCONF3args;
}

inline auto proc_t_of(NFS3::PATHCONF3res&) -> decltype(&xdr_PATHCONF3res)
{
    return &xdr_PATHCONF3res;
}

// Procedure 21: COMMIT - Commit cached data on a server to stable storage
inline auto proc_t_of(NFS3::COMMIT3args&) -> decltype(&xdr_COMMIT3args)
{
    return &xdr_COMMIT3args;
}

inline auto proc_t_of(NFS3::COMMIT3res&) -> decltype(&xdr_COMMIT3res)
{
    return &xdr_COMMIT3res;
}

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
#endif // NFS3_UTILS_H
//------------------------------------------------------------------------------
