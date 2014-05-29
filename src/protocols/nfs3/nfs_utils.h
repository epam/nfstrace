//------------------------------------------------------------------------------
// Author: Dzianis Huznou
// Description: Helpers for parsing NFS structures.
// Copyright (c) 2013 EPAM Systems. All Rights Reserved.
//------------------------------------------------------------------------------
#ifndef NFS_UTILS_H
#define NFS_UTILS_H
//------------------------------------------------------------------------------
#include <cassert>
#include <ostream>

#include "api/nfs3_types.h"

#include "protocols/xdr/xdr_reader.h"
#include "protocols/rpc/rpc_header.h"
//------------------------------------------------------------------------------
//------------------------------------------------------------------------------
namespace NST
{
namespace protocols
{
namespace NFS3
{

using namespace NST::API;

using namespace NST::protocols::xdr;

using Validator = rpc::RPCProgramValidator
                <
                    100003,             // SunRPC/NFS program
                    3,                  // v3
                    ProcEnum::NFS_NULL, // NFSPROC3_NULL
                    ProcEnum::COMMIT    // NFSPROC3_COMMIT
                >;

static const char* const NFSProcedureTitles[ProcEnum::count] =
{
  "NULL",       "GETATTR",      "SETATTR",  "LOOKUP",
  "ACCESS",     "READLINK",     "READ",     "WRITE",
  "CREATE",     "MKDIR",        "SYMLINK",  "MKNOD",
  "REMOVE",     "RMDIR",        "RENAME",   "LINK",
  "READDIR",    "READDIRPLUS",  "FSSTAT",   "FSINFO",
  "PATHCONF",   "COMMIT"
};

inline XDRReader& operator>>(XDRReader& in, mode3& obj)
{
    return in >> obj.mode;
}

inline XDRReader& operator>>(XDRReader& in, nfsstat3& obj)
{
    return in >> obj.stat;
}

inline XDRReader& operator>>(XDRReader& in, ftype3& obj)
{
    return in >> obj.ftype;
}

inline XDRReader& operator>>(XDRReader& in, specdata3& obj)
{
    const size_t size = sizeof(obj.specdata1) +
                        sizeof(obj.specdata2);
    in.arrange_check(size);
    in.read_unchecked(obj.specdata1);
    in.read_unchecked(obj.specdata2);
    return in;
}

inline XDRReader& operator>>(XDRReader& in, nfs_fh3& obj)
{
    in.read_variable_len(obj.data); // opaque data size should be less than NFS3_FHSIZE
    assert(obj.data.size() < NFS3_FHSIZE);
    return in;
}

inline XDRReader& operator>>(XDRReader& in, nfstime3& obj)
{
    const size_t size = sizeof(obj.seconds) +
                        sizeof(obj.nseconds);
    in.arrange_check(size);
    in.read_unchecked(obj.seconds);
    in.read_unchecked(obj.nseconds);
    return in;
}

inline XDRReader& operator>>(XDRReader& in, fattr3& obj)
{
    const size_t size = sizeof(obj.type) +
                        sizeof(obj.mode.mode) +
                        sizeof(obj.nlink) +
                        sizeof(obj.uid) +
                        sizeof(obj.gid) +
                        sizeof(obj.size) +
                        sizeof(obj.used) +
                        sizeof(obj.rdev) +
                        sizeof(obj.fsid) +
                        sizeof(obj.fileid);
    in.arrange_check(size);
    in >> obj.type;
    in.read_unchecked(obj.mode.mode);
    in.read_unchecked(obj.nlink);
    in.read_unchecked(obj.uid);
    in.read_unchecked(obj.gid);
    in.read_unchecked(obj.size);
    in.read_unchecked(obj.used);
    in >> obj.rdev;
    in.read_unchecked(obj.fsid);
    in.read_unchecked(obj.fileid);

    in >> obj.atime >> obj.mtime >> obj.ctime;
    return in;
}

inline XDRReader& operator>>(XDRReader& in, post_op_attr& obj)
{
    in >> obj.attributes_follow;
    if(obj.attributes_follow)
    {
        in >> obj.attributes;
    }
    return in;
}

inline XDRReader& operator>>(XDRReader& in, wcc_attr& obj)
{
    return in >> obj.size >> obj.mtime >> obj.ctime;
}

inline XDRReader& operator>>(XDRReader& in, pre_op_attr& obj)
{
    in >> obj.attributes_follow;
    if(obj.attributes_follow)
    {
        in >> obj.attributes;
    }
    return in;
}

inline XDRReader& operator>>(XDRReader& in, wcc_data& obj)
{
    return in >> obj.before >> obj.after;
}

inline XDRReader& operator>>(XDRReader& in, post_op_fh3& obj)
{
    in >> obj.handle_follows;
    if(obj.handle_follows)
    {
        in >> obj.handle;
    }
    return in;
}

inline XDRReader& operator>>(XDRReader& in, sattr3& obj)
{
    in >> obj.set_it_mode;
    if(obj.set_it_mode)
        in >> obj.mode;

    in >> obj.set_it_uid;
    if(obj.set_it_uid)
        in >> obj.uid;

    in >>obj.set_it_gid;
    if(obj.set_it_gid)
        in >> obj.gid;

    in >>obj.set_it_size;
    if(obj.set_it_size)
        in >> obj.size;

    in >> obj.set_it_atime;
    if(obj.set_it_atime == sattr3::SET_TO_CLIENT_TIME)
    {
        in >> obj.atime;
    }

    in >> obj.set_it_mtime;
    if(obj.set_it_mtime == sattr3::SET_TO_CLIENT_TIME)
    {
        in >> obj.mtime;
    }
    return in;
}

inline XDRReader& operator>>(XDRReader& in, diropargs3& obj)
{
    in >> obj.dir;
    in.read_variable_len(obj.name);
    return in;
}

// Procedure 0: NULL - Do nothing
// void NFSPROC3_NULL(void) = 0;
inline XDRReader& operator>>(XDRReader& in, NULLargs&)
{
    return in;
}

inline XDRReader& operator>>(XDRReader& in, NULLres&)
{
    return in;
}

// Procedure 1: GETATTR - Get file attributes
// GETATTR3res NFSPROC3_GETATTR(GETATTR3args) = 1;
inline XDRReader& operator>>(XDRReader& in, GETATTR3args& o)
{
    return in >> o.object;
}

inline XDRReader& operator>>(XDRReader& in, GETATTR3res& o)
{
    in >> o.status;
    if(o.status == nfsstat3::OK)
    {
        in >> o.resok.obj_attributes;
    }
    return in;
}

// Procedure 2: SETATTR - Set file attributes
// SETATTR3res NFSPROC3_SETATTR(SETATTR3args) = 2;
inline XDRReader& operator>>(XDRReader& in, sattrguard3& obj)
{
    uint32_t temp;

    in >> temp;
    obj.check = temp;
    if(obj.check)
        in >> obj.obj_ctime;

    return in;
}

inline XDRReader& operator>>(XDRReader& in, SETATTR3args& o)
{
    return in >> o.object >> o.new_attributes >> o.guard;
}

inline XDRReader& operator>>(XDRReader& in, SETATTR3res& o)
{
    in >> o.status;
    if(o.status == nfsstat3::OK)
    {
        in >> o.resok.obj_wcc;
    }
    else
    {
        in >> o.resfail.obj_wcc;
    }
    return in;
}

// Procedure 3: LOOKUP -  Lookup filename
// LOOKUP3res NFSPROC3_LOOKUP(LOOKUP3args) = 3;
inline XDRReader& operator>>(XDRReader& in, LOOKUP3args& o)
{
    return in >> o.what;
}

inline XDRReader& operator>>(XDRReader& in, LOOKUP3res& o)
{
    in >> o.status;
    if(o.status == nfsstat3::OK)
    {
        in >> o.resok.object;
        in >> o.resok.obj_attributes;
        in >> o.resok.dir_attributes;
    }
    else
    {
        in >> o.resfail.dir_attributes;
    }
    return in;
}

// Procedure 4: ACCESS - Check Access Permission
// ACCESS3res NFSPROC3_ACCESS(ACCESS3args) = 4;
inline XDRReader& operator>>(XDRReader& in, ACCESS3args& o)
{
    return in >> o.object >> o.access;
}
inline XDRReader& operator>>(XDRReader& in, ACCESS3res& o)
{
    in >> o.status;
    if(o.status == nfsstat3::OK)
    {
        in >> o.resok.obj_attributes;
        in >> o.resok.access;
    }
    else
    {
        in >> o.resfail.obj_attributes;
    }
    return in;
}

// Procedure 5: READLINK - Read from symbolic link
// READLINK3res NFSPROC3_READLINK(READLINK3args) = 5;
inline XDRReader& operator>>(XDRReader& in, READLINK3args& o)
{
    return in >> o.symlink;
}

inline XDRReader& operator>>(XDRReader& in, READLINK3res& o)
{
    in >> o.status;
    if(o.status == nfsstat3::OK)
    {
        in >> o.resok.symlink_attributes;
        in.read_variable_len(o.resok.data);
    }
    else
    {
        in >> o.resfail.symlink_attributes;
    }
    return in;
}

// Procedure 6: READ - Read From file
// READ3res NFSPROC3_READ(READ3args) = 6;
inline XDRReader& operator>>(XDRReader& in, READ3args& o)
{
    return in >> o.file >> o.offset >> o.count;
}

inline XDRReader& operator>>(XDRReader& in, READ3res& o)
{
    in >> o.status;
    if(o.status == nfsstat3::OK)
    {
        in >> o.resok.file_attributes;
        in >> o.resok.count;
        in >> o.resok.eof;
    }
    else
    {
        in >> o.resfail.file_attributes;
    }
    return in;
}

// Procedure 7: WRITE - Write to file
// WRITE3res NFSPROC3_WRITE(WRITE3args) = 7;
inline XDRReader& operator>>(XDRReader& in, stable_how& obj)
{
    return in >> obj.stable;
}

inline XDRReader& operator>>(XDRReader& in, WRITE3args& o)
{
    return in >> o.file >> o.offset >> o.count >> o.stable;
}

inline XDRReader& operator>>(XDRReader& in, WRITE3res& o)
{
    in >> o.status;
    if(o.status == nfsstat3::OK)
    {
        in >> o.resok.file_wcc;
        in >> o.resok.count;
        in >> o.resok.committed;
        in.read_fixed_len(o.resok.verf, NFS3_WRITEVERFSIZE);
    }
    else
    {
        in >> o.resfail.file_wcc;
    }
    return in;
}

// Procedure 8: CREATE - Create a file
// CREATE3res NFSPROC3_CREATE(CREATE3args) = 8;
inline XDRReader& operator>>(XDRReader& in, createhow3& obj)
{
    in >> obj.mode;
    switch(obj.mode)
    {
        case createhow3::UNCHECKED:  in >> obj.u.obj_attributes; break;
        case createhow3::GUARDED:    in >> obj.u.obj_attributes; break;
        case createhow3::EXCLUSIVE:
            in.read_fixed_len(obj.u.verf, NFS3_CREATEVERFSIZE);
        break;
    }
    return in;
}

inline XDRReader& operator>>(XDRReader& in, CREATE3args& o)
{
    return in >> o.where >> o.how;
}

inline XDRReader& operator>>(XDRReader& in, CREATE3res& o)
{
    in >> o.status;
    if(o.status == nfsstat3::OK)
    {
        in >> o.resok.obj;
        in >> o.resok.obj_attributes;
        in >> o.resok.dir_wcc;
    }
    else
    {
        in >> o.resfail.dir_wcc;
    }
    return in;
}

// Procedure 9: MKDIR - Create a directory
// MKDIR3res NFSPROC3_MKDIR(MKDIR3args) = 9;
inline XDRReader& operator>>(XDRReader& in, MKDIR3args& o)
{
    return in >> o.where >> o.attributes;
}

inline XDRReader& operator>>(XDRReader& in, MKDIR3res& o)
{
    in >> o.status;
    if(o.status == nfsstat3::OK)
    {
        in >> o.resok.obj;
        in >> o.resok.obj_attributes;
        in >> o.resok.dir_wcc;
    }
    else
    {
        in >> o.resfail.dir_wcc;
    }
    return in;
}

// Procedure 10: SYMLINK - Create a symbolic link
// SYMLINK3res NFSPROC3_SYMLINK(SYMLINK3args) = 10;
inline XDRReader& operator>>(XDRReader& in, symlinkdata3& obj)
{
    in >> obj.symlink_attributes;
    in.read_variable_len(obj.symlink_data);
    return in;
}

inline XDRReader& operator>>(XDRReader& in, SYMLINK3args& o)
{
    return in >> o.where >> o.symlink;
}

inline XDRReader& operator>>(XDRReader& in, SYMLINK3res& o)
{
    in >> o.status;
    if(o.status == nfsstat3::OK)
    {
        in >> o.resok.obj;
        in >> o.resok.obj_attributes;
        in >> o.resok.dir_wcc;
    }
    else
    {
        in >> o.resfail.dir_wcc;
    }
    return in;
}

// Procedure 11: MKNOD - Create a special device
// MKNOD3res NFSPROC3_MKNOD(MKNOD3args) = 11;
inline XDRReader& operator>>(XDRReader& in, devicedata3& obj)
{
    return in >> obj.dev_attributes >> obj.spec;
}

inline XDRReader& operator>>(XDRReader& in, mknoddata3& obj)
{
    in >> obj.type;
    switch(obj.type)
    {
        case ftype3::CHR:
        case ftype3::BLK:
            {
                in >> obj.u.device;
            }
            break;
        case ftype3::SOCK:
        case ftype3::FIFO:
            {
                in >> obj.u.pipe_attributes;
            }
            break;
        default:
            break;
    }
    return in;
}

inline XDRReader& operator>>(XDRReader& in, MKNOD3args& o)
{
    return in >> o.where >> o.what;
}

inline XDRReader& operator>>(XDRReader& in, MKNOD3res& o)
{
    in >> o.status;
    if(o.status == nfsstat3::OK)
    {
        in >> o.resok.obj;
        in >> o.resok.obj_attributes;
        in >> o.resok.dir_wcc;
    }
    else
    {
        in >> o.resfail.dir_wcc;
    }
    return in;
}

// Procedure 12: REMOVE - Remove a File
// REMOVE3res NFSPROC3_REMOVE(REMOVE3args) = 12;
inline XDRReader& operator>>(XDRReader& in, REMOVE3args& o)
{
    return in >> o.object;
}

inline XDRReader& operator>>(XDRReader& in, REMOVE3res& o)
{
    in >> o.status;
    if(o.status == nfsstat3::OK)
    {
        in >> o.resok.dir_wcc;
    }
    else
    {
        in >> o.resfail.dir_wcc;
    }
    return in;
}

// Procedure 13: RMDIR - Remove a Directory
// RMDIR3res NFSPROC3_RMDIR(RMDIR3args) = 13;
inline XDRReader& operator>>(XDRReader& in, RMDIR3args& o)
{
    return in >> o.object;
}

inline XDRReader& operator>>(XDRReader& in, RMDIR3res& o)
{
    in >> o.status;
    if(o.status == nfsstat3::OK)
    {
        in >> o.resok.dir_wcc;
    }
    else
    {
        in >> o.resfail.dir_wcc;
    }
    return in;
}

// Procedure 14: RENAME - Rename a File or Directory
// RENAME3res NFSPROC3_RENAME(RENAME3args) = 14;
inline XDRReader& operator>>(XDRReader& in, RENAME3args& o)
{
    return in >> o.from >> o.to;
}

inline XDRReader& operator>>(XDRReader& in, RENAME3res& o)
{
    in >> o.status;
    if(o.status == nfsstat3::OK)
    {
        in >> o.resok.fromdir_wcc;
        in >> o.resok.todir_wcc;
    }
    else
    {
        in >> o.resfail.fromdir_wcc;
        in >> o.resfail.todir_wcc;
    }
    return in;
}

// Procedure 15: LINK - Create Link to an object
// LINK3res NFSPROC3_LINK(LINK3args) = 15;
inline XDRReader& operator>>(XDRReader& in, LINK3args& o)
{
    return in >> o.file >> o.link;
}

inline XDRReader& operator>>(XDRReader& in, LINK3res& o)
{
    in >> o.status;
    if(o.status == nfsstat3::OK)
    {
        in >> o.resok.file_attributes;
        in >> o.resok.linkdir_wcc;
    }
    else
    {
        in >> o.resfail.file_attributes;
        in >> o.resfail.linkdir_wcc;
    }
    return in;
}

// Procedure 16: READDIR - Read From Directory
// READDIR3res NFSPROC3_READDIR(READDIR3args) = 16;
inline XDRReader& operator>>(XDRReader& in, READDIR3args& o)
{
    in >> o.dir >> o.cookie;
    in.read_fixed_len(o.cookieverf, NFS3_COOKIEVERFSIZE);
    return in >> o.count;
}


inline XDRReader& operator>>(XDRReader& in, READDIR3res& o)
{
    in >> o.status;
    if(o.status == nfsstat3::OK)
    {
        in >> o.resok.dir_attributes;
        in.read_fixed_len(o.resok.cookieverf, NFS3_COOKIEVERFSIZE);
        // TODO: Parse entries
        o.resok.reply.entries = NULL;
        o.resok.reply.eof = true;
    }
    else
    {
        in >> o.resfail.dir_attributes;
    }
    return in;
}

// Procedure 17: READDIRPLUS - Extended read from directory
// READDIRPLUS3res NFSPROC3_READDIRPLUS(READDIRPLUS3args) = 17;
inline XDRReader& operator>>(XDRReader& in, READDIRPLUS3args& o)
{
    in >> o.dir >> o.cookie;
    in.read_fixed_len(o.cookieverf, NFS3_COOKIEVERFSIZE);
    return in >> o.dircount >> o.maxcount;
}

inline XDRReader& operator>>(XDRReader& in, READDIRPLUS3res& o)
{
    in >> o.status;
    if(o.status == nfsstat3::OK)
    {
        in >> o.resok.dir_attributes;
        in.read_fixed_len(o.resok.cookieverf, NFS3_COOKIEVERFSIZE);
        // TODO: Parse entries
        o.resok.reply.entries = NULL;
        o.resok.reply.eof = true;
    }
    else
    {
        in >> o.resfail.dir_attributes;
    }
    return in;
}

// Procedure 18: FSSTAT - Get dynamic file system information
// FSSTAT3res NFSPROC3_FSSTAT(FSSTAT3args) = 18;
inline XDRReader& operator>>(XDRReader& in, FSSTAT3args& o)
{
    return in >> o.fsroot;
}

inline XDRReader& operator>>(XDRReader& in, FSSTAT3res& o)
{
    in >> o.status;
    if(o.status == nfsstat3::OK)
    {
        in >> o.resok.obj_attributes;
        in >> o.resok.tbytes;
        in >> o.resok.fbytes;
        in >> o.resok.abytes;
        in >> o.resok.tfiles;
        in >> o.resok.ffiles;
        in >> o.resok.afiles;
        in >> o.resok.invarsec;
    }
    else
    {
        in >> o.resfail.obj_attributes;
    }
    return in;
}

// Procedure 19: FSINFO - Get static file system Information
// FSINFO3res NFSPROC3_FSINFO(FSINFO3args) = 19;

inline XDRReader& operator>>(XDRReader& in, FSINFO3args& o)
{
    return in >> o.fsroot;
}

inline XDRReader& operator>>(XDRReader& in, FSINFO3res& o)
{
    in >> o.status;
    if(o.status == nfsstat3::OK)
    {
        in >> o.resok.obj_attributes;
        in >> o.resok.rtmax;
        in >> o.resok.rtpref;
        in >> o.resok.rtmult;
        in >> o.resok.wtmax;
        in >> o.resok.wtpref;
        in >> o.resok.wtmult;
        in >> o.resok.dtpref;
        in >> o.resok.maxfilesize;
        in >> o.resok.time_delta;
        in >> o.resok.properties;
    }
    else
    {
        in >> o.resfail.obj_attributes;
    }
    return in;
}

// Procedure 20: PATHCONF - Retrieve POSIX information
// PATHCONF3res NFSPROC3_PATHCONF(PATHCONF3args) = 20;
inline XDRReader& operator>>(XDRReader& in, PATHCONF3args& o)
{
    return in >> o.object;
}

inline XDRReader& operator>>(XDRReader& in, PATHCONF3res& o)
{
    in >> o.status;
    if(o.status == nfsstat3::OK)
    {
        in >> o.resok.obj_attributes;
        in >> o.resok.linkmax;
        in >> o.resok.name_max;
        in >> o.resok.no_trunc;
        in >> o.resok.chown_restricted;
        in >> o.resok.case_insensitive;
        in >> o.resok.case_preserving;
    }
    else
    {
        in >> o.resfail.obj_attributes;
    }
    return in;
}

// Procedure 21: COMMIT - Commit cached data on a server to stable storage
// COMMIT3res NFSPROC3_COMMIT(COMMIT3args) = 21;
inline XDRReader& operator>>(XDRReader& in, COMMIT3args& o)
{
    return in >> o.file >> o.offset >> o.count;
}

inline XDRReader& operator>>(XDRReader& in, COMMIT3res& o)
{
    in >> o.status;
    if(o.status == nfsstat3::OK)
    {
        in >> o.resok.file_wcc;
        in.read_fixed_len(o.resok.verf, NFS3_WRITEVERFSIZE);
    }
    else
    {
        in >> o.resfail.file_wcc;
    }
    return in;
}

extern"C"
std::ostream& print_nfs3_procedures(std::ostream& out, const ProcEnum::NFSProcedure proc);

std::ostream& operator<<(std::ostream& out, const ProcEnum::NFSProcedure proc);
std::ostream& operator<<(std::ostream& out, const mode3 obj);
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
std::ostream& operator<<(std::ostream& out, const sattr3& obj);
std::ostream& operator<<(std::ostream& out, const diropargs3& obj);
std::ostream& operator<<(std::ostream& out, const stable_how& obj);
std::ostream& operator<<(std::ostream& out, const sattrguard3& obj);
std::ostream& operator<<(std::ostream& out, const createhow3& obj);
std::ostream& operator<<(std::ostream& out, const symlinkdata3& obj);
std::ostream& operator<<(std::ostream& out, const devicedata3& obj);
std::ostream& operator<<(std::ostream& out, const mknoddata3& obj);

} // namespace NFS3
} // namespace protocols
} // namespace NST
//------------------------------------------------------------------------------
#endif//NFS_UTILS_H
//------------------------------------------------------------------------------
