//------------------------------------------------------------------------------
// Author: Dzianis Huznou (Alexey Costroma)
// Description: Helpers for parsing NFS structures.
// Copyright (c) 2013,2014 EPAM Systems
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
#include "protocols/nfs/nfs_utils.h"
#include "protocols/nfs3/nfs3_utils.h"
//------------------------------------------------------------------------------
using namespace NST::API::NFS3;
using namespace NST::protocols::NFS;
using namespace NST::protocols::xdr;
//------------------------------------------------------------------------------
namespace NST
{
namespace protocols
{
namespace NFS3
{

const char* print_nfs3_procedures(const ProcEnumNFS3::NFSProcedure proc)
{
    static const char* const NFS3ProcedureTitles[ProcEnumNFS3::count] =
    {
        "NULL",       "GETATTR",      "SETATTR",  "LOOKUP",
        "ACCESS",     "READLINK",     "READ",     "WRITE",
        "CREATE",     "MKDIR",        "SYMLINK",  "MKNOD",
        "REMOVE",     "RMDIR",        "RENAME",   "LINK",
        "READDIR",    "READDIRPLUS",  "FSSTAT",   "FSINFO",
        "PATHCONF",   "COMMIT"
    };

    return NFS3ProcedureTitles[proc];
}

enum
{
    S_ISUID = 0x00800,
    S_ISGID = 0x00400,
    S_ISVTX = 0x00200, // Not defined in POSIX
    S_IRUSR = 0x00100,
    S_IWUSR = 0x00080,
    S_IXUSR = 0x00040, // Search in directory
    S_IRGRP = 0x00020,
    S_IWGRP = 0x00010,
    S_IXGRP = 0x00008, // Search in directory
    S_IROTH = 0x00004,
    S_IWOTH = 0x00002,
    S_IXOTH = 0x00001  // Search in directory
};

void print_mode3(std::ostream& out, const uint32 val)
{
    if (val & S_ISUID) out << "USER_ID_EXEC ";
    if (val & S_ISGID) out << "GROUP_ID_EXEC ";
    if (val & S_ISVTX) out << "SAVE_SWAPPED_TEXT ";
    if (val & S_IRUSR) out << "OWNER_READ ";
    if (val & S_IWUSR) out << "OWNER_WRITE ";
    if (val & S_IXUSR) out << "OWNER_EXEC ";
    if (val & S_IRGRP) out << "GROUP_READ ";
    if (val & S_IWGRP) out << "GROUP_WRITE ";
    if (val & S_IXGRP) out << "GROUP_EXEC ";
    if (val & S_IROTH) out << "OTHER_READ ";
    if (val & S_IWOTH) out << "OTHER_WRITE ";
    if (val & S_IXOTH) out << "OTHER_EXEC";
}

void print_access3(std::ostream& out, const uint32 val)
{
    if (val & ACCESS3_READ)    out << "READ ";
    if (val & ACCESS3_LOOKUP)  out << "LOOKUP ";
    if (val & ACCESS3_MODIFY)  out << "MODIFY ";
    if (val & ACCESS3_EXTEND)  out << "EXTEND ";
    if (val & ACCESS3_DELETE)  out << "DELETE ";
    if (val & ACCESS3_EXECUTE) out << "EXECUTE ";
}

std::ostream& operator<<(std::ostream& out, const nfsstat3& obj)
{
    switch(obj)
    {
    case nfsstat3::NFS3_OK:
        return out << "OK";
    case nfsstat3::NFS3ERR_PERM:
        return out << "ERR_PERM";
    case nfsstat3::NFS3ERR_NOENT:
        return out << "ERR_NOENT";
    case nfsstat3::NFS3ERR_IO:
        return out << "ERR_IO";
    case nfsstat3::NFS3ERR_NXIO:
        return out << "ERR_NXIO";
    case nfsstat3::NFS3ERR_ACCES:
        return out << "ERR_ACCES";
    case nfsstat3::NFS3ERR_EXIST:
        return out << "ERR_EXIST";
    case nfsstat3::NFS3ERR_XDEV:
        return out << "ERR_XDEV";
    case nfsstat3::NFS3ERR_NODEV:
        return out << "ERR_NODEV";
    case nfsstat3::NFS3ERR_NOTDIR:
        return out << "ERR_NOTDIR";
    case nfsstat3::NFS3ERR_ISDIR:
        return out << "ERR_ISDIR";
    case nfsstat3::NFS3ERR_INVAL:
        return out << "ERR_INVAL";
    case nfsstat3::NFS3ERR_FBIG:
        return out << "ERR_FBIG";
    case nfsstat3::NFS3ERR_NOSPC:
        return out << "ERR_NOSPC";
    case nfsstat3::NFS3ERR_ROFS:
        return out << "ERR_ROFS";
    case nfsstat3::NFS3ERR_MLINK:
        return out << "ERR_MLINK";
    case nfsstat3::NFS3ERR_NAMETOOLONG:
        return out << "ERR_NAMETOOLONG";
    case nfsstat3::NFS3ERR_NOTEMPTY:
        return out << "ERR_NOTEMPTY";
    case nfsstat3::NFS3ERR_DQUOT:
        return out << "ERR_DQUOT";
    case nfsstat3::NFS3ERR_STALE:
        return out << "ERR_STALE";
    case nfsstat3::NFS3ERR_REMOTE:
        return out << "ERR_REMOTE";
    case nfsstat3::NFS3ERR_BADHANDLE:
        return out << "ERR_BADHANDLE";
    case nfsstat3::NFS3ERR_NOT_SYNC:
        return out << "ERR_NOT_SYNC";
    case nfsstat3::NFS3ERR_BAD_COOKIE:
        return out << "ERR_BAD_COOKIE";
    case nfsstat3::NFS3ERR_NOTSUPP:
        return out << "ERR_NOTSUPP";
    case nfsstat3::NFS3ERR_TOOSMALL:
        return out << "ERR_TOOSMALL";
    case nfsstat3::NFS3ERR_SERVERFAULT:
        return out << "ERR_SERVERFAULT";
    case nfsstat3::NFS3ERR_BADTYPE:
        return out << "ERR_BADTYPE";
    case nfsstat3::NFS3ERR_JUKEBOX:
        return out << "ERR_JUKEBOX";
    }
    return out;
}

std::ostream& operator<<(std::ostream& out, const ftype3& obj)
{
    switch(obj)
    {
    case ftype3::NF3REG:  return out << "REG";
    case ftype3::NF3DIR:  return out << "DIR";
    case ftype3::NF3BLK:  return out << "BLK";
    case ftype3::NF3CHR:  return out << "CHR";
    case ftype3::NF3LNK:  return out << "LNK";
    case ftype3::NF3SOCK: return out << "SOCK";
    case ftype3::NF3FIFO: return out << "FIFO";
    }
    return out;
}

std::ostream& operator<<(std::ostream& out, const specdata3& obj)
{
    return out << " specdata1: " << obj.specdata1
               << " specdata2: " << obj.specdata2;
}

std::ostream& operator<<(std::ostream& out, const nfs_fh3& obj)
{
    NFS::print_nfs_fh(out, obj.data.data_val, obj.data.data_len);
    return out;
}

std::ostream& operator<<(std::ostream& out, const nfstime3& obj)
{
    return out << "seconds: "   << obj.seconds
               << " nseconds: " << obj.nseconds << ' ';
}

std::ostream& operator<<(std::ostream& out, const fattr3& obj)
{
    out << " type: " << obj.type
        << " mode: ";

    print_mode3(out,obj.mode);

    out << " nlink: "  << obj.nlink
        << " uid: "    << obj.uid
        << " gid: "    << obj.gid
        << " size: "   << obj.size
        << " used: "   << obj.used
        << " rdev: "   << obj.rdev
        << " fsid: "   << obj.fsid
        << " fileid: " << obj.fileid
        << " atime: "  << obj.atime
        << " mtime: "  << obj.mtime
        << " ctime: "  << obj.ctime;
    return out;
}

std::ostream& operator<<(std::ostream& out, const post_op_attr& obj)
{
    if(obj.attributes_follow) return out << obj.post_op_attr_u.attributes;
    else                      return out << " void ";
}

std::ostream& operator<<(std::ostream& out, const wcc_attr& obj)
{
    return out << " size: "  << obj.size
               << " mtime: " << obj.mtime
               << " ctime: " << obj.ctime;
}

std::ostream& operator<<(std::ostream& out, const pre_op_attr& obj)
{
    if(obj.attributes_follow) return out << obj.pre_op_attr_u.attributes;
    else                      return out << " void ";
}

std::ostream& operator<<(std::ostream& out, const wcc_data& obj)
{
    return out << " before: " << obj.before << "after: " << obj.after;
}

std::ostream& operator<<(std::ostream& out, const post_op_fh3& obj)
{
    if(obj.handle_follows) return out << " handle: "
                                      << obj.post_op_fh3_u.handle;
    else                   return out << " void ";
}

std::ostream& operator<<(std::ostream& out, const time_how& obj)
{
    switch(obj)
    {
    case time_how::DONT_CHANGE:
        return out << "DONT_CHANGE";
    case time_how::SET_TO_SERVER_TIME:
        return out << "SET_TO_SERVER_TIME";
    case time_how::SET_TO_CLIENT_TIME:
        return out << "SET_TO_CLIENT_TIME";
    }
    return out;
}

std::ostream& operator<<(std::ostream& out, const set_mode3& obj)
{
    if(obj.set_it) return out << obj.set_mode3_u.mode;
    else           return out << " void ";
}

std::ostream& operator<<(std::ostream& out, const set_uid3& obj)
{
    if(obj.set_it) return out << obj.set_uid3_u.uid;
    else           return out << " void ";
}

std::ostream& operator<<(std::ostream& out, const set_gid3& obj)
{
    if(obj.set_it) return out << obj.set_gid3_u.gid;
    else           return out << " void ";
}

std::ostream& operator<<(std::ostream& out, const set_size3& obj)
{
    if(obj.set_it) return out << obj.set_size3_u.size;
    else           return out << " void ";
}

std::ostream& operator<<(std::ostream& out, const set_atime& obj)
{
    if(obj.set_it == time_how::SET_TO_CLIENT_TIME)
         return out << obj.set_it << " " << obj.set_atime_u.atime;
    else return out << obj.set_it;
}

std::ostream& operator<<(std::ostream& out, const set_mtime& obj)
{
    if(obj.set_it == time_how::SET_TO_CLIENT_TIME)
         return out << obj.set_it << " " << obj.set_mtime_u.mtime;
    else return out << obj.set_it;
}

std::ostream& operator<<(std::ostream& out, const sattr3& obj)
{
    if(obj.mode.set_it)
    {
        out << " mode: ";
        print_mode3(out, obj.mode.set_mode3_u.mode);
    }

    if(obj.uid.set_it)   out << " uid: "   << obj.uid.set_uid3_u.uid;
    if(obj.gid.set_it)   out << " gid: "   << obj.gid.set_gid3_u.gid;
    if(obj.size.set_it)  out << " size: "  << obj.size.set_size3_u.size;
    if(obj.atime.set_it == time_how::SET_TO_CLIENT_TIME)
        out << " atime: " << obj.atime.set_atime_u.atime;
    if(obj.mtime.set_it == time_how::SET_TO_CLIENT_TIME)
        out << " atime: " << obj.mtime.set_mtime_u.mtime;

    return out;
}

std::ostream& operator<<(std::ostream& out, const diropargs3& obj)
{
    return out << " dir: "   << obj.dir
               << " name: " << obj.name;
}

std::ostream& operator<<(std::ostream& out, const sattrguard3& obj)
{
    if(obj.check) return out << " obj_ctime: " << obj.sattrguard3_u.obj_ctime; 
    else          return out << " void ";
}

std::ostream& operator<<(std::ostream& out, const stable_how& obj)
{
    switch(obj)
    {
    case stable_how::UNSTABLE:  return out << "UNSTABLE";
    case stable_how::DATA_SYNC: return out << "DATA_SYNC";
    case stable_how::FILE_SYNC: return out << "FILE_SYNC";
    }
    return out;
}

std::ostream& operator<<(std::ostream& out, const createmode3& obj)
{
    switch(obj)
    {
    case createmode3::UNCHECKED: return out << "UNCHECKED";
    case createmode3::GUARDED:   return out << "GUARDED";
    case createmode3::EXCLUSIVE: return out << "EXCLUSIVE";
    }
    return out;
}

std::ostream& operator<<(std::ostream& out, const createhow3& obj)
{
    switch(obj.mode)
    {
    case createmode3::UNCHECKED:
    case createmode3::GUARDED:
        return out << obj.mode << " obj attributes: "
                   << obj.createhow3_u.obj_attributes;
    case createmode3::EXCLUSIVE:
        out << obj.mode << " verf: ";
        print_hex(out, obj.createhow3_u.verf, NFS3_COOKIEVERFSIZE);
        break;
    }
    return out;
}

std::ostream& operator<<(std::ostream& out, const symlinkdata3& obj)
{
    return out << " symlink_attributes: " << obj.symlink_attributes
               << " symlink_data: "       << obj.symlink_data;
}

std::ostream& operator<<(std::ostream& out, const devicedata3& obj)
{
    return out << " dev_attributes: " << obj.dev_attributes
               << " spec: "           << obj.spec;
}


std::ostream& operator<<(std::ostream& out, const mknoddata3& obj)
{
    out << " type: " << obj.type;
    switch(obj.type)
    {
    case ftype3::NF3CHR:
    case ftype3::NF3BLK:
        return out << " device: "          << obj.mknoddata3_u.device;
    case ftype3::NF3SOCK:
    case ftype3::NF3FIFO:
        return out << " pipe_attributes: " << obj.mknoddata3_u.pipe_attributes;
    default: break;
    }
    return out; 
}

std::ostream& operator<<(std::ostream& out, const entry3& obj)
{
    out << " file id: "   <<  obj.fileid
        << " name: "      <<  obj.name
        << " cookie: "    <<  obj.cookie << '\n';
    if(obj.nextentry) out << *obj.nextentry;
    return out;
}

std::ostream& operator<<(std::ostream& out, const dirlist3& obj)
{
    out << " eof: "     <<  obj.eof;
    if(obj.entries) out << *obj.entries;
    return out;
}

std::ostream& operator<<(std::ostream& out, const entryplus3& obj)
{
    out << " file id: "         << obj.fileid
        << " name: "            << obj.name
        << " name attributes: " << obj.name_attributes
        << " name handle: "     << obj.name_handle
        << " cookie: "          << obj.cookie << '\n';
    if(obj.nextentry) out << *obj.nextentry;
    return out;
}

std::ostream& operator<<(std::ostream& out, const dirlistplus3& obj)
{
    out << " eof: " << obj.eof;
    if(obj.entries) out << *obj.entries;
    return out;
}

bool_t
xdr_uint64 (XDR* xdrs, uint64* objp)
{

    if (!xdr_u_longlong_t (xdrs, objp))
    {
        return FALSE;
    }
    return TRUE;
}

bool_t
xdr_uint32 (XDR* xdrs, uint32* objp)
{

    if (!xdr_u_int (xdrs, objp))
    {
        return FALSE;
    }
    return TRUE;
}

bool_t
xdr_int64 (XDR* xdrs, int64* objp)
{

    if (!xdr_longlong_t (xdrs, objp))
    {
        return FALSE;
    }
    return TRUE;
}

bool_t
xdr_int32 (XDR* xdrs, int32* objp)
{

    if (!xdr_int (xdrs, objp))
    {
        return FALSE;
    }
    return TRUE;
}

bool_t
xdr_filename3 (XDR* xdrs, filename3* objp)
{

    if (!xdr_string (xdrs, objp, ~0))
    {
        return FALSE;
    }
    return TRUE;
}

bool_t
xdr_nfspath3 (XDR* xdrs, nfspath3* objp)
{

    if (!xdr_string (xdrs, objp, ~0))
    {
        return FALSE;
    }
    return TRUE;
}

bool_t
xdr_fileid3 (XDR* xdrs, fileid3* objp)
{

    if (!xdr_uint64 (xdrs, objp))
    {
        return FALSE;
    }
    return TRUE;
}

bool_t
xdr_cookie3 (XDR* xdrs, cookie3* objp)
{

    if (!xdr_uint64 (xdrs, objp))
    {
        return FALSE;
    }
    return TRUE;
}

bool_t
xdr_cookieverf3 (XDR* xdrs, cookieverf3 objp)
{

    if (!xdr_opaque (xdrs, objp, NFS3_COOKIEVERFSIZE))
    {
        return FALSE;
    }
    return TRUE;
}

bool_t
xdr_createverf3 (XDR* xdrs, createverf3 objp)
{

    if (!xdr_opaque (xdrs, objp, NFS3_CREATEVERFSIZE))
    {
        return FALSE;
    }
    return TRUE;
}

bool_t
xdr_writeverf3 (XDR* xdrs, writeverf3 objp)
{

    if (!xdr_opaque (xdrs, objp, NFS3_WRITEVERFSIZE))
    {
        return FALSE;
    }
    return TRUE;
}

bool_t
xdr_uid3 (XDR* xdrs, uid3* objp)
{

    if (!xdr_uint32 (xdrs, objp))
    {
        return FALSE;
    }
    return TRUE;
}

bool_t
xdr_gid3 (XDR* xdrs, gid3* objp)
{

    if (!xdr_uint32 (xdrs, objp))
    {
        return FALSE;
    }
    return TRUE;
}

bool_t
xdr_size3 (XDR* xdrs, size3* objp)
{

    if (!xdr_uint64 (xdrs, objp))
    {
        return FALSE;
    }
    return TRUE;
}

bool_t
xdr_offset3 (XDR* xdrs, offset3* objp)
{

    if (!xdr_uint64 (xdrs, objp))
    {
        return FALSE;
    }
    return TRUE;
}

bool_t
xdr_mode3 (XDR* xdrs, mode3* objp)
{

    if (!xdr_uint32 (xdrs, objp))
    {
        return FALSE;
    }
    return TRUE;
}

bool_t
xdr_count3 (XDR* xdrs, count3* objp)
{

    if (!xdr_uint32 (xdrs, objp))
    {
        return FALSE;
    }
    return TRUE;
}

bool_t
xdr_nfsstat3 (XDR* xdrs, nfsstat3* objp)
{

    if (!xdr_enum (xdrs, (enum_t*) objp))
    {
        return FALSE;
    }
    return TRUE;
}

bool_t
xdr_ftype3 (XDR* xdrs, ftype3* objp)
{

    if (!xdr_enum (xdrs, (enum_t*) objp))
    {
        return FALSE;
    }
    return TRUE;
}

bool_t
xdr_specdata3 (XDR* xdrs, specdata3* objp)
{

    if (!xdr_uint32 (xdrs, &objp->specdata1))
    {
        return FALSE;
    }
    if (!xdr_uint32 (xdrs, &objp->specdata2))
    {
        return FALSE;
    }
    return TRUE;
}

bool_t
xdr_nfs_fh3 (XDR* xdrs, nfs_fh3* objp)
{

    if (!xdr_bytes (xdrs, (char**)&objp->data.data_val, (u_int*) &objp->data.data_len, NFS3_FHSIZE))
    {
        return FALSE;
    }
    return TRUE;
}

bool_t
xdr_nfstime3 (XDR* xdrs, nfstime3* objp)
{

    if (!xdr_uint32 (xdrs, &objp->seconds))
    {
        return FALSE;
    }
    if (!xdr_uint32 (xdrs, &objp->nseconds))
    {
        return FALSE;
    }
    return TRUE;
}

bool_t
xdr_fattr3 (XDR* xdrs, fattr3* objp)
{

    if (!xdr_ftype3 (xdrs, &objp->type))
    {
        return FALSE;
    }
    if (!xdr_mode3 (xdrs, &objp->mode))
    {
        return FALSE;
    }
    if (!xdr_uint32 (xdrs, &objp->nlink))
    {
        return FALSE;
    }
    if (!xdr_uid3 (xdrs, &objp->uid))
    {
        return FALSE;
    }
    if (!xdr_gid3 (xdrs, &objp->gid))
    {
        return FALSE;
    }
    if (!xdr_size3 (xdrs, &objp->size))
    {
        return FALSE;
    }
    if (!xdr_size3 (xdrs, &objp->used))
    {
        return FALSE;
    }
    if (!xdr_specdata3 (xdrs, &objp->rdev))
    {
        return FALSE;
    }
    if (!xdr_uint64 (xdrs, &objp->fsid))
    {
        return FALSE;
    }
    if (!xdr_fileid3 (xdrs, &objp->fileid))
    {
        return FALSE;
    }
    if (!xdr_nfstime3 (xdrs, &objp->atime))
    {
        return FALSE;
    }
    if (!xdr_nfstime3 (xdrs, &objp->mtime))
    {
        return FALSE;
    }
    if (!xdr_nfstime3 (xdrs, &objp->ctime))
    {
        return FALSE;
    }
    return TRUE;
}

bool_t
xdr_post_op_attr (XDR* xdrs, post_op_attr* objp)
{

    if (!xdr_bool (xdrs, &objp->attributes_follow))
    {
        return FALSE;
    }
    switch (objp->attributes_follow)
    {
    case TRUE:
        if (!xdr_fattr3 (xdrs, &objp->post_op_attr_u.attributes))
        {
            return FALSE;
        }
        break;
    case FALSE:
        break;
    default:
        return FALSE;
    }
    return TRUE;
}

bool_t
xdr_wcc_attr (XDR* xdrs, wcc_attr* objp)
{

    if (!xdr_size3 (xdrs, &objp->size))
    {
        return FALSE;
    }
    if (!xdr_nfstime3 (xdrs, &objp->mtime))
    {
        return FALSE;
    }
    if (!xdr_nfstime3 (xdrs, &objp->ctime))
    {
        return FALSE;
    }
    return TRUE;
}

bool_t
xdr_pre_op_attr (XDR* xdrs, pre_op_attr* objp)
{

    if (!xdr_bool (xdrs, &objp->attributes_follow))
    {
        return FALSE;
    }
    switch (objp->attributes_follow)
    {
    case TRUE:
        if (!xdr_wcc_attr (xdrs, &objp->pre_op_attr_u.attributes))
        {
            return FALSE;
        }
        break;
    case FALSE:
        break;
    default:
        return FALSE;
    }
    return TRUE;
}

bool_t
xdr_wcc_data (XDR* xdrs, wcc_data* objp)
{

    if (!xdr_pre_op_attr (xdrs, &objp->before))
    {
        return FALSE;
    }
    if (!xdr_post_op_attr (xdrs, &objp->after))
    {
        return FALSE;
    }
    return TRUE;
}

bool_t
xdr_post_op_fh3 (XDR* xdrs, post_op_fh3* objp)
{

    if (!xdr_bool (xdrs, &objp->handle_follows))
    {
        return FALSE;
    }
    switch (objp->handle_follows)
    {
    case TRUE:
        if (!xdr_nfs_fh3 (xdrs, &objp->post_op_fh3_u.handle))
        {
            return FALSE;
        }
        break;
    case FALSE:
        break;
    default:
        return FALSE;
    }
    return TRUE;
}

bool_t
xdr_time_how (XDR* xdrs, time_how* objp)
{

    if (!xdr_enum (xdrs, (enum_t*) objp))
    {
        return FALSE;
    }
    return TRUE;
}

bool_t
xdr_set_mode3 (XDR* xdrs, set_mode3* objp)
{

    if (!xdr_bool (xdrs, &objp->set_it))
    {
        return FALSE;
    }
    switch (objp->set_it)
    {
    case TRUE:
        if (!xdr_mode3 (xdrs, &objp->set_mode3_u.mode))
        {
            return FALSE;
        }
        break;
    default:
        break;
    }
    return TRUE;
}

bool_t
xdr_set_uid3 (XDR* xdrs, set_uid3* objp)
{

    if (!xdr_bool (xdrs, &objp->set_it))
    {
        return FALSE;
    }
    switch (objp->set_it)
    {
    case TRUE:
        if (!xdr_uid3 (xdrs, &objp->set_uid3_u.uid))
        {
            return FALSE;
        }
        break;
    default:
        break;
    }
    return TRUE;
}

bool_t
xdr_set_gid3 (XDR* xdrs, set_gid3* objp)
{

    if (!xdr_bool (xdrs, &objp->set_it))
    {
        return FALSE;
    }
    switch (objp->set_it)
    {
    case TRUE:
        if (!xdr_gid3 (xdrs, &objp->set_gid3_u.gid))
        {
            return FALSE;
        }
        break;
    default:
        break;
    }
    return TRUE;
}

bool_t
xdr_set_size3 (XDR* xdrs, set_size3* objp)
{

    if (!xdr_bool (xdrs, &objp->set_it))
    {
        return FALSE;
    }
    switch (objp->set_it)
    {
    case TRUE:
        if (!xdr_size3 (xdrs, &objp->set_size3_u.size))
        {
            return FALSE;
        }
        break;
    default:
        break;
    }
    return TRUE;
}

bool_t
xdr_set_atime (XDR* xdrs, set_atime* objp)
{

    if (!xdr_time_how (xdrs, &objp->set_it))
    {
        return FALSE;
    }
    switch (objp->set_it)
    {
    case SET_TO_CLIENT_TIME:
        if (!xdr_nfstime3 (xdrs, &objp->set_atime_u.atime))
        {
            return FALSE;
        }
        break;
    default:
        break;
    }
    return TRUE;
}

bool_t
xdr_set_mtime (XDR* xdrs, set_mtime* objp)
{

    if (!xdr_time_how (xdrs, &objp->set_it))
    {
        return FALSE;
    }
    switch (objp->set_it)
    {
    case SET_TO_CLIENT_TIME:
        if (!xdr_nfstime3 (xdrs, &objp->set_mtime_u.mtime))
        {
            return FALSE;
        }
        break;
    default:
        break;
    }
    return TRUE;
}

bool_t
xdr_sattr3 (XDR* xdrs, sattr3* objp)
{

    if (!xdr_set_mode3 (xdrs, &objp->mode))
    {
        return FALSE;
    }
    if (!xdr_set_uid3 (xdrs, &objp->uid))
    {
        return FALSE;
    }
    if (!xdr_set_gid3 (xdrs, &objp->gid))
    {
        return FALSE;
    }
    if (!xdr_set_size3 (xdrs, &objp->size))
    {
        return FALSE;
    }
    if (!xdr_set_atime (xdrs, &objp->atime))
    {
        return FALSE;
    }
    if (!xdr_set_mtime (xdrs, &objp->mtime))
    {
        return FALSE;
    }
    return TRUE;
}

bool_t
xdr_diropargs3 (XDR* xdrs, diropargs3* objp)
{

    if (!xdr_nfs_fh3 (xdrs, &objp->dir))
    {
        return FALSE;
    }
    if (!xdr_filename3 (xdrs, &objp->name))
    {
        return FALSE;
    }
    return TRUE;
}

bool_t
xdr_GETATTR3args (XDR* xdrs, GETATTR3args* objp)
{

    if (!xdr_nfs_fh3 (xdrs, &objp->object))
    {
        return FALSE;
    }
    return TRUE;
}

bool_t
xdr_GETATTR3resok (XDR* xdrs, GETATTR3resok* objp)
{

    if (!xdr_fattr3 (xdrs, &objp->obj_attributes))
    {
        return FALSE;
    }
    return TRUE;
}

bool_t
xdr_GETATTR3res (XDR* xdrs, GETATTR3res* objp)
{

    if (!xdr_nfsstat3 (xdrs, &objp->status))
    {
        return FALSE;
    }
    switch (objp->status)
    {
    case NFS3_OK:
        if (!xdr_GETATTR3resok (xdrs, &objp->GETATTR3res_u.resok))
        {
            return FALSE;
        }
        break;
    default:
        break;
    }
    return TRUE;
}

bool_t
xdr_sattrguard3 (XDR* xdrs, sattrguard3* objp)
{

    if (!xdr_bool (xdrs, &objp->check))
    {
        return FALSE;
    }
    switch (objp->check)
    {
    case TRUE:
        if (!xdr_nfstime3 (xdrs, &objp->sattrguard3_u.obj_ctime))
        {
            return FALSE;
        }
        break;
    case FALSE:
        break;
    default:
        return FALSE;
    }
    return TRUE;
}

// handmade for compatibility
bool_t
xdr_NULL3args (XDR*, NULL3args*)
{
    return TRUE;
}

// handmade for compatibility
bool_t
xdr_NULL3res (XDR*, NULL3res*)
{
    return TRUE;
}

bool_t
xdr_SETATTR3args (XDR* xdrs, SETATTR3args* objp)
{

    if (!xdr_nfs_fh3 (xdrs, &objp->object))
    {
        return FALSE;
    }
    if (!xdr_sattr3 (xdrs, &objp->new_attributes))
    {
        return FALSE;
    }
    if (!xdr_sattrguard3 (xdrs, &objp->guard))
    {
        return FALSE;
    }
    return TRUE;
}

bool_t
xdr_SETATTR3resok (XDR* xdrs, SETATTR3resok* objp)
{

    if (!xdr_wcc_data (xdrs, &objp->obj_wcc))
    {
        return FALSE;
    }
    return TRUE;
}

bool_t
xdr_SETATTR3resfail (XDR* xdrs, SETATTR3resfail* objp)
{

    if (!xdr_wcc_data (xdrs, &objp->obj_wcc))
    {
        return FALSE;
    }
    return TRUE;
}

bool_t
xdr_SETATTR3res (XDR* xdrs, SETATTR3res* objp)
{

    if (!xdr_nfsstat3 (xdrs, &objp->status))
    {
        return FALSE;
    }
    switch (objp->status)
    {
    case NFS3_OK:
        if (!xdr_SETATTR3resok (xdrs, &objp->SETATTR3res_u.resok))
        {
            return FALSE;
        }
        break;
    default:
        if (!xdr_SETATTR3resfail (xdrs, &objp->SETATTR3res_u.resfail))
        {
            return FALSE;
        }
        break;
    }
    return TRUE;
}

bool_t
xdr_LOOKUP3args (XDR* xdrs, LOOKUP3args* objp)
{

    if (!xdr_diropargs3 (xdrs, &objp->what))
    {
        return FALSE;
    }
    return TRUE;
}

bool_t
xdr_LOOKUP3resok (XDR* xdrs, LOOKUP3resok* objp)
{

    if (!xdr_nfs_fh3 (xdrs, &objp->object))
    {
        return FALSE;
    }
    if (!xdr_post_op_attr (xdrs, &objp->obj_attributes))
    {
        return FALSE;
    }
    if (!xdr_post_op_attr (xdrs, &objp->dir_attributes))
    {
        return FALSE;
    }
    return TRUE;
}

bool_t
xdr_LOOKUP3resfail (XDR* xdrs, LOOKUP3resfail* objp)
{

    if (!xdr_post_op_attr (xdrs, &objp->dir_attributes))
    {
        return FALSE;
    }
    return TRUE;
}

bool_t
xdr_LOOKUP3res (XDR* xdrs, LOOKUP3res* objp)
{

    if (!xdr_nfsstat3 (xdrs, &objp->status))
    {
        return FALSE;
    }
    switch (objp->status)
    {
    case NFS3_OK:
        if (!xdr_LOOKUP3resok (xdrs, &objp->LOOKUP3res_u.resok))
        {
            return FALSE;
        }
        break;
    default:
        if (!xdr_LOOKUP3resfail (xdrs, &objp->LOOKUP3res_u.resfail))
        {
            return FALSE;
        }
        break;
    }
    return TRUE;
}

bool_t
xdr_ACCESS3args (XDR* xdrs, ACCESS3args* objp)
{

    if (!xdr_nfs_fh3 (xdrs, &objp->object))
    {
        return FALSE;
    }
    if (!xdr_uint32 (xdrs, &objp->access))
    {
        return FALSE;
    }
    return TRUE;
}

bool_t
xdr_ACCESS3resok (XDR* xdrs, ACCESS3resok* objp)
{

    if (!xdr_post_op_attr (xdrs, &objp->obj_attributes))
    {
        return FALSE;
    }
    if (!xdr_uint32 (xdrs, &objp->access))
    {
        return FALSE;
    }
    return TRUE;
}

bool_t
xdr_ACCESS3resfail (XDR* xdrs, ACCESS3resfail* objp)
{

    if (!xdr_post_op_attr (xdrs, &objp->obj_attributes))
    {
        return FALSE;
    }
    return TRUE;
}

bool_t
xdr_ACCESS3res (XDR* xdrs, ACCESS3res* objp)
{

    if (!xdr_nfsstat3 (xdrs, &objp->status))
    {
        return FALSE;
    }
    switch (objp->status)
    {
    case NFS3_OK:
        if (!xdr_ACCESS3resok (xdrs, &objp->ACCESS3res_u.resok))
        {
            return FALSE;
        }
        break;
    default:
        if (!xdr_ACCESS3resfail (xdrs, &objp->ACCESS3res_u.resfail))
        {
            return FALSE;
        }
        break;
    }
    return TRUE;
}

bool_t
xdr_READLINK3args (XDR* xdrs, READLINK3args* objp)
{

    if (!xdr_nfs_fh3 (xdrs, &objp->symlink))
    {
        return FALSE;
    }
    return TRUE;
}

bool_t
xdr_READLINK3resok (XDR* xdrs, READLINK3resok* objp)
{

    if (!xdr_post_op_attr (xdrs, &objp->symlink_attributes))
    {
        return FALSE;
    }
    if (!xdr_nfspath3 (xdrs, &objp->data))
    {
        return FALSE;
    }
    return TRUE;
}

bool_t
xdr_READLINK3resfail (XDR* xdrs, READLINK3resfail* objp)
{

    if (!xdr_post_op_attr (xdrs, &objp->symlink_attributes))
    {
        return FALSE;
    }
    return TRUE;
}

bool_t
xdr_READLINK3res (XDR* xdrs, READLINK3res* objp)
{

    if (!xdr_nfsstat3 (xdrs, &objp->status))
    {
        return FALSE;
    }
    switch (objp->status)
    {
    case NFS3_OK:
        if (!xdr_READLINK3resok (xdrs, &objp->READLINK3res_u.resok))
        {
            return FALSE;
        }
        break;
    default:
        if (!xdr_READLINK3resfail (xdrs, &objp->READLINK3res_u.resfail))
        {
            return FALSE;
        }
        break;
    }
    return TRUE;
}

bool_t
xdr_READ3args (XDR* xdrs, READ3args* objp)
{

    if (!xdr_nfs_fh3 (xdrs, &objp->file))
    {
        return FALSE;
    }
    if (!xdr_offset3 (xdrs, &objp->offset))
    {
        return FALSE;
    }
    if (!xdr_count3 (xdrs, &objp->count))
    {
        return FALSE;
    }
    return TRUE;
}

bool_t
xdr_READ3resok (XDR* xdrs, READ3resok* objp)
{

    if (!xdr_post_op_attr (xdrs, &objp->file_attributes))
    {
        return FALSE;
    }
    if (!xdr_count3 (xdrs, &objp->count))
    {
        return FALSE;
    }
    if (!xdr_bool (xdrs, &objp->eof))
    {
        return FALSE;
    }
    return TRUE;
}

bool_t
xdr_READ3resfail (XDR* xdrs, READ3resfail* objp)
{

    if (!xdr_post_op_attr (xdrs, &objp->file_attributes))
    {
        return FALSE;
    }
    return TRUE;
}

bool_t
xdr_READ3res (XDR* xdrs, READ3res* objp)
{

    if (!xdr_nfsstat3 (xdrs, &objp->status))
    {
        return FALSE;
    }
    switch (objp->status)
    {
    case NFS3_OK:
        if (!xdr_READ3resok (xdrs, &objp->READ3res_u.resok))
        {
            return FALSE;
        }
        break;
    default:
        if (!xdr_READ3resfail (xdrs, &objp->READ3res_u.resfail))
        {
            return FALSE;
        }
        break;
    }
    return TRUE;
}

bool_t
xdr_stable_how (XDR* xdrs, stable_how* objp)
{

    if (!xdr_enum (xdrs, (enum_t*) objp))
    {
        return FALSE;
    }
    return TRUE;
}

bool_t
xdr_WRITE3args (XDR* xdrs, WRITE3args* objp)
{

    if (!xdr_nfs_fh3 (xdrs, &objp->file))
    {
        return FALSE;
    }
    if (!xdr_offset3 (xdrs, &objp->offset))
    {
        return FALSE;
    }
    if (!xdr_count3 (xdrs, &objp->count))
    {
        return FALSE;
    }
    if (!xdr_stable_how (xdrs, &objp->stable))
    {
        return FALSE;
    }
    return TRUE;
}

bool_t
xdr_WRITE3resok (XDR* xdrs, WRITE3resok* objp)
{

    if (!xdr_wcc_data (xdrs, &objp->file_wcc))
    {
        return FALSE;
    }
    if (!xdr_count3 (xdrs, &objp->count))
    {
        return FALSE;
    }
    if (!xdr_stable_how (xdrs, &objp->committed))
    {
        return FALSE;
    }
    if (!xdr_writeverf3 (xdrs, objp->verf))
    {
        return FALSE;
    }
    return TRUE;
}

bool_t
xdr_WRITE3resfail (XDR* xdrs, WRITE3resfail* objp)
{

    if (!xdr_wcc_data (xdrs, &objp->file_wcc))
    {
        return FALSE;
    }
    return TRUE;
}

bool_t
xdr_WRITE3res (XDR* xdrs, WRITE3res* objp)
{

    if (!xdr_nfsstat3 (xdrs, &objp->status))
    {
        return FALSE;
    }
    switch (objp->status)
    {
    case NFS3_OK:
        if (!xdr_WRITE3resok (xdrs, &objp->WRITE3res_u.resok))
        {
            return FALSE;
        }
        break;
    default:
        if (!xdr_WRITE3resfail (xdrs, &objp->WRITE3res_u.resfail))
        {
            return FALSE;
        }
        break;
    }
    return TRUE;
}

bool_t
xdr_createmode3 (XDR* xdrs, createmode3* objp)
{

    if (!xdr_enum (xdrs, (enum_t*) objp))
    {
        return FALSE;
    }
    return TRUE;
}

bool_t
xdr_createhow3 (XDR* xdrs, createhow3* objp)
{

    if (!xdr_createmode3 (xdrs, &objp->mode))
    {
        return FALSE;
    }
    switch (objp->mode)
    {
    case UNCHECKED:
    case GUARDED:
        if (!xdr_sattr3 (xdrs, &objp->createhow3_u.obj_attributes))
        {
            return FALSE;
        }
        break;
    case EXCLUSIVE:
        if (!xdr_createverf3 (xdrs, objp->createhow3_u.verf))
        {
            return FALSE;
        }
        break;
    default:
        return FALSE;
    }
    return TRUE;
}

bool_t
xdr_CREATE3args (XDR* xdrs, CREATE3args* objp)
{

    if (!xdr_diropargs3 (xdrs, &objp->where))
    {
        return FALSE;
    }
    if (!xdr_createhow3 (xdrs, &objp->how))
    {
        return FALSE;
    }
    return TRUE;
}

bool_t
xdr_CREATE3resok (XDR* xdrs, CREATE3resok* objp)
{

    if (!xdr_post_op_fh3 (xdrs, &objp->obj))
    {
        return FALSE;
    }
    if (!xdr_post_op_attr (xdrs, &objp->obj_attributes))
    {
        return FALSE;
    }
    if (!xdr_wcc_data (xdrs, &objp->dir_wcc))
    {
        return FALSE;
    }
    return TRUE;
}

bool_t
xdr_CREATE3resfail (XDR* xdrs, CREATE3resfail* objp)
{

    if (!xdr_wcc_data (xdrs, &objp->dir_wcc))
    {
        return FALSE;
    }
    return TRUE;
}

bool_t
xdr_CREATE3res (XDR* xdrs, CREATE3res* objp)
{

    if (!xdr_nfsstat3 (xdrs, &objp->status))
    {
        return FALSE;
    }
    switch (objp->status)
    {
    case NFS3_OK:
        if (!xdr_CREATE3resok (xdrs, &objp->CREATE3res_u.resok))
        {
            return FALSE;
        }
        break;
    default:
        if (!xdr_CREATE3resfail (xdrs, &objp->CREATE3res_u.resfail))
        {
            return FALSE;
        }
        break;
    }
    return TRUE;
}

bool_t
xdr_MKDIR3args (XDR* xdrs, MKDIR3args* objp)
{

    if (!xdr_diropargs3 (xdrs, &objp->where))
    {
        return FALSE;
    }
    if (!xdr_sattr3 (xdrs, &objp->attributes))
    {
        return FALSE;
    }
    return TRUE;
}

bool_t
xdr_MKDIR3resok (XDR* xdrs, MKDIR3resok* objp)
{

    if (!xdr_post_op_fh3 (xdrs, &objp->obj))
    {
        return FALSE;
    }
    if (!xdr_post_op_attr (xdrs, &objp->obj_attributes))
    {
        return FALSE;
    }
    if (!xdr_wcc_data (xdrs, &objp->dir_wcc))
    {
        return FALSE;
    }
    return TRUE;
}

bool_t
xdr_MKDIR3resfail (XDR* xdrs, MKDIR3resfail* objp)
{

    if (!xdr_wcc_data (xdrs, &objp->dir_wcc))
    {
        return FALSE;
    }
    return TRUE;
}

bool_t
xdr_MKDIR3res (XDR* xdrs, MKDIR3res* objp)
{

    if (!xdr_nfsstat3 (xdrs, &objp->status))
    {
        return FALSE;
    }
    switch (objp->status)
    {
    case NFS3_OK:
        if (!xdr_MKDIR3resok (xdrs, &objp->MKDIR3res_u.resok))
        {
            return FALSE;
        }
        break;
    default:
        if (!xdr_MKDIR3resfail (xdrs, &objp->MKDIR3res_u.resfail))
        {
            return FALSE;
        }
        break;
    }
    return TRUE;
}

bool_t
xdr_symlinkdata3 (XDR* xdrs, symlinkdata3* objp)
{

    if (!xdr_sattr3 (xdrs, &objp->symlink_attributes))
    {
        return FALSE;
    }
    if (!xdr_nfspath3 (xdrs, &objp->symlink_data))
    {
        return FALSE;
    }
    return TRUE;
}

bool_t
xdr_SYMLINK3args (XDR* xdrs, SYMLINK3args* objp)
{

    if (!xdr_diropargs3 (xdrs, &objp->where))
    {
        return FALSE;
    }
    if (!xdr_symlinkdata3 (xdrs, &objp->symlink))
    {
        return FALSE;
    }
    return TRUE;
}

bool_t
xdr_SYMLINK3resok (XDR* xdrs, SYMLINK3resok* objp)
{

    if (!xdr_post_op_fh3 (xdrs, &objp->obj))
    {
        return FALSE;
    }
    if (!xdr_post_op_attr (xdrs, &objp->obj_attributes))
    {
        return FALSE;
    }
    if (!xdr_wcc_data (xdrs, &objp->dir_wcc))
    {
        return FALSE;
    }
    return TRUE;
}

bool_t
xdr_SYMLINK3resfail (XDR* xdrs, SYMLINK3resfail* objp)
{

    if (!xdr_wcc_data (xdrs, &objp->dir_wcc))
    {
        return FALSE;
    }
    return TRUE;
}

bool_t
xdr_SYMLINK3res (XDR* xdrs, SYMLINK3res* objp)
{

    if (!xdr_nfsstat3 (xdrs, &objp->status))
    {
        return FALSE;
    }
    switch (objp->status)
    {
    case NFS3_OK:
        if (!xdr_SYMLINK3resok (xdrs, &objp->SYMLINK3res_u.resok))
        {
            return FALSE;
        }
        break;
    default:
        if (!xdr_SYMLINK3resfail (xdrs, &objp->SYMLINK3res_u.resfail))
        {
            return FALSE;
        }
        break;
    }
    return TRUE;
}

bool_t
xdr_devicedata3 (XDR* xdrs, devicedata3* objp)
{

    if (!xdr_sattr3 (xdrs, &objp->dev_attributes))
    {
        return FALSE;
    }
    if (!xdr_specdata3 (xdrs, &objp->spec))
    {
        return FALSE;
    }
    return TRUE;
}

bool_t
xdr_mknoddata3 (XDR* xdrs, mknoddata3* objp)
{

    if (!xdr_ftype3 (xdrs, &objp->type))
    {
        return FALSE;
    }
    switch (objp->type)
    {
    case NF3CHR:
    case NF3BLK:
        if (!xdr_devicedata3 (xdrs, &objp->mknoddata3_u.device))
        {
            return FALSE;
        }
        break;
    case NF3SOCK:
    case NF3FIFO:
        if (!xdr_sattr3 (xdrs, &objp->mknoddata3_u.pipe_attributes))
        {
            return FALSE;
        }
        break;
    default:
        break;
    }
    return TRUE;
}

bool_t
xdr_MKNOD3args (XDR* xdrs, MKNOD3args* objp)
{

    if (!xdr_diropargs3 (xdrs, &objp->where))
    {
        return FALSE;
    }
    if (!xdr_mknoddata3 (xdrs, &objp->what))
    {
        return FALSE;
    }
    return TRUE;
}

bool_t
xdr_MKNOD3resok (XDR* xdrs, MKNOD3resok* objp)
{

    if (!xdr_post_op_fh3 (xdrs, &objp->obj))
    {
        return FALSE;
    }
    if (!xdr_post_op_attr (xdrs, &objp->obj_attributes))
    {
        return FALSE;
    }
    if (!xdr_wcc_data (xdrs, &objp->dir_wcc))
    {
        return FALSE;
    }
    return TRUE;
}

bool_t
xdr_MKNOD3resfail (XDR* xdrs, MKNOD3resfail* objp)
{

    if (!xdr_wcc_data (xdrs, &objp->dir_wcc))
    {
        return FALSE;
    }
    return TRUE;
}

bool_t
xdr_MKNOD3res (XDR* xdrs, MKNOD3res* objp)
{

    if (!xdr_nfsstat3 (xdrs, &objp->status))
    {
        return FALSE;
    }
    switch (objp->status)
    {
    case NFS3_OK:
        if (!xdr_MKNOD3resok (xdrs, &objp->MKNOD3res_u.resok))
        {
            return FALSE;
        }
        break;
    default:
        if (!xdr_MKNOD3resfail (xdrs, &objp->MKNOD3res_u.resfail))
        {
            return FALSE;
        }
        break;
    }
    return TRUE;
}

bool_t
xdr_REMOVE3args (XDR* xdrs, REMOVE3args* objp)
{

    if (!xdr_diropargs3 (xdrs, &objp->object))
    {
        return FALSE;
    }
    return TRUE;
}

bool_t
xdr_REMOVE3resok (XDR* xdrs, REMOVE3resok* objp)
{

    if (!xdr_wcc_data (xdrs, &objp->dir_wcc))
    {
        return FALSE;
    }
    return TRUE;
}

bool_t
xdr_REMOVE3resfail (XDR* xdrs, REMOVE3resfail* objp)
{

    if (!xdr_wcc_data (xdrs, &objp->dir_wcc))
    {
        return FALSE;
    }
    return TRUE;
}

bool_t
xdr_REMOVE3res (XDR* xdrs, REMOVE3res* objp)
{

    if (!xdr_nfsstat3 (xdrs, &objp->status))
    {
        return FALSE;
    }
    switch (objp->status)
    {
    case NFS3_OK:
        if (!xdr_REMOVE3resok (xdrs, &objp->REMOVE3res_u.resok))
        {
            return FALSE;
        }
        break;
    default:
        if (!xdr_REMOVE3resfail (xdrs, &objp->REMOVE3res_u.resfail))
        {
            return FALSE;
        }
        break;
    }
    return TRUE;
}

bool_t
xdr_RMDIR3args (XDR* xdrs, RMDIR3args* objp)
{

    if (!xdr_diropargs3 (xdrs, &objp->object))
    {
        return FALSE;
    }
    return TRUE;
}

bool_t
xdr_RMDIR3resok (XDR* xdrs, RMDIR3resok* objp)
{

    if (!xdr_wcc_data (xdrs, &objp->dir_wcc))
    {
        return FALSE;
    }
    return TRUE;
}

bool_t
xdr_RMDIR3resfail (XDR* xdrs, RMDIR3resfail* objp)
{

    if (!xdr_wcc_data (xdrs, &objp->dir_wcc))
    {
        return FALSE;
    }
    return TRUE;
}

bool_t
xdr_RMDIR3res (XDR* xdrs, RMDIR3res* objp)
{

    if (!xdr_nfsstat3 (xdrs, &objp->status))
    {
        return FALSE;
    }
    switch (objp->status)
    {
    case NFS3_OK:
        if (!xdr_RMDIR3resok (xdrs, &objp->RMDIR3res_u.resok))
        {
            return FALSE;
        }
        break;
    default:
        if (!xdr_RMDIR3resfail (xdrs, &objp->RMDIR3res_u.resfail))
        {
            return FALSE;
        }
        break;
    }
    return TRUE;
}

bool_t
xdr_RENAME3args (XDR* xdrs, RENAME3args* objp)
{

    if (!xdr_diropargs3 (xdrs, &objp->from))
    {
        return FALSE;
    }
    if (!xdr_diropargs3 (xdrs, &objp->to))
    {
        return FALSE;
    }
    return TRUE;
}

bool_t
xdr_RENAME3resok (XDR* xdrs, RENAME3resok* objp)
{

    if (!xdr_wcc_data (xdrs, &objp->fromdir_wcc))
    {
        return FALSE;
    }
    if (!xdr_wcc_data (xdrs, &objp->todir_wcc))
    {
        return FALSE;
    }
    return TRUE;
}

bool_t
xdr_RENAME3resfail (XDR* xdrs, RENAME3resfail* objp)
{

    if (!xdr_wcc_data (xdrs, &objp->fromdir_wcc))
    {
        return FALSE;
    }
    if (!xdr_wcc_data (xdrs, &objp->todir_wcc))
    {
        return FALSE;
    }
    return TRUE;
}

bool_t
xdr_RENAME3res (XDR* xdrs, RENAME3res* objp)
{

    if (!xdr_nfsstat3 (xdrs, &objp->status))
    {
        return FALSE;
    }
    switch (objp->status)
    {
    case NFS3_OK:
        if (!xdr_RENAME3resok (xdrs, &objp->RENAME3res_u.resok))
        {
            return FALSE;
        }
        break;
    default:
        if (!xdr_RENAME3resfail (xdrs, &objp->RENAME3res_u.resfail))
        {
            return FALSE;
        }
        break;
    }
    return TRUE;
}

bool_t
xdr_LINK3args (XDR* xdrs, LINK3args* objp)
{

    if (!xdr_nfs_fh3 (xdrs, &objp->file))
    {
        return FALSE;
    }
    if (!xdr_diropargs3 (xdrs, &objp->link))
    {
        return FALSE;
    }
    return TRUE;
}

bool_t
xdr_LINK3resok (XDR* xdrs, LINK3resok* objp)
{

    if (!xdr_post_op_attr (xdrs, &objp->file_attributes))
    {
        return FALSE;
    }
    if (!xdr_wcc_data (xdrs, &objp->linkdir_wcc))
    {
        return FALSE;
    }
    return TRUE;
}

bool_t
xdr_LINK3resfail (XDR* xdrs, LINK3resfail* objp)
{

    if (!xdr_post_op_attr (xdrs, &objp->file_attributes))
    {
        return FALSE;
    }
    if (!xdr_wcc_data (xdrs, &objp->linkdir_wcc))
    {
        return FALSE;
    }
    return TRUE;
}

bool_t
xdr_LINK3res (XDR* xdrs, LINK3res* objp)
{

    if (!xdr_nfsstat3 (xdrs, &objp->status))
    {
        return FALSE;
    }
    switch (objp->status)
    {
    case NFS3_OK:
        if (!xdr_LINK3resok (xdrs, &objp->LINK3res_u.resok))
        {
            return FALSE;
        }
        break;
    default:
        if (!xdr_LINK3resfail (xdrs, &objp->LINK3res_u.resfail))
        {
            return FALSE;
        }
        break;
    }
    return TRUE;
}

bool_t
xdr_READDIR3args (XDR* xdrs, READDIR3args* objp)
{

    if (!xdr_nfs_fh3 (xdrs, &objp->dir))
    {
        return FALSE;
    }
    if (!xdr_cookie3 (xdrs, &objp->cookie))
    {
        return FALSE;
    }
    if (!xdr_cookieverf3 (xdrs, objp->cookieverf))
    {
        return FALSE;
    }
    if (!xdr_count3 (xdrs, &objp->count))
    {
        return FALSE;
    }
    return TRUE;
}

bool_t
xdr_entry3 (XDR* xdrs, entry3* objp)
{

    if (!xdr_fileid3 (xdrs, &objp->fileid))
    {
        return FALSE;
    }
    if (!xdr_filename3 (xdrs, &objp->name))
    {
        return FALSE;
    }
    if (!xdr_cookie3 (xdrs, &objp->cookie))
    {
        return FALSE;
    }
    if (!xdr_pointer (xdrs, (char**)&objp->nextentry, sizeof (entry3), (xdrproc_t) xdr_entry3))
    {
        return FALSE;
    }
    return TRUE;
}

bool_t
xdr_dirlist3 (XDR* xdrs, dirlist3* objp)
{

    if (!xdr_pointer (xdrs, (char**)&objp->entries, sizeof (entry3), (xdrproc_t) xdr_entry3))
    {
        return FALSE;
    }
    if (!xdr_bool (xdrs, &objp->eof))
    {
        return FALSE;
    }
    return TRUE;
}

bool_t
xdr_READDIR3resok (XDR* xdrs, READDIR3resok* objp)
{

    if (!xdr_post_op_attr (xdrs, &objp->dir_attributes))
    {
        return FALSE;
    }
    if (!xdr_cookieverf3 (xdrs, objp->cookieverf))
    {
        return FALSE;
    }
    if (!xdr_dirlist3 (xdrs, &objp->reply))
    {
        return FALSE;
    }
    return TRUE;
}

bool_t
xdr_READDIR3resfail (XDR* xdrs, READDIR3resfail* objp)
{

    if (!xdr_post_op_attr (xdrs, &objp->dir_attributes))
    {
        return FALSE;
    }
    return TRUE;
}

bool_t
xdr_READDIR3res (XDR* xdrs, READDIR3res* objp)
{

    if (!xdr_nfsstat3 (xdrs, &objp->status))
    {
        return FALSE;
    }
    switch (objp->status)
    {
    case NFS3_OK:
        if (!xdr_READDIR3resok (xdrs, &objp->READDIR3res_u.resok))
        {
            return FALSE;
        }
        break;
    default:
        if (!xdr_READDIR3resfail (xdrs, &objp->READDIR3res_u.resfail))
        {
            return FALSE;
        }
        break;
    }
    return TRUE;
}

bool_t
xdr_READDIRPLUS3args (XDR* xdrs, READDIRPLUS3args* objp)
{

    if (!xdr_nfs_fh3 (xdrs, &objp->dir))
    {
        return FALSE;
    }
    if (!xdr_cookie3 (xdrs, &objp->cookie))
    {
        return FALSE;
    }
    if (!xdr_cookieverf3 (xdrs, objp->cookieverf))
    {
        return FALSE;
    }
    if (!xdr_count3 (xdrs, &objp->dircount))
    {
        return FALSE;
    }
    if (!xdr_count3 (xdrs, &objp->maxcount))
    {
        return FALSE;
    }
    return TRUE;
}

bool_t
xdr_entryplus3 (XDR* xdrs, entryplus3* objp)
{

    if (!xdr_fileid3 (xdrs, &objp->fileid))
    {
        return FALSE;
    }
    if (!xdr_filename3 (xdrs, &objp->name))
    {
        return FALSE;
    }
    if (!xdr_cookie3 (xdrs, &objp->cookie))
    {
        return FALSE;
    }
    if (!xdr_post_op_attr (xdrs, &objp->name_attributes))
    {
        return FALSE;
    }
    if (!xdr_post_op_fh3 (xdrs, &objp->name_handle))
    {
        return FALSE;
    }
    if (!xdr_pointer (xdrs, (char**)&objp->nextentry, sizeof (entryplus3), (xdrproc_t) xdr_entryplus3))
    {
        return FALSE;
    }
    return TRUE;
}

bool_t
xdr_dirlistplus3 (XDR* xdrs, dirlistplus3* objp)
{

    if (!xdr_pointer (xdrs, (char**)&objp->entries, sizeof (entryplus3), (xdrproc_t) xdr_entryplus3))
    {
        return FALSE;
    }
    if (!xdr_bool (xdrs, &objp->eof))
    {
        return FALSE;
    }
    return TRUE;
}

bool_t
xdr_READDIRPLUS3resok (XDR* xdrs, READDIRPLUS3resok* objp)
{

    if (!xdr_post_op_attr (xdrs, &objp->dir_attributes))
    {
        return FALSE;
    }
    if (!xdr_cookieverf3 (xdrs, objp->cookieverf))
    {
        return FALSE;
    }
    if (!xdr_dirlistplus3 (xdrs, &objp->reply))
    {
        return FALSE;
    }
    return TRUE;
}

bool_t
xdr_READDIRPLUS3resfail (XDR* xdrs, READDIRPLUS3resfail* objp)
{

    if (!xdr_post_op_attr (xdrs, &objp->dir_attributes))
    {
        return FALSE;
    }
    return TRUE;
}

bool_t
xdr_READDIRPLUS3res (XDR* xdrs, READDIRPLUS3res* objp)
{

    if (!xdr_nfsstat3 (xdrs, &objp->status))
    {
        return FALSE;
    }
    switch (objp->status)
    {
    case NFS3_OK:
        if (!xdr_READDIRPLUS3resok (xdrs, &objp->READDIRPLUS3res_u.resok))
        {
            return FALSE;
        }
        break;
    default:
        if (!xdr_READDIRPLUS3resfail (xdrs, &objp->READDIRPLUS3res_u.resfail))
        {
            return FALSE;
        }
        break;
    }
    return TRUE;
}

bool_t
xdr_FSSTAT3args (XDR* xdrs, FSSTAT3args* objp)
{

    if (!xdr_nfs_fh3 (xdrs, &objp->fsroot))
    {
        return FALSE;
    }
    return TRUE;
}

bool_t
xdr_FSSTAT3resok (XDR* xdrs, FSSTAT3resok* objp)
{

    if (!xdr_post_op_attr (xdrs, &objp->obj_attributes))
    {
        return FALSE;
    }
    if (!xdr_size3 (xdrs, &objp->tbytes))
    {
        return FALSE;
    }
    if (!xdr_size3 (xdrs, &objp->fbytes))
    {
        return FALSE;
    }
    if (!xdr_size3 (xdrs, &objp->abytes))
    {
        return FALSE;
    }
    if (!xdr_size3 (xdrs, &objp->tfiles))
    {
        return FALSE;
    }
    if (!xdr_size3 (xdrs, &objp->ffiles))
    {
        return FALSE;
    }
    if (!xdr_size3 (xdrs, &objp->afiles))
    {
        return FALSE;
    }
    if (!xdr_uint32 (xdrs, &objp->invarsec))
    {
        return FALSE;
    }
    return TRUE;
}

bool_t
xdr_FSSTAT3resfail (XDR* xdrs, FSSTAT3resfail* objp)
{

    if (!xdr_post_op_attr (xdrs, &objp->obj_attributes))
    {
        return FALSE;
    }
    return TRUE;
}

bool_t
xdr_FSSTAT3res (XDR* xdrs, FSSTAT3res* objp)
{

    if (!xdr_nfsstat3 (xdrs, &objp->status))
    {
        return FALSE;
    }
    switch (objp->status)
    {
    case NFS3_OK:
        if (!xdr_FSSTAT3resok (xdrs, &objp->FSSTAT3res_u.resok))
        {
            return FALSE;
        }
        break;
    default:
        if (!xdr_FSSTAT3resfail (xdrs, &objp->FSSTAT3res_u.resfail))
        {
            return FALSE;
        }
        break;
    }
    return TRUE;
}

bool_t
xdr_FSINFO3args (XDR* xdrs, FSINFO3args* objp)
{

    if (!xdr_nfs_fh3 (xdrs, &objp->fsroot))
    {
        return FALSE;
    }
    return TRUE;
}

bool_t
xdr_FSINFO3resok (XDR* xdrs, FSINFO3resok* objp)
{

    if (!xdr_post_op_attr (xdrs, &objp->obj_attributes))
    {
        return FALSE;
    }
    if (!xdr_uint32 (xdrs, &objp->rtmax))
    {
        return FALSE;
    }
    if (!xdr_uint32 (xdrs, &objp->rtpref))
    {
        return FALSE;
    }
    if (!xdr_uint32 (xdrs, &objp->rtmult))
    {
        return FALSE;
    }
    if (!xdr_uint32 (xdrs, &objp->wtmax))
    {
        return FALSE;
    }
    if (!xdr_uint32 (xdrs, &objp->wtpref))
    {
        return FALSE;
    }
    if (!xdr_uint32 (xdrs, &objp->wtmult))
    {
        return FALSE;
    }
    if (!xdr_uint32 (xdrs, &objp->dtpref))
    {
        return FALSE;
    }
    if (!xdr_size3 (xdrs, &objp->maxfilesize))
    {
        return FALSE;
    }
    if (!xdr_nfstime3 (xdrs, &objp->time_delta))
    {
        return FALSE;
    }
    if (!xdr_uint32 (xdrs, &objp->properties))
    {
        return FALSE;
    }
    return TRUE;
}

bool_t
xdr_FSINFO3resfail (XDR* xdrs, FSINFO3resfail* objp)
{

    if (!xdr_post_op_attr (xdrs, &objp->obj_attributes))
    {
        return FALSE;
    }
    return TRUE;
}

bool_t
xdr_FSINFO3res (XDR* xdrs, FSINFO3res* objp)
{

    if (!xdr_nfsstat3 (xdrs, &objp->status))
    {
        return FALSE;
    }
    switch (objp->status)
    {
    case NFS3_OK:
        if (!xdr_FSINFO3resok (xdrs, &objp->FSINFO3res_u.resok))
        {
            return FALSE;
        }
        break;
    default:
        if (!xdr_FSINFO3resfail (xdrs, &objp->FSINFO3res_u.resfail))
        {
            return FALSE;
        }
        break;
    }
    return TRUE;
}

bool_t
xdr_PATHCONF3args (XDR* xdrs, PATHCONF3args* objp)
{

    if (!xdr_nfs_fh3 (xdrs, &objp->object))
    {
        return FALSE;
    }
    return TRUE;
}

bool_t
xdr_PATHCONF3resok (XDR* xdrs, PATHCONF3resok* objp)
{
    int32_t* buf;

    if (xdrs->x_op == XDR_ENCODE)
    {
        if (!xdr_post_op_attr (xdrs, &objp->obj_attributes))
        {
            return FALSE;
        }
        if (!xdr_uint32 (xdrs, &objp->linkmax))
        {
            return FALSE;
        }
        if (!xdr_uint32 (xdrs, &objp->name_max))
        {
            return FALSE;
        }
        buf = XDR_INLINE (xdrs, 4 * BYTES_PER_XDR_UNIT);
        if (buf == NULL)
        {
            if (!xdr_bool (xdrs, &objp->no_trunc))
            {
                return FALSE;
            }
            if (!xdr_bool (xdrs, &objp->chown_restricted))
            {
                return FALSE;
            }
            if (!xdr_bool (xdrs, &objp->case_insensitive))
            {
                return FALSE;
            }
            if (!xdr_bool (xdrs, &objp->case_preserving))
            {
                return FALSE;
            }
        }
        else
        {
            IXDR_PUT_BOOL(buf, objp->no_trunc);
            IXDR_PUT_BOOL(buf, objp->chown_restricted);
            IXDR_PUT_BOOL(buf, objp->case_insensitive);
            IXDR_PUT_BOOL(buf, objp->case_preserving);
        }
        return TRUE;
    }
    else if (xdrs->x_op == XDR_DECODE)
    {
        if (!xdr_post_op_attr (xdrs, &objp->obj_attributes))
        {
            return FALSE;
        }
        if (!xdr_uint32 (xdrs, &objp->linkmax))
        {
            return FALSE;
        }
        if (!xdr_uint32 (xdrs, &objp->name_max))
        {
            return FALSE;
        }
        buf = XDR_INLINE (xdrs, 4 * BYTES_PER_XDR_UNIT);
        if (buf == NULL)
        {
            if (!xdr_bool (xdrs, &objp->no_trunc))
            {
                return FALSE;
            }
            if (!xdr_bool (xdrs, &objp->chown_restricted))
            {
                return FALSE;
            }
            if (!xdr_bool (xdrs, &objp->case_insensitive))
            {
                return FALSE;
            }
            if (!xdr_bool (xdrs, &objp->case_preserving))
            {
                return FALSE;
            }
        }
        else
        {
            objp->no_trunc = IXDR_GET_BOOL(buf);
            objp->chown_restricted = IXDR_GET_BOOL(buf);
            objp->case_insensitive = IXDR_GET_BOOL(buf);
            objp->case_preserving = IXDR_GET_BOOL(buf);
        }
        return TRUE;
    }

    if (!xdr_post_op_attr (xdrs, &objp->obj_attributes))
    {
        return FALSE;
    }
    if (!xdr_uint32 (xdrs, &objp->linkmax))
    {
        return FALSE;
    }
    if (!xdr_uint32 (xdrs, &objp->name_max))
    {
        return FALSE;
    }
    if (!xdr_bool (xdrs, &objp->no_trunc))
    {
        return FALSE;
    }
    if (!xdr_bool (xdrs, &objp->chown_restricted))
    {
        return FALSE;
    }
    if (!xdr_bool (xdrs, &objp->case_insensitive))
    {
        return FALSE;
    }
    if (!xdr_bool (xdrs, &objp->case_preserving))
    {
        return FALSE;
    }
    return TRUE;
}

bool_t
xdr_PATHCONF3resfail (XDR* xdrs, PATHCONF3resfail* objp)
{

    if (!xdr_post_op_attr (xdrs, &objp->obj_attributes))
    {
        return FALSE;
    }
    return TRUE;
}

bool_t
xdr_PATHCONF3res (XDR* xdrs, PATHCONF3res* objp)
{

    if (!xdr_nfsstat3 (xdrs, &objp->status))
    {
        return FALSE;
    }
    switch (objp->status)
    {
    case NFS3_OK:
        if (!xdr_PATHCONF3resok (xdrs, &objp->PATHCONF3res_u.resok))
        {
            return FALSE;
        }
        break;
    default:
        if (!xdr_PATHCONF3resfail (xdrs, &objp->PATHCONF3res_u.resfail))
        {
            return FALSE;
        }
        break;
    }
    return TRUE;
}

bool_t
xdr_COMMIT3args (XDR* xdrs, COMMIT3args* objp)
{

    if (!xdr_nfs_fh3 (xdrs, &objp->file))
    {
        return FALSE;
    }
    if (!xdr_offset3 (xdrs, &objp->offset))
    {
        return FALSE;
    }
    if (!xdr_count3 (xdrs, &objp->count))
    {
        return FALSE;
    }
    return TRUE;
}

bool_t
xdr_COMMIT3resok (XDR* xdrs, COMMIT3resok* objp)
{

    if (!xdr_wcc_data (xdrs, &objp->file_wcc))
    {
        return FALSE;
    }
    if (!xdr_writeverf3 (xdrs, objp->verf))
    {
        return FALSE;
    }
    return TRUE;
}

bool_t
xdr_COMMIT3resfail (XDR* xdrs, COMMIT3resfail* objp)
{

    if (!xdr_wcc_data (xdrs, &objp->file_wcc))
    {
        return FALSE;
    }
    return TRUE;
}

bool_t
xdr_COMMIT3res (XDR* xdrs, COMMIT3res* objp)
{

    if (!xdr_nfsstat3 (xdrs, &objp->status))
    {
        return FALSE;
    }
    switch (objp->status)
    {
    case NFS3_OK:
        if (!xdr_COMMIT3resok (xdrs, &objp->COMMIT3res_u.resok))
        {
            return FALSE;
        }
        break;
    default:
        if (!xdr_COMMIT3resfail (xdrs, &objp->COMMIT3res_u.resfail))
        {
            return FALSE;
        }
        break;
    }
    return TRUE;
}

} // namespace NFS3
} // namespace protocols
} // namespace NST
//------------------------------------------------------------------------------
