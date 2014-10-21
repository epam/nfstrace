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

void print_mode3(std::ostream& out, const rpcgen::uint32 val)
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

void print_access3(std::ostream& out, const rpcgen::uint32 val)
{
    if (val & rpcgen::ACCESS3_READ)    out << "READ ";
    if (val & rpcgen::ACCESS3_LOOKUP)  out << "LOOKUP ";
    if (val & rpcgen::ACCESS3_MODIFY)  out << "MODIFY ";
    if (val & rpcgen::ACCESS3_EXTEND)  out << "EXTEND ";
    if (val & rpcgen::ACCESS3_DELETE)  out << "DELETE ";
    if (val & rpcgen::ACCESS3_EXECUTE) out << "EXECUTE ";
}

std::ostream& operator<<(std::ostream& out, const rpcgen::nfsstat3& obj)
{
    switch(obj)
    {
    case rpcgen::nfsstat3::NFS3_OK:             return out << "OK";
    case rpcgen::nfsstat3::NFS3ERR_PERM:        return out << "ERR_PERM";
    case rpcgen::nfsstat3::NFS3ERR_NOENT:       return out << "ERR_NOENT";
    case rpcgen::nfsstat3::NFS3ERR_IO:          return out << "ERR_IO";
    case rpcgen::nfsstat3::NFS3ERR_NXIO:        return out << "ERR_NXIO";
    case rpcgen::nfsstat3::NFS3ERR_ACCES:       return out << "ERR_ACCES";
    case rpcgen::nfsstat3::NFS3ERR_EXIST:       return out << "ERR_EXIST";
    case rpcgen::nfsstat3::NFS3ERR_XDEV:        return out << "ERR_XDEV";
    case rpcgen::nfsstat3::NFS3ERR_NODEV:       return out << "ERR_NODEV";
    case rpcgen::nfsstat3::NFS3ERR_NOTDIR:      return out << "ERR_NOTDIR";
    case rpcgen::nfsstat3::NFS3ERR_ISDIR:       return out << "ERR_ISDIR";
    case rpcgen::nfsstat3::NFS3ERR_INVAL:       return out << "ERR_INVAL";
    case rpcgen::nfsstat3::NFS3ERR_FBIG:        return out << "ERR_FBIG";
    case rpcgen::nfsstat3::NFS3ERR_NOSPC:       return out << "ERR_NOSPC";
    case rpcgen::nfsstat3::NFS3ERR_ROFS:        return out << "ERR_ROFS";
    case rpcgen::nfsstat3::NFS3ERR_MLINK:       return out << "ERR_MLINK";
    case rpcgen::nfsstat3::NFS3ERR_NAMETOOLONG: return out << "ERR_NAMETOOLONG";
    case rpcgen::nfsstat3::NFS3ERR_NOTEMPTY:    return out << "ERR_NOTEMPTY";
    case rpcgen::nfsstat3::NFS3ERR_DQUOT:       return out << "ERR_DQUOT";
    case rpcgen::nfsstat3::NFS3ERR_STALE:       return out << "ERR_STALE";
    case rpcgen::nfsstat3::NFS3ERR_REMOTE:      return out << "ERR_REMOTE";
    case rpcgen::nfsstat3::NFS3ERR_BADHANDLE:   return out << "ERR_BADHANDLE";
    case rpcgen::nfsstat3::NFS3ERR_NOT_SYNC:    return out << "ERR_NOT_SYNC";
    case rpcgen::nfsstat3::NFS3ERR_BAD_COOKIE:  return out << "ERR_BAD_COOKIE";
    case rpcgen::nfsstat3::NFS3ERR_NOTSUPP:     return out << "ERR_NOTSUPP";
    case rpcgen::nfsstat3::NFS3ERR_TOOSMALL:    return out << "ERR_TOOSMALL";
    case rpcgen::nfsstat3::NFS3ERR_SERVERFAULT: return out << "ERR_SERVERFAULT";
    case rpcgen::nfsstat3::NFS3ERR_BADTYPE:     return out << "ERR_BADTYPE";
    case rpcgen::nfsstat3::NFS3ERR_JUKEBOX:     return out << "ERR_JUKEBOX";
    }
    return out;
}

std::ostream& operator<<(std::ostream& out, const rpcgen::ftype3& obj)
{
    switch(obj)
    {
    case rpcgen::ftype3::NF3REG:  return out << "REG";
    case rpcgen::ftype3::NF3DIR:  return out << "DIR";
    case rpcgen::ftype3::NF3BLK:  return out << "BLK";
    case rpcgen::ftype3::NF3CHR:  return out << "CHR";
    case rpcgen::ftype3::NF3LNK:  return out << "LNK";
    case rpcgen::ftype3::NF3SOCK: return out << "SOCK";
    case rpcgen::ftype3::NF3FIFO: return out << "FIFO";
    }
    return out;
}

std::ostream& operator<<(std::ostream& out, const rpcgen::specdata3& obj)
{
    return out << " specdata1: " << obj.specdata1 << " specdata2: " << obj.specdata2;
}

std::ostream& operator<<(std::ostream& out, const rpcgen::nfs_fh3& obj)
{
    NFS::print_nfs_fh(out, obj.data.data_val, obj.data.data_len);
    return out;
}

std::ostream& operator<<(std::ostream& out, const rpcgen::nfstime3& obj)
{
    return out << "seconds: " << obj.seconds << " nseconds: " << obj.nseconds << ' ';
}

std::ostream& operator<<(std::ostream& out, const rpcgen::fattr3& obj)
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

std::ostream& operator<<(std::ostream& out, const rpcgen::post_op_attr& obj)
{
    if(obj.attributes_follow) return out << obj.post_op_attr_u.attributes;
    else                      return out << " void ";
}

std::ostream& operator<<(std::ostream& out, const rpcgen::wcc_attr& obj)
{
    return out << " size: "  << obj.size
               << " mtime: " << obj.mtime
               << " ctime: " << obj.ctime;
}

std::ostream& operator<<(std::ostream& out, const rpcgen::pre_op_attr& obj)
{
    if(obj.attributes_follow) return out << obj.pre_op_attr_u.attributes;
    else                      return out << " void ";
}

std::ostream& operator<<(std::ostream& out, const rpcgen::wcc_data& obj)
{
    return out << " before: " << obj.before << "after: " << obj.after;
}

std::ostream& operator<<(std::ostream& out, const rpcgen::post_op_fh3& obj)
{
    if(obj.handle_follows) return out << " handle: " << obj.post_op_fh3_u.handle;
    else                   return out << " void ";
}

std::ostream& operator<<(std::ostream& out, const rpcgen::time_how& obj)
{
    switch(obj)
    {
    case rpcgen::time_how::DONT_CHANGE:        return out << "DONT_CHANGE";
    case rpcgen::time_how::SET_TO_SERVER_TIME: return out << "SET_TO_SERVER_TIME";
    case rpcgen::time_how::SET_TO_CLIENT_TIME: return out << "SET_TO_CLIENT_TIME";
    }
    return out;
}

std::ostream& operator<<(std::ostream& out, const rpcgen::set_mode3& obj)
{
    if(obj.set_it) return out << obj.set_mode3_u.mode;
    else           return out << " void ";
}

std::ostream& operator<<(std::ostream& out, const rpcgen::set_uid3& obj)
{
    if(obj.set_it) return out << obj.set_uid3_u.uid;
    else           return out << " void ";
}

std::ostream& operator<<(std::ostream& out, const rpcgen::set_gid3& obj)
{
    if(obj.set_it) return out << obj.set_gid3_u.gid;
    else           return out << " void ";
}

std::ostream& operator<<(std::ostream& out, const rpcgen::set_size3& obj)
{
    if(obj.set_it) return out << obj.set_size3_u.size;
    else           return out << " void ";
}

std::ostream& operator<<(std::ostream& out, const rpcgen::set_atime& obj)
{
    if(obj.set_it == rpcgen::time_how::SET_TO_CLIENT_TIME)
         return out << obj.set_it << " " << obj.set_atime_u.atime;
    else return out << obj.set_it;
}

std::ostream& operator<<(std::ostream& out, const rpcgen::set_mtime& obj)
{
    if(obj.set_it == rpcgen::time_how::SET_TO_CLIENT_TIME)
         return out << obj.set_it << " " << obj.set_mtime_u.mtime;
    else return out << obj.set_it;
}

std::ostream& operator<<(std::ostream& out, const rpcgen::sattr3& obj)
{
    if(obj.mode.set_it)
    {
        out << " mode: ";
        print_mode3(out, obj.mode.set_mode3_u.mode);
    }

    if(obj.uid.set_it)   out << " uid: "   << obj.uid.set_uid3_u.uid;
    if(obj.gid.set_it)   out << " gid: "   << obj.gid.set_gid3_u.gid;
    if(obj.size.set_it)  out << " size: "  << obj.size.set_size3_u.size;
    if(obj.atime.set_it == rpcgen::time_how::SET_TO_CLIENT_TIME) out << " atime: " << obj.atime.set_atime_u.atime;
    if(obj.mtime.set_it == rpcgen::time_how::SET_TO_CLIENT_TIME) out << " atime: " << obj.mtime.set_mtime_u.mtime;

    return out;
}

std::ostream& operator<<(std::ostream& out, const rpcgen::diropargs3& obj)
{
    return out << " dir: "   << obj.dir
               << " name: " << obj.name;
}

std::ostream& operator<<(std::ostream& out, const rpcgen::sattrguard3& obj)
{
    if(obj.check) return out << " obj_ctime: " << obj.sattrguard3_u.obj_ctime; 
    else          return out << " void ";
}

std::ostream& operator<<(std::ostream& out, const rpcgen::stable_how& obj)
{
    switch(obj)
    {
    case rpcgen::stable_how::UNSTABLE:  return out << "UNSTABLE";
    case rpcgen::stable_how::DATA_SYNC: return out << "DATA_SYNC";
    case rpcgen::stable_how::FILE_SYNC: return out << "FILE_SYNC";
    }
    return out;
}

std::ostream& operator<<(std::ostream& out, const rpcgen::createmode3& obj)
{
    switch(obj)
    {
    case rpcgen::createmode3::UNCHECKED: return out << "UNCHECKED";
    case rpcgen::createmode3::GUARDED:   return out << "GUARDED";
    case rpcgen::createmode3::EXCLUSIVE: return out << "EXCLUSIVE";
    }
    return out;
}

std::ostream& operator<<(std::ostream& out, const rpcgen::createhow3& obj)
{
    switch(obj.mode)
    {
    case rpcgen::createmode3::UNCHECKED:
    case rpcgen::createmode3::GUARDED:
        return out << obj.mode << " obj attributes: " << obj.createhow3_u.obj_attributes;
    case rpcgen::createmode3::EXCLUSIVE:
        out << obj.mode << " verf: ";
        print_hex(out, obj.createhow3_u.verf, rpcgen::NFS3_COOKIEVERFSIZE);
        break;
    }
    return out;
}

std::ostream& operator<<(std::ostream& out, const rpcgen::symlinkdata3& obj)
{
    return out << " symlink_attributes: " << obj.symlink_attributes
               << " symlink_data: "       << obj.symlink_data;
}

std::ostream& operator<<(std::ostream& out, const rpcgen::devicedata3& obj)
{
    return out << " dev_attributes: " << obj.dev_attributes
               << " spec: "           << obj.spec;
}


std::ostream& operator<<(std::ostream& out, const rpcgen::mknoddata3& obj)
{
    out << " type: " << obj.type;
    switch(obj.type)
    {
    case rpcgen::ftype3::NF3CHR:
    case rpcgen::ftype3::NF3BLK:
        return out << " device: "          << obj.mknoddata3_u.device;
    case rpcgen::ftype3::NF3SOCK:
    case rpcgen::ftype3::NF3FIFO:
        return out << " pipe_attributes: " << obj.mknoddata3_u.pipe_attributes;
    default: break;
    }
    return out; 
}

std::ostream& operator<<(std::ostream& out, const rpcgen::entry3& obj)
{
    out << " file id: "   <<  obj.fileid
        << " name: "      <<  obj.name
        << " cookie: "    <<  obj.cookie << '\n';
    if(obj.nextentry) out << *obj.nextentry;
    return out;
}

std::ostream& operator<<(std::ostream& out, const rpcgen::dirlist3& obj)
{
    out << " eof: "     <<  obj.eof;
    if(obj.entries) out << *obj.entries;
    return out;
}

std::ostream& operator<<(std::ostream& out, const rpcgen::entryplus3& obj)
{
    out << " file id: "         << obj.fileid
        << " name: "            << obj.name
        << " name attributes: " << obj.name_attributes
        << " name handle: "     << obj.name_handle
        << " cookie: "          << obj.cookie << '\n';
    if(obj.nextentry) out << *obj.nextentry;
    return out;
}

std::ostream& operator<<(std::ostream& out, const rpcgen::dirlistplus3& obj)
{
    out << " eof: " << obj.eof;
    if(obj.entries) out << *obj.entries;
    return out;
}

} // namespace NFS3
} // namespace protocols
} // namespace NST
//------------------------------------------------------------------------------
