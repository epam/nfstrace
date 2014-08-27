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
#include "protocols/nfs3/nfs3_utils.h"
//------------------------------------------------------------------------------
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
/*
std::ostream& operator <<(std::ostream& out, const Opaque& opaque)
{
    out << std::hex;
    for(uint32_t i = 0; i < opaque.len; i++)
    {
        out << (uint32_t) opaque.ptr[i];
    }
    return out << std::dec;
}

std::ostream& operator<<(std::ostream& out, const ProcEnumNFS3::NFSProcedure proc)
{
    return out << print_nfs3_procedures(proc);
}

std::ostream& operator<<(std::ostream& out, const nfs_fh3& obj)
{
    return out << obj.data;
}
*/
/*
std::ostream& operator<<(std::ostream& out, const mode3 m)
{
    if(m & mode3::USER_ID_EXEC)      out << "USER_ID_EXEC ";
    if(m & mode3::GROUP_ID_EXEC)     out << "GROUP_ID_EXEC ";
    if(m & mode3::SAVE_SWAPPED_TEXT) out << "SAVE_SWAPPED_TEXT ";
    if(m & mode3::OWNER_READ)        out << "OWNER_READ ";
    if(m & mode3::OWNER_WRITE)       out << "OWNER_WRITE ";
    if(m & mode3::OWNER_EXEC)        out << "OWNER_EXEC ";
    if(m & mode3::GROUP_READ)        out << "GROUP_READ ";
    if(m & mode3::GROUP_WRITE)       out << "GROUP_WRITE ";
    if(m & mode3::GROUP_EXEC)        out << "GROUP_EXEC ";
    if(m & mode3::OTHER_READ)        out << "OTHER_READ ";
    if(m & mode3::OTHER_WRITE)       out << "OTHER_WRITE ";
    if(m & mode3::OTHER_EXEC)        out << "OTHER_EXEC";
    return out;
}

std::ostream& operator<<(std::ostream& out, const nfsstat3& obj)
{
    switch(obj)
    {
        case nfsstat3::OK:               out << "OK";                break;
        case nfsstat3::ERR_PERM:         out << "ERR_PERM";          break;
        case nfsstat3::ERR_NOENT:        out << "ERR_NOENT";         break;
        case nfsstat3::ERR_IO:           out << "ERR_IO";            break;
        case nfsstat3::ERR_NXIO:         out << "ERR_NXIO";          break;
        case nfsstat3::ERR_ACCES:        out << "ERR_ACCES";         break;
        case nfsstat3::ERR_EXIST:        out << "ERR_EXIST";         break;
        case nfsstat3::ERR_XDEV:         out << "ERR_XDEV";          break;
        case nfsstat3::ERR_NODEV:        out << "ERR_NODEV";         break;
        case nfsstat3::ERR_NOTDIR:       out << "ERR_NOTDIR";        break;
        case nfsstat3::ERR_ISDIR:        out << "ERR_ISDIR";         break;
        case nfsstat3::ERR_INVAL:        out << "ERR_INVAL";         break;
        case nfsstat3::ERR_FBIG:         out << "ERR_FBIG";          break;
        case nfsstat3::ERR_NOSPC:        out << "ERR_NOSPC";         break;
        case nfsstat3::ERR_ROFS:         out << "ERR_ROFS";          break;
        case nfsstat3::ERR_MLINK:        out << "ERR_MLINK";         break;
        case nfsstat3::ERR_NAMETOOLONG:  out << "ERR_NAMETOOLONG";   break;
        case nfsstat3::ERR_NOTEMPTY:     out << "ERR_NOTEMPTY";      break;
        case nfsstat3::ERR_DQUOT:        out << "ERR_DQUOT";         break;
        case nfsstat3::ERR_STALE:        out << "ERR_STALE";         break;
        case nfsstat3::ERR_REMOTE:       out << "ERR_REMOTE";        break;
        case nfsstat3::ERR_BADHANDLE:    out << "ERR_BADHANDLE";     break;
        case nfsstat3::ERR_NOT_SYNC:     out << "ERR_NOT_SYNC";      break;
        case nfsstat3::ERR_BAD_COOKIE:   out << "ERR_BAD_COOKIE";    break;
        case nfsstat3::ERR_NOTSUPP:      out << "ERR_NOTSUPP";       break;
        case nfsstat3::ERR_TOOSMALL:     out << "ERR_TOOSMALL";      break;
        case nfsstat3::ERR_SERVERFAULT:  out << "ERR_SERVERFAULT";   break;
        case nfsstat3::ERR_BADTYPE:      out << "ERR_BADTYPE";       break;
        case nfsstat3::ERR_JUKEBOX:      out << "ERR_JUKEBOX";       break;
    }
    return out;
}

std::ostream& operator<<(std::ostream& out, const ftype3& obj)
{
    switch(obj)
    {
        case ftype3::REG: out << "REG"; break;
        case ftype3::DIR: out << "DIR"; break;
        case ftype3::BLK: out << "BLK"; break;
        case ftype3::CHR: out << "CHR"; break;
        case ftype3::LNK: out << "LNK"; break;
        case ftype3::SOCK: out << "SOCK"; break;
        case ftype3::FIFO: out << "FIFO"; break;
    }
    return out;
}

std::ostream& operator<<(std::ostream& out, const specdata3& obj)
{
    return out << " specdata1: " << obj.specdata1 << " specdata2: " << obj.specdata2;
}

std::ostream& operator<<(std::ostream& out, const nfstime3& obj)
{
    return out << "seconds: " << obj.seconds << " nseconds: " << obj.nseconds;
}

std::ostream& operator<<(std::ostream& out, const fattr3& obj)
{
    out << " type: " << obj.type;
    out << " mode: " << obj.mode;
    out << " nlink: " << obj.nlink;
    out << " uid: " << obj.uid;
    out << " gid: " << obj.gid;
    out << " size: " << obj.size;
    out << " used: " << obj.used;
    out << " rdev: " << obj.rdev;
    out << " fsid: " << obj.fsid;
    out << " fileid: " << obj.fileid;
    out << " atime: " << obj.atime;
    out << " mtime: " << obj.mtime;
    out << " ctime: " << obj.ctime;

    return out;
}

std::ostream& operator<<(std::ostream& out, const post_op_attr& obj)
{
    if(obj.attributes_follow)
    {
        out << " attributes: " << obj.attributes;
    }
    else
    {
        out << " void ";
    }

    return out;
}

std::ostream& operator<<(std::ostream& out, const wcc_attr& obj)
{
    out << " size: " << obj.size;
    out << " mtime: " << obj.mtime;
    out << " ctime: " << obj.ctime;

    return out;
}

std::ostream& operator<<(std::ostream& out, const pre_op_attr& obj)
{
    if(obj.attributes_follow)
    {
        out << " attributes: " << obj.attributes;
    }
    else
    {
        out << " void ";
    }

    return out;
}

std::ostream& operator<<(std::ostream& out, const wcc_data& obj)
{
    out << " before: " << obj.before;
    out << " after: "  << obj.after;
    return out;
}

std::ostream& operator<<(std::ostream& out, const post_op_fh3& obj)
{
    if(obj.handle_follows)
    {
        out << " handle: " << obj.handle;
    }
    else
    {
        out << " void ";
    }
    return out;
}

std::ostream& operator<<(std::ostream& out, const sattr3& obj)
{
    if(obj.set_it_mode)
    {
        out << " mode: " << obj.mode;
    }

    if(obj.set_it_uid)
    {
        out << " uid: " << obj.uid;
    }

    if(obj.set_it_gid)
    {
        out << " gid: " << obj.gid;
    }

    if(obj.set_it_size)
    {
        out << " size: " << obj.size;
    }

    if(obj.set_it_atime == sattr3::SET_TO_CLIENT_TIME)
    {
        out << " atime: " << obj.atime;
    }

    if(obj.set_it_mtime == sattr3::SET_TO_CLIENT_TIME)
    {
        out << " mtime: " << obj.mtime;
    }
    return out;
}

std::ostream& operator<<(std::ostream& out, const diropargs3& obj)
{
    out << " dir: "  << obj.dir;
    out << " name: " << to_string(obj.name);
    return out;
}

std::ostream& operator<<(std::ostream& out, const stable_how& obj)
{
    switch(obj.stable)
    {
        case stable_how::UNSTABLE:  out << "UNSTABLE";  break;
        case stable_how::DATA_SYNC: out << "DATA_SYNC"; break;
        case stable_how::FILE_SYNC: out << "FILE_SYNC"; break;
    }
    return out;
}

std::ostream& operator<<(std::ostream& out, const sattrguard3& obj)
{
    if(obj.check)
    {
        out << " obj_ctime: " << obj.obj_ctime;
    }
    else
    {
        out << " void ";
    }
    return out;
}

std::ostream& operator<<(std::ostream& out, const createhow3& obj)
{
    switch(obj.mode)
    {
        case createhow3::UNCHECKED:
        {
            out << " mode: UNCHECKED obj_attributes: " << obj.u.obj_attributes;
        }
        break;
        case createhow3::GUARDED:
        {
            out << " mode: GUARDED obj_attributes: " << obj.u.obj_attributes;
        }
        break;
        case createhow3::EXCLUSIVE:
        {
            out << " mode: EXCLUSIVE verf: " << obj.u.verf;
        }
        break;
    }

    return out;
}

std::ostream& operator<<(std::ostream& out, const symlinkdata3& obj)
{
    out << " symlink_attributes: " << obj.symlink_attributes;
    out << " symlink_data: " << obj.symlink_data;
    return out;
}

std::ostream& operator<<(std::ostream& out, const devicedata3& obj)
{
    out << " dev_attributes: " << obj.dev_attributes;
    out << " spec: " << obj.spec;
    return out;
}

std::ostream& operator<<(std::ostream& out, const mknoddata3& obj)
{
    out << " type: " << obj.type;
    switch(obj.type)
    {
        case ftype3::CHR:
        case ftype3::BLK:
            {
                out << " device: " << obj.u.device;
            }
            break;
        case ftype3::SOCK:
        case ftype3::FIFO:
            {
                out << " pipe_attributes: " << obj.u.pipe_attributes;
            }
            break;
        default:
            out << " void ";
            break;
    }
    return out;
}
*/

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
    if(obj.data.data_len) return out << *obj.data.data_val;
    else                  return out << " void ";
}

std::ostream& operator<<(std::ostream& out, const rpcgen::nfstime3& obj)
{
    return out << "seconds: " << obj.seconds << " nseconds: " << obj.nseconds;
}

std::ostream& operator<<(std::ostream& out, const rpcgen::fattr3& obj)
{
    return out << " type: "   << obj.type
               << " mode: "   << obj.mode
               << " nlink: "  << obj.nlink
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
    return out << " mode: "  << obj.mode
               << " uid: "   << obj.uid
               << " gid: "   << obj.gid
               << " size: "  << obj.size
               << " atime: " << obj.atime
               << " mtime: " << obj.mtime;
}

std::ostream& operator<<(std::ostream& out, const rpcgen::diropargs3& obj)
{
    return out << " dir: "   << obj.dir
               << " name: :" << obj.name;
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
        return out << obj.mode;
    case rpcgen::createmode3::GUARDED:
        return out << obj.mode << " obj attributes: " << obj.createhow3_u.obj_attributes;
    case rpcgen::createmode3::EXCLUSIVE:
        return out << obj.mode << " verf: "           << obj.createhow3_u.verf;
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
        << " cookie: "    <<  obj.cookie;
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
        << " name:       "      << obj.name
        << " name attributes: " << obj.name_attributes
        << " name handle: "     << obj.name_handle
        << " cookie: "          << obj.cookie;
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
