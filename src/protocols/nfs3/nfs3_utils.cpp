//------------------------------------------------------------------------------
// Author: Dzianis Huznou
// Description: Helpers for parsing NFS structures.
// Copyright (c) 2013 EPAM Systems
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
#include <cassert>

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

std::ostream& operator <<(std::ostream& out, const Opaque& opaque)
{
    out << std::hex;
    for(uint32_t i = 0; i < opaque.len; i++)
    {
        out << (uint32_t) opaque.ptr[i];
    }
    return out << std::dec;
}

std::ostream& operator<<(std::ostream& out, const ProcEnum::NFSProcedure proc)
{
    print_nfs3_procedures(out, proc);
    return out;
}

void print_nfs3_procedures(std::ostream& out, const ProcEnum::NFSProcedure proc)
{
    out << NFSProcedureTitles[proc];
}

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

std::ostream& operator<<(std::ostream& out, const nfs_fh3& obj)
{
    return out << obj.data;
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

} // namespace NFS3
} // namespace protocols
} // namespace NST
//------------------------------------------------------------------------------
