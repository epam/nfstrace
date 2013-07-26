//------------------------------------------------------------------------------
// Author: Dzianis Huznou
// Description: All RFC1813 declared structures.
// Copyright (c) 2013 EPAM Systems. All Rights Reserved.
//------------------------------------------------------------------------------
#include "nfs_structs.h"
//------------------------------------------------------------------------------
//------------------------------------------------------------------------------
namespace NST
{
namespace analyzer
{
namespace NFS3
{

XDRReader& operator>>(XDRReader& in, nfsstat3& obj)
{
    return in >> obj.stat;
}

XDRReader& operator>>(XDRReader& in, ftype3& obj)
{
    return in >> obj.ftype;
}

XDRReader& operator>>(XDRReader& in, specdata3& obj)
{
    return in >> obj.specdata1 >> obj.specdata2;
}

XDRReader& operator>>(XDRReader& in, nfs_fh3& obj)
{
    in.read_varialble_len(obj.data); // opaque data size should be less than NFS3_FHSIZE
    assert(obj.data.size() < NFS3_FHSIZE);
    return in;
}

XDRReader& operator>>(XDRReader& in, nfstime3& obj)
{
    return in >> obj.seconds >> obj.nseconds;
}

XDRReader& operator>>(XDRReader& in, fattr3& obj)
{
    in >> obj.type >> obj.mode >> obj.nlink >> obj.uid >> obj.gid >> obj.size >> obj.used >> obj.rdev >> obj.fsid >> obj.fileid >> obj.atime >> obj.mtime >> obj.ctime;
    return in;
}

XDRReader& operator>>(XDRReader& in, post_op_attr& obj)
{
    in >> obj.attributes_follow;
    if(obj.attributes_follow)
    {
        in >> obj.attributes;
    }
    return in;
}

XDRReader& operator>>(XDRReader& in, wcc_attr& obj)
{
    return in >> obj.size >> obj.mtime >> obj.ctime;
}

XDRReader& operator>>(XDRReader& in, pre_op_attr& obj)
{
    in >> obj.attributes_follow;
    if(obj.attributes_follow)
    {
        in >> obj.attributes;
    }
    return in;
}

XDRReader& operator>>(XDRReader& in, wcc_data& obj)
{
    return in >> obj.before >> obj.after;
}

XDRReader& operator>>(XDRReader& in, post_op_fh3& obj)
{
    in >> obj.handle_follows;
    if(obj.handle_follows)
    {
        in >> obj.handle;
    }
    return in;
}

XDRReader& operator>>(XDRReader& in, sattr3& obj)
{
    uint32_t temp;

    in >> temp;
    obj.b_mode = temp;
    if(obj.b_mode)
        in >> obj.mode;

    in >> temp;
    obj.b_uid = temp;
    if(obj.b_uid)
        in >> obj.uid;

    in >> temp;
    obj.b_gid = temp;
    if(obj.b_gid)
        in >> obj.gid;

    in >> temp;
    obj.b_size = temp;
    if(obj.b_size)
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

XDRReader& operator>>(XDRReader& in, diropargs3& obj)
{
    in >> obj.dir;
    in.read_varialble_len(obj.name);
    return in;
}






XDRReader& operator>>(XDRReader& in, sattrguard3& obj)
{
    uint32_t temp;

    in >> temp;
    obj.check = temp;
    if(obj.check)
        in >> obj.obj_ctime;

    return in;
}

XDRReader& operator>>(XDRReader& in, createhow3& obj)
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

XDRReader& operator>>(XDRReader& in, symlinkdata3& obj)
{
    in >> obj.symlink_attributes;
    in.read_varialble_len(obj.symlink_data);
    return in;
}

XDRReader& operator>>(XDRReader& in, devicedata3& obj)
{
    return in >> obj.dev_attributes >> obj.spec;
}

XDRReader& operator>>(XDRReader& in, mknoddata3& obj)
{
    in >> obj.type;
    switch(obj.type.get_ftype())
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



std::ostream& operator<<(std::ostream& out, const Enum_mode3 m)
{
    out << "mode: ";
    if(m & USER_ID_EXEC)      out << "USER_ID_EXEC";
    if(m & GROUP_ID_EXEC)     out << "GROUP_ID_EXEC";
    if(m & SAVE_SWAPPED_TEXT) out << "SAVE_SWAPPED_TEXT";
    if(m & OWNER_READ)        out << "OWNER_READ";
    if(m & OWNER_WRITE)       out << "OWNER_WRITE";
    if(m & OWNER_EXEC)        out << "OWNER_EXEC";
    if(m & GROUP_READ)        out << "GROUP_READ";
    if(m & GROUP_WRITE)       out << "GROUP_WRITE";
    if(m & GROUP_EXEC)        out << "GROUP_EXEC";
    if(m & OTHER_READ)        out << "OTHER_READ";
    if(m & OTHER_WRITE)       out << "OTHER_WRITE";
    if(m & OTHER_EXEC)        out << "OTHER_EXEC";
    return out;
}

std::ostream& operator<<(std::ostream& out, const nfsstat3& obj)
{
    switch(obj.get_stat())
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
    switch(obj.get_ftype())
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
    return out << "specdata1: " << obj.get_specdata1() << " specdata2: " << obj.get_specdata2();
}

std::ostream& operator<<(std::ostream& out, const nfs_fh3& obj)
{
    return out << obj.get_data();
}

std::ostream& operator<<(std::ostream& out, const nfstime3& obj)
{
    return out << "seconds: " << obj.get_seconds() << "nseconds: " << obj.get_nseconds();
}

std::ostream& operator<<(std::ostream& out, const fattr3& obj)
{
    out << "type: " << obj.get_type() << std::endl;
    out << "mode: " << obj.get_mode() << std::endl;
    out << "nlink: " << obj.get_nlink() << std::endl;
    out << "uid: " << obj.get_uid() << std::endl;
    out << "gid: " << obj.get_gid() << std::endl;
    out << "size: " << obj.get_size() << std::endl;
    out << "used: " << obj.get_used() << std::endl;
    out << "rdev: " << obj.get_rdev() << std::endl;
    out << "fsid: " << obj.get_fsid() << std::endl;
    out << "fileid: " << obj.get_fileid() << std::endl;
    out << "atime: " << obj.get_atime() << std::endl;
    out << "mtime: " << obj.get_mtime() << std::endl;
    out << "ctime: " << obj.get_ctime() << std::endl;

    return out;
}

std::ostream& operator<<(std::ostream& out, const post_op_attr& obj)
{
    if(obj.is_attributes())
    {
        out << "attributes: " << obj.get_attributes();
    }
    else
    {
        out << "void";
    }

    return out;
}

std::ostream& operator<<(std::ostream& out, const wcc_attr& obj)
{
    out << "size:" << obj.get_size() << std::endl;
    out << "mtime:" << obj.get_mtime() << std::endl;
    out << "ctime:" << obj.get_ctime() << std::endl;

    return out;
}

std::ostream& operator<<(std::ostream& out, const pre_op_attr& obj)
{
    if(obj.is_attributes())
    {
        out << "attributes: " << obj.get_attributes();
    }
    else
    {
        out << "void";
    }

    return out;
}

std::ostream& operator<<(std::ostream& out, const wcc_data& obj)
{
    out << "before:" << obj.get_before() << std::endl;
    out << "after:"  << obj.get_after()  << std::endl;
    return out;
}

std::ostream& operator<<(std::ostream& out, const post_op_fh3& obj)
{
    if(obj.is_handle())
    {
        out << "handle:" << obj.get_handle();
    }
    else
    {
        out << "void";
    }
    return out;
}

std::ostream& operator<<(std::ostream& out, const sattr3& obj)
{
    if(obj.is_mode())
    {
        out << "mode:" << obj.get_mode() << std::endl;
    }

    if(obj.is_uid())
    {
        out << "uid:" << obj.get_uid() << std::endl;
    }

    if(obj.is_gid())
    {
        out << "gid:" << obj.get_gid() << std::endl;
    }

    if(obj.is_size())
    {
        out << "size:" << obj.get_size() << std::endl;
    }

    if(obj.is_atime())
    {
        out << "atime:" << obj.get_atime() << std::endl;
    }

    if(obj.is_mtime())
    {
        out << "mtime:" << obj.get_mtime() << std::endl;
    }
    return out;
}

std::ostream& operator<<(std::ostream& out, const diropargs3& obj)
{
    out << "dir:"  << obj.get_dir()  << std::endl;
    out << "name:" << obj.get_name().get_string() << std::endl;
    return out;
}

std::ostream& operator<<(std::ostream& out, const sattrguard3& obj)
{
    if(obj.is_obj_ctime())
    {
        out << "obj_ctime:" << obj.get_obj_ctime();
    }
    else
    {
        out << "void";
    }
    return out;
}

std::ostream& operator<<(std::ostream& out, const SetAttrArgs& obj)
{
    out << "object: " << obj.get_object();
    out << "new_attributes: " << obj.get_new_attributes();
    out << "guard: " << obj.get_guard();

    return out;
}

std::ostream& operator<<(std::ostream& out, const WriteArgs& obj)
{
    out << "file: " << obj.get_file();
    out << " offset: " << obj.get_offset();
    out << " count: " << obj.get_count();
    switch(obj.get_stable())
    {
        case WriteArgs::UNSTABLE:  out << " stable: UNSTABLE";  break;
        case WriteArgs::DATA_SYNC: out << " stable: DATA_SYNC"; break;
        case WriteArgs::FYLE_SYNC: out << " stable: FYLE_SYNC"; break;
    }
    return out;
}

std::ostream& operator<<(std::ostream& out, const createhow3& obj)
{
    switch(obj.get_mode())
    {
        case createhow3::UNCHECKED:
        {
            out << "mode: UNCHECKED obj_attributes: " << obj.get_obj_attributes();
        }
        break;
        case createhow3::GUARDED:
        {
            out << "mode: GUARDED obj_attributes: " << obj.get_obj_attributes();
        }
        break;
        case createhow3::EXCLUSIVE:
        {
            out << "mode: EXCLUSIVE verf: " << obj.get_verf();
        }
        break;
    }

    return out;
}

std::ostream& operator<<(std::ostream& out, const CreateArgs& obj)
{
    out << "where: " << obj.get_where();
    out << " howcreate: " << obj.get_how();
    return out;
}

std::ostream& operator<<(std::ostream& out, const MkDirArgs& obj)
{
    out << "where: " << obj.get_where();
    out << " attributes: " << obj.get_attributes();
    return out;
}

std::ostream& operator<<(std::ostream& out, const symlinkdata3& obj)
{
    out << "symlink_attributes: " << obj.get_symlink_attributes();
    out << " symlink_data: " << obj.get_symlink_data();
    return out;
}

std::ostream& operator<<(std::ostream& out, const SymLinkArgs& obj)
{
    out << "where: " << obj.get_where();
    out << " symlink: " << obj.get_symlink();
    return out;
}

std::ostream& operator<<(std::ostream& out, const devicedata3& obj)
{
    out << "dev_attributes: " << obj.get_dev_attributes();
    out << "spec: " << obj.get_spec();
    return out;
}

std::ostream& operator<<(std::ostream& out, const mknoddata3& obj)
{
    out << "type: " << obj.get_type();
    
    switch(obj.get_type())
    {
        case ftype3::CHR:
        case ftype3::BLK:
            {
                out << "device: " << obj.get_device();
            }
            break;
        case ftype3::SOCK:
        case ftype3::FIFO:
            {
                out << "pipe_attributes:" << obj.get_pipe_attributes();
            }
            break;
        default:
            out << "void";
            break;
    }
    return out;
}

std::ostream& operator<<(std::ostream& out, const MkNodArgs& obj)
{
    out << "where: " << obj.get_where();
    out << " what: " << obj.get_what();
    return out;
}

} // namespace NFS3
} // namespace filter
} // namespace NST
//------------------------------------------------------------------------------
