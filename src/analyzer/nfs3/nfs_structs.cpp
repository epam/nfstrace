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

XDRReader& operator>>(XDRReader& in, FileName& obj)
{
    in >> obj.filename;
    return in;
}

std::ostream& operator<<(std::ostream& out, const FileName& obj)
{
    out << "filename: " << obj.get_filename();
    return out;
}

XDRReader& operator>>(XDRReader& in, NFSPath& obj)
{
    in >> obj.nfspath;
    return in;
}

std::ostream& operator<<(std::ostream& out, const NFSPath& obj)
{
    out << "nfspath: " << obj.get_nfspath();
    return out;
}

XDRReader& operator>>(XDRReader& in, FileID& obj)
{
    in >> obj.fileid;
    return in;
}

std::ostream& operator<<(std::ostream& out, const FileID& obj)
{
    out << "fileid: " << obj.fileid;
    return out;
}

XDRReader& operator>>(XDRReader& in, Cookie& obj)
{
    in >> obj.cookie;
    return in;
}

std::ostream& operator<<(std::ostream& out, const Cookie& obj)
{
    out << "cookie: " << obj.cookie;
    return out;
}

XDRReader& operator>>(XDRReader& in, CookieVerf& obj)
{
    in >> obj.cookieverf;
    return in;
}

std::ostream& operator<<(std::ostream& out, const CookieVerf& obj)
{
    out << "cookieverf: " << std::hex << obj.cookieverf;
    return out;
}

XDRReader& operator>>(XDRReader& in, CreateVerf& obj)
{
    in >> obj.createverf;
    return in;
}

std::ostream& operator<<(std::ostream& out, const CreateVerf& obj)
{
    out << "createverf: " << std::hex << obj.createverf;
    return out;
}

XDRReader& operator>>(XDRReader& in, WriteVerf& obj)
{
    in >> obj.writeverf;
    return in;
}

std::ostream& operator<<(std::ostream& out, const WriteVerf& obj)
{
    out << "writeverf: " << std::hex << obj.writeverf;
    return out;
}

XDRReader& operator>>(XDRReader& in, UID& obj)
{
    in >> obj.uid;
    return in;
}

std::ostream& operator<<(std::ostream& out, const UID& obj)
{
    out << "uid: " << obj.uid;
    return out;
}

XDRReader& operator>>(XDRReader& in, GID& obj)
{
    in >> obj.gid;
    return in;
}

std::ostream& operator<<(std::ostream& out, const GID& obj)
{
    out << "gid: " << obj.gid;
    return out;
}

XDRReader& operator>>(XDRReader& in, Size& obj)
{
    in >> obj.size;
    return in;
}

std::ostream& operator<<(std::ostream& out, const Size& obj)
{
    out << "size: " << obj.size;
    return out;
}

XDRReader& operator>>(XDRReader& in, Offset& obj)
{
    in >> obj.offset;
    return in;
}

std::ostream& operator<<(std::ostream& out, const Offset& obj)
{
    out << "offset: " << obj.offset;
    return out;
}

XDRReader& operator>>(XDRReader& in, Mode& obj)
{
    in >> obj.mode;
    return in;
}

std::ostream& operator<<(std::ostream& out, const Mode& obj)
{
    out << "mode:";
    if(obj.mode & Mode::USER_ID_EXEC)
        out << " USER_ID_EXEC";
    if(obj.mode & Mode::GROUP_ID_EXEC)
        out << " GROUP_ID_EXEC";
    if(obj.mode & Mode::SAVE_SWAPPED_TEXT)
        out << " SAVE_SWAPPED_TEXT";
    if(obj.mode & Mode::OWNER_READ)
        out << " OWNER_READ";
    if(obj.mode & Mode::OWNER_WRITE)
        out << " OWNER_WRITE";
    if(obj.mode & Mode::OWNER_EXEC)
        out << " OWNER_EXEC";
    if(obj.mode & Mode::GROUP_READ)
        out << " GROUP_READ";
    if(obj.mode & Mode::GROUP_WRITE)
        out << " GROUP_WRITE";
    if(obj.mode & Mode::GROUP_EXEC)
        out << " GROUP_EXEC";
    if(obj.mode & Mode::OTHER_READ)
        out << " OTHER_READ";
    if(obj.mode & Mode::OTHER_WRITE)
        out << " OTHER_WRITE";
    if(obj.mode & Mode::OTHER_EXEC)
        out << " OTHER_EXEC";
    return out;
}

XDRReader& operator>>(XDRReader& in, Count& obj)
{
    in >> obj.count;
    return in;
}

std::ostream& operator<<(std::ostream& out, const Count& obj)
{
    out << "count: " << obj.count;
    return out;
}

XDRReader& operator>>(XDRReader& in, NFSStat& obj)
{
    in >> obj.nfsstat;
    return in;
}

std::ostream& operator<<(std::ostream& out, const NFSStat& obj)
{
    out << "nfsstat: ";
    switch(obj.nfsstat)
    {
        case NFSStat::OK:
            out << "OK"; break;
        case NFSStat::ERR_PERM:
            out << "ERR_PERM"; break;
        case NFSStat::ERR_NOENT:
            out << "ERR_NOENT"; break;
        case NFSStat::ERR_IO:
            out << "ERR_IO"; break;
        case NFSStat::ERR_NXIO:
            out << "ERR_NXIO"; break;
        case NFSStat::ERR_ACCES:
            out << "ERR_ACCES"; break;
        case NFSStat::ERR_EXIST:
            out << "ERR_EXIST"; break;
        case NFSStat::ERR_XDEV:
            out << "ERR_XDEV"; break;
        case NFSStat::ERR_NODEV:
            out << "ERR_NODEV"; break;
        case NFSStat::ERR_NOTDIR:
            out << "ERR_NOTDIR"; break;
        case NFSStat::ERR_ISDIR:
            out << "ERR_ISDIR"; break;
        case NFSStat::ERR_INVAL:
            out << "ERR_INVAL"; break;
        case NFSStat::ERR_FBIG:
            out << "ERR_FBIG"; break;
        case NFSStat::ERR_NOSPC:
            out << "ERR_NOSPC"; break;
        case NFSStat::ERR_ROFS:
            out << "ERR_ROFS"; break;
        case NFSStat::ERR_MLINK:
            out << "ERR_MLINK"; break;
        case NFSStat::ERR_NAMETOOLONG:
            out << "ERR_NAMETOOLONG"; break;
        case NFSStat::ERR_NOTEMPTY:
            out << "ERR_NOTEMPTY"; break;
        case NFSStat::ERR_DQUOT:
            out << "ERR_DQUOT"; break;
        case NFSStat::ERR_STALE:
            out << "ERR_STALE"; break;
        case NFSStat::ERR_REMOTE:
            out << "ERR_REMOTE"; break;
        case NFSStat::ERR_BADHANDLE:
            out << "ERR_BADHANDLE"; break;
        case NFSStat::ERR_NOT_SYNC:
            out << "ERR_NOT_SYNC"; break;
        case NFSStat::ERR_BAD_COOKIE:
            out << "ERR_BAD_COOKIE"; break;
        case NFSStat::ERR_NOTSUPP:
            out << "ERR_NOTSUPP"; break;
        case NFSStat::ERR_TOOSMALL:
            out << "ERR_TOOSMALL"; break;
        case NFSStat::ERR_SERVERFAULT:
            out << "ERR_SERVERFAULT"; break;
        case NFSStat::ERR_BADTYPE:
            out << "ERR_BADTYPE"; break;
        case NFSStat::ERR_JUKEBOX:
            out << "ERR_JUKEBOX"; break;
    }
    return out;
}

XDRReader& operator>>(XDRReader& in, FType& obj)
{
    in >> obj.ftype;
    return in;
}

std::ostream& operator<<(std::ostream& out, const FType& obj)
{
    out << "ftype: ";
    switch(obj.ftype)
    {
        case FType::REG:
            out << "REG"; break;
        case FType::DIR:
            out << "DIR"; break;
        case FType::BLK:
            out << "BLK"; break;
        case FType::CHR:
            out << "CHR"; break;
        case FType::LNK:
            out << "LNK"; break;
        case FType::SOCK:
            out << "SOCK"; break;
        case FType::FIFO:
            out << "FIFO"; break;
    }
    return out;
}

XDRReader& operator>>(XDRReader& in, SpecData& obj)
{
    in >> obj.specdata1 >> obj.specdata2;
    return in;
}

std::ostream& operator<<(std::ostream& out, const SpecData& obj)
{
    out << "specdata1: " << obj.specdata1 << std::endl;
    out << "specdata2: " << obj.specdata2;
    return out;
}

XDRReader& operator>>(XDRReader& in, NFS_FH& obj)
{
    in >> obj.data;
    return in;
}

std::ostream& operator<<(std::ostream& out, const NFS_FH& obj)
{
    std::stringstream tmp;
    tmp << "data: " << std::hex << obj.data;
    return out << tmp.str();
}

XDRReader& operator>>(XDRReader& in, NFSTime& obj)
{
    in >> obj.seconds >> obj.nseconds;
    return in;
}

std::ostream& operator<<(std::ostream& out, const NFSTime& obj)
{
    out << "seconds: " << obj.seconds << std::endl;
    out << "nseconds: " << obj.nseconds;
    return out;
}

XDRReader& operator>>(XDRReader& in, FAttr& obj)
{
    in >> obj.type >> obj.mode >> obj.nlink >> obj.uid >> obj.gid >> obj.size >> obj.used >> obj.rdev >> obj.fsid >> obj.fileid >> obj.atime >> obj.mtime >> obj.ctime;
    return in;
}

std::ostream& operator<<(std::ostream& out, const FAttr& obj)
{
    out << "type: " << std::endl;
    {
        Indent indentation(out, 4);
        out << obj.type << std::endl;
    }

    out << "mode: " << std::endl;
    {
        Indent indentation(out, 4);
        out << obj.mode << std::endl;
    }

    out << "nlink: " << std::endl;
    {
        Indent indentation(out, 4);
        out << obj.nlink << std::endl;
    }

    out << "uid: " << std::endl;
    {
        Indent indentation(out, 4);
        out << obj.uid << std::endl;
    }

    out << "gid: " << std::endl;
    {
        Indent indentation(out, 4);
        out << obj.gid << std::endl;
    }

    out << "size: " << std::endl;
    {
        Indent indentation(out, 4);
        out << obj.size << std::endl;
    }
    
    out << "used: " << std::endl;
    {
        Indent indentation(out, 4);
        out << obj.used << std::endl;
    }

    out << "rdev: " << std::endl;
    {
        Indent indentation(out, 4);
        out << obj.rdev << std::endl;
    }

    out << "fsid: " << std::endl;
    {
        Indent indentation(out, 4);
        out << obj.fsid << std::endl;
    }

    out << "fileid: " << std::endl;
    {
        Indent indentation(out, 4);
        out << obj.fileid << std::endl;
    }

    out << "atime: " << std::endl;
    {
        Indent indentation(out, 4);
        out << obj.atime << std::endl;
    }

    out << "mtime: " << std::endl;
    {
        Indent indentation(out, 4);
        out << obj.mtime << std::endl;
    }

    out << "ctime: " << std::endl;
    {
        Indent indentation(out, 4);
        out << obj.ctime;
    }

    return out;
}

XDRReader& operator>>(XDRReader& in, Post_Op_Attr& obj)
{
    uint32_t temp;

    in >> temp;
    if(temp)
    {
        obj.attributes = new FAttr();
        in >> *obj.attributes;
    }

    return in;
}

std::ostream& operator<<(std::ostream& out, const Post_Op_Attr& obj)
{
    if(obj.attributes)
    {
        out << "attributes: " << std::endl;

        Indent indentation(out, 4);
        out << obj.attributes;
    }
    else
    {
        out << "void";
    }

    return out;
}

XDRReader& operator>>(XDRReader& in, WCC_Attr& obj)
{
    in >> obj.size >> obj.mtime >> obj.ctime;
    return in;
}

std::ostream& operator<<(std::ostream& out, const WCC_Attr& obj)
{
    out << "size:" << std::endl;
    {
        Indent indentation(out, 4);
        out << obj.size << std::endl;
    }

    out << "mtime:" << std::endl;
    {
        Indent indentation(out, 4);
        out << obj.mtime << std::endl;
    }

    out << "ctime:" << std::endl;
    {
        Indent indentation(out, 4);
        out << obj.ctime;
    }
    return out;
}

XDRReader& operator>>(XDRReader& in, Pre_Op_Attr& obj)
{
    uint32_t temp;

    in >> temp;
    if(temp)
    {
        obj.attributes = new WCC_Attr();
        in >> *obj.attributes;
    }

    return in;
}

std::ostream& operator<<(std::ostream& out, const Pre_Op_Attr& obj)
{
    if(obj.attributes)
    {
        out << "attributes: " << std::endl;

        Indent indentation(out, 4);
        out << obj.attributes;
    }
    else
    {
        out << "void";
    }

    return out;
}

XDRReader& operator>>(XDRReader& in, WCC_Data& obj)
{
    in >> obj.before >> obj.after;
    return in;
}

std::ostream& operator<<(std::ostream& out, const WCC_Data& obj)
{
    out << "before:" << std::endl;
    {
        Indent indentation(out, 4);
        out << obj.before << std::endl;
    }

    out << "after:" << std::endl;
    {
        Indent indentation(out, 4);
        out << obj.after;
    }

    return out;
}

XDRReader& operator>>(XDRReader& in, Post_Op_FH& obj)
{
    uint32_t temp;

    in >> temp;
    obj.b_handle = temp;
    if(obj.b_handle)
        in >> obj.handle;

    return in;
}

std::ostream& operator<<(std::ostream& out, const Post_Op_FH& obj)
{
    if(obj.b_handle)
    {
        out << "handle:" << std::endl;
        Indent indentation(out, 4);
        out << obj.handle;
    }
    else
    {
        out << "void";
    }
    return out;
}

XDRReader& operator>>(XDRReader& in, SAttr& obj)
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

    in >> temp;
    obj.b_atime = temp;
    if(obj.b_atime)
        in >> obj.atime;

    in >> temp;
    obj.b_mtime = temp;
    if(obj.b_mtime)
        in >> obj.mtime;

    return in;
}

std::ostream& operator<<(std::ostream& out, const SAttr& obj)
{
    bool new_line = false;

    if(obj.b_mode)
    {
        if(new_line == true)
            out << std::endl;
        new_line = true;

        out << "mode:" << std::endl;
        Indent indentation(out, 4);
        out << obj.mode;
    }

    if(obj.b_uid)
    {
        if(new_line == true)
            out << std::endl;
        new_line = true;

        out << "uid:" << std::endl;
        Indent indentation(out, 4);
        out << obj.uid;
    }

    if(obj.b_gid)
    {
        if(new_line == true)
            out << std::endl;
        new_line = true;

        out << "gid:" << std::endl;
        Indent indentation(out, 4);
        out << obj.gid;
    }

    if(obj.b_size)
    {
        if(new_line == true)
            out << std::endl;
        new_line = true;

        out << "size:" << std::endl;
        Indent indentation(out, 4);
        out << obj.size;
    }
    
    if(obj.b_atime)
    {
        if(new_line == true)
            out << std::endl;
        new_line = true;

        out << "atime:" << std::endl;
        Indent indentation(out, 4);
        out << obj.atime;
    }

    if(obj.b_mtime)
    {
        if(new_line == true)
            out << std::endl;
        new_line = true;

        out << "mtime:" << std::endl;
        Indent indentation(out, 4);
        out << obj.mtime;
    }
    return out;
}

XDRReader& operator>>(XDRReader& in, DirOpArgs& obj)
{
    in >> obj.dir >> obj.name;
    return in;
} 

std::ostream& operator<<(std::ostream& out, const DirOpArgs& obj)
{
    out << "dir:" << std::endl;
    {
        Indent indentation(out, 4);
        out << obj.dir << std::endl;
    }

    out << "name:" << std::endl;
    {
        Indent indentation(out, 4);
        out << obj.name;
    }
    return out;
}

XDRReader& operator>>(XDRReader& in, SAttrGuard& obj)
{
    uint32_t temp;

    in >> temp;
    obj.b_obj_ctime = temp;
    if(obj.b_obj_ctime)
        in >> obj.obj_ctime;

    return in;
} 

std::ostream& operator<<(std::ostream& out, const SAttrGuard& obj)
{
    if(obj.b_obj_ctime)
    {
        out << "obj_ctime:" << std::endl;
        Indent indentation(out, 4);
        out << obj.obj_ctime;
    }
    else
    {
        out << "void";
    }
    return out;
}

std::ostream& operator<<(std::ostream& out, const SetAttrArgs& obj)
{
    out << "object:" << std::endl;
    {
        Indent indentation(out, 4);
        out << obj.object << std::endl;
    }

    out << "new_attributes:" << std::endl;
    {
        Indent indentation(out, 4);
        out << obj.new_attributes << std::endl;
    }

    out << "guard:" << std::endl;
    {
        Indent indentation(out, 4);
        out << obj.guard;
    }
    return out;
}

XDRReader& operator>>(XDRReader& in, CreateHow& obj)
{
    in >> obj.mode;
    switch(obj.mode)
    {
        case CreateHow::EXCLUSIVE :
            {
                obj.verf = new CreateVerf();
                in >> *obj.verf;
            }
            break;
        default:
            {
                obj.obj_attributes = new SAttr();
                in >> *obj.obj_attributes;
            }
            break;
    }
    return in;
} 

std::ostream& operator<<(std::ostream& out, const WriteArgs& obj)
{
    out << "file:" << std::endl;
    {
        Indent indentation(out, 4);
        out << obj.file << std::endl;
    }

    out << "offset:" << std::endl;
    {
        Indent indentation(out, 4);
        out << obj.offset << std::endl;
    }

    out << "count:" << std::endl;
    {
        Indent indentation(out, 4);
        out << obj.file << std::endl;
    }

    out << "stable:" << std::endl;
    {
        Indent indentation(out, 4);
        switch(obj.stable)
        {
            case WriteArgs::UNSTABLE :
                out << "UNSTABLE"; break;
            case WriteArgs::DATA_SYNC :
                out << "DATA_SYNC"; break;
            case WriteArgs::FYLE_SYNC :
                out << "FYLE_SYNC"; break;
        }
    }
    return out;
}

std::ostream& operator<<(std::ostream& out, const CreateHow& obj)
{
    out << "mode: ";
    switch(obj.mode)
    {
        case CreateHow::UNCHECKED :
            {
                out << "UNCHECKED" << std::endl;
            }
            break;
        case CreateHow::GUARDED :
            {
                out << "GUARDED" << std::endl;;
            }
            break;
        default:
            {
                out << "EXCLUSIVE" << std::endl;;
            }
            break;
    }
    if(obj.mode == CreateHow::EXCLUSIVE)
    {
        out << "obj_attributes:" << std::endl;
        Indent indentation(out, 4);
        out << obj.obj_attributes;
    }
    else
    {
        out << "verf:" << std::endl;
        Indent indentation(out, 4);
        out << obj.verf;
    }
    
    return out;
}

std::ostream& operator<<(std::ostream& out, const CreateArgs& obj)
{
    out << "where:" << std::endl;
    {
        Indent indentation(out, 4);
        out << obj.where << std::endl;
    }

    out << "how:" << std::endl;
    {
        Indent indentation(out, 4);
        out << obj.how;
    }
    return out;
}

std::ostream& operator<<(std::ostream& out, const MkDirArgs& obj)
{
    out << "where:" << std::endl;
    {
        Indent indentation(out, 4);
        out << obj.where << std::endl;
    }

    out << "attributes:" << std::endl;
    {
        Indent indentation(out, 4);
        out << obj.attributes;
    }
    return out;
}

XDRReader& operator>>(XDRReader& in, SymLinkData& obj)
{
    in >> obj.symlink_attributes >> obj.symlink_data;
    return in;
} 

std::ostream& operator<<(std::ostream& out, const SymLinkData& obj)
{
    out << "symlink_attributes:" << std::endl;
    {
        Indent indentation(out, 4);
        out << obj.symlink_attributes << std::endl;
    }

    out << "symlink_data:" << std::endl;
    {
        Indent indentation(out, 4);
        out << obj.symlink_data;
    }
    return out;
}

std::ostream& operator<<(std::ostream& out, const SymLinkArgs& obj)
{
    out << "where:" << std::endl;
    {
        Indent indentation(out, 4);
        out << obj.where << std::endl;
    }

    out << "symlink:" << std::endl;
    {
        Indent indentation(out, 4);
        out << obj.symlink;
    }
    return out;
}

XDRReader& operator>>(XDRReader& in, DeviceData& obj)
{
    in >> obj.dev_attributes >> obj.spec;
    return in;
} 

std::ostream& operator<<(std::ostream& out, const DeviceData& obj)
{
    out << "dev_attributes:" << std::endl;
    {
        Indent indentation(out, 4);
        out << obj.dev_attributes << std::endl;
    }

    out << "spec:" << std::endl;
    {
        Indent indentation(out, 4);
        out << obj.spec;
    }
    return out;
}

XDRReader& operator>>(XDRReader& in, MkNodData& obj)
{
    in >> obj.type;
    switch(obj.get_type())
    {
        case FType::CHR:
        case FType::BLK:
            {
                obj.device = new DeviceData();
                in >> *obj.device;
            }
            break;
        case FType::SOCK:
        case FType::FIFO:
            {
                obj.pipe_attributes = new SAttr();
                in >> *obj.pipe_attributes;
            }
            break;
        default:
            break;
    }
    return in;
} 

std::ostream& operator<<(std::ostream& out, const MkNodData& obj)
{
    out << "type: " << obj.type << std::endl;
    
    switch(obj.get_type())
    {
        case FType::CHR :
        case FType::BLK :
            {
                out << "device:" << std::endl;
                Indent indentation(out, 4);
                out << *obj.device;
            }
            break;
        case FType::SOCK :
        case FType::FIFO :
            {
                out << "pipe_attributes:" << std::endl;
                Indent indentation(out, 4);
                out << *obj.pipe_attributes;
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
    out << "where:" << std::endl;
    {
        Indent indentation(out, 4);
        out << obj.where << std::endl;
    }

    out << "what:" << std::endl;
    {
        Indent indentation(out, 4);
        out << obj.what << std::endl;
    }
    return out;
}

} // namespace NFS3
} // namespace filter
} // namespace NST
//------------------------------------------------------------------------------
