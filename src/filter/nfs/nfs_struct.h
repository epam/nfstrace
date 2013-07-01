//------------------------------------------------------------------------------
// Author: Dzianis Huznou
// Description: Different nfs structures.
// Copyright (c) 2013 EPAM Systems. All Rights Reserved.
//------------------------------------------------------------------------------
#ifndef NFS_STRUCT_H
#define NFS_STRUCT_H
//------------------------------------------------------------------------------
#include "../rpc/rpc_struct.h"
#include "../xdr/xdr_struct.h"
#include "../xdr/xdr_reader.h"
//------------------------------------------------------------------------------
using namespace NST::filter::XDR;
using namespace NST::filter::RPC;
//------------------------------------------------------------------------------
namespace NST
{
namespace filter
{
namespace NFS3
{

struct Proc // counters definition for NFS v3 procedures. See: RFC 1813
{
    enum Ops
    {
        NFS_NULL        = 0,
        NFS_GETATTR     = 1,
        NFS_SETATTR     = 2,
        NFS_LOOKUP      = 3,
        NFS_ACCESS      = 4,
        NFS_READLINK    = 5,
        NFS_READ        = 6,
        NFS_WRITE       = 7,
        NFS_CREATE      = 8,
        NFS_MKDIR       = 9,
        NFS_SYMLINK     = 10,
        NFS_MKNOD       = 11,
        NFS_REMOVE      = 12,
        NFS_RMDIR       = 13,
        NFS_RENAME      = 14,
        NFS_LINK        = 15,
        NFS_READDIR     = 16,
        NFS_READDIRPLUS = 17,
        NFS_FSSTAT      = 18,
        NFS_FSINFO      = 19,
        NFS_PATHCONF    = 20,
        NFS_COMMIT      = 21,
        num             = 22
    };

    static const char* titles[num];
};

/*
class SAttr
{
public:
    SAttr(XDRReader& in)
    {

    }


private:
    uint32_t mode;
    uint32_t uid;
    uint32_t gid;
    uint64_t size;
};
*/

class NullArgs : public RPCCall
{
public:
    NullArgs(XDRReader& in) : RPCCall(in)
    {
    }
};

class GetAttrArgs : public RPCCall
{
public:
    GetAttrArgs(XDRReader& in) : RPCCall(in)
    {
        in >> file;
    }

    const OpaqueDyn& get_file() const
    {
        return file;
    }

private:
    OpaqueDyn file;
};

/*
class SetAttrArgs : public RPCCall
{
public:
    SetAttrArgs(XDRReader& in) : RPCCall(in)
    {
        in >> file;
    }
    
    const OpaqueDyn& get_file() const
    {
        return file;
    }

private:
    OpaqueDyn file;
};
*/

class LookUpArgs : public RPCCall
{
public:
    LookUpArgs(XDRReader& in) : RPCCall(in)
    {
        in >> dir >> name;
    }
    
    const OpaqueDyn& get_dir() const
    {
        return dir;
    }
    const OpaqueDyn& get_name() const
    {
        return name;
    }

private:
    OpaqueDyn dir;
    OpaqueDyn name;
};

class AccessArgs : public RPCCall
{
public:
    AccessArgs(XDRReader& in) : RPCCall(in)
    {
        in >> object >> access;
    }

    const OpaqueDyn& get_object() const
    {
        return object;
    }
    uint32_t get_access() const
    {
        return access;
    }

private:
    OpaqueDyn object;
    uint32_t access;
};

class ReadLinkArgs : public RPCCall
{
public:
    ReadLinkArgs(XDRReader& in) : RPCCall(in)
    {
        in >> symlink;
    }

    const OpaqueDyn& get_symlink() const
    {
        return symlink;
    }

private:
    OpaqueDyn symlink;
};

class ReadArgs : public RPCCall
{
public:
    ReadArgs(XDRReader& in) : RPCCall(in)
    {
        in >> file >> offset >> count;
    }
    
    const OpaqueDyn& get_file() const
    {
        return file;
    }
    uint64_t get_offset() const
    {
        return offset;
    }
    uint32_t get_count() const
    {
        return count;
    }

private:
    OpaqueDyn file;
    uint64_t  offset;
    uint32_t  count;
};

class WriteArgs : public RPCCall
{
public:
    WriteArgs(XDRReader& in) : RPCCall(in)
    {
        in >> file >> offset >> count >> stable;
    }

    const OpaqueDyn& get_file() const
    {
        return file;
    }
    uint64_t get_offset() const
    {
        return offset;
    }
    uint32_t get_count() const
    {
        return count;
    }
    uint32_t get_stable() const
    {
        return stable;
    }
    
private:
    OpaqueDyn file;
    uint64_t  offset;
    uint32_t  count;
    uint32_t  stable;
    //OpaqueDyn data; Represent real writeargs request
};

/*
class CreateArgs : public RPCCall
{
public:
    CreateArgs(XDRReader& in) : RPCCall(in)
    {
    }

private:
};
*/

class RemoveArgs : public RPCCall
{
public:
    RemoveArgs(XDRReader& in) : RPCCall(in)
    {
        in >> dir >> name;
    }
    
    const OpaqueDyn& get_dir() const
    {
        return dir;
    }
    const OpaqueDyn& get_name() const
    {
        return name;
    }

private:
    OpaqueDyn dir;
    OpaqueDyn name;
}; 

class RmDirArgs : public RPCCall
{
public:
    RmDirArgs(XDRReader& in) : RPCCall(in)
    {
        in >> dir >> name;
    }
    
    const OpaqueDyn& get_dir() const
    {
        return dir;
    }
    const OpaqueDyn& get_name() const
    {
        return name;
    }

private:
    OpaqueDyn dir;
    OpaqueDyn name;
};

class RenameArgs : public RPCCall
{
public:
    RenameArgs(XDRReader& in) : RPCCall(in)
    {
        in >> from_dir >> from_name >> to_dir >> to_name;
    }
    
    const OpaqueDyn& get_from_dir() const
    {
        return from_dir;
    }
    const OpaqueDyn& get_from_name() const
    {
        return from_name;
    }
    const OpaqueDyn& get_to_dir() const
    {
        return to_dir;
    }
    const OpaqueDyn& get_to_name() const
    {
        return to_name;
    }

private:
    OpaqueDyn from_dir;
    OpaqueDyn from_name;
    OpaqueDyn to_dir;
    OpaqueDyn to_name;
}; 

class LinkArgs : public RPCCall
{
public:
    LinkArgs(XDRReader& in) : RPCCall(in)
    {
        in >> file >> dir >> name;
    }
    
    const OpaqueDyn& get_file() const
    {
        return file;
    }
    const OpaqueDyn& get_dir() const
    {
        return dir;
    }
    const OpaqueDyn& get_name() const
    {
        return name;
    }

private:
    OpaqueDyn file;
    OpaqueDyn dir;
    OpaqueDyn name;
};

class ReadDirArgs : public RPCCall
{
public:
    ReadDirArgs(XDRReader& in) : RPCCall(in)
    {
        in >> dir >> cookie >> cookieverf >> count;
    }
    
    const OpaqueDyn& get_dir() const
    {
        return dir;
    }
    uint64_t get_cookie() const
    {
        return cookie;
    }
    const OpaqueStat<8>& get_cookieverf() const
    {
        return cookieverf;
    }
    uint32_t get_count() const
    {
        return count;
    }

private:
    OpaqueDyn dir;
    uint64_t cookie;
    OpaqueStat<8> cookieverf;
    uint32_t count;
};

class ReadDirPlusArgs : public RPCCall
{
public:
    ReadDirPlusArgs(XDRReader& in) : RPCCall(in)
    {
        in >> dir >> cookie >> cookieverf >> dir_count >> max_count;
    }
    
    const OpaqueDyn& get_dir() const
    {
        return dir;
    }
    uint64_t get_cookie() const
    {
        return cookie;
    }
    const OpaqueStat<8>& get_cookieverf() const
    {
        return cookieverf;
    }
    uint32_t get_dir_count() const
    {
        return dir_count;
    }
    uint32_t get_max_count() const
    {
        return max_count;
    }

private:
    OpaqueDyn dir;
    uint64_t cookie;
    OpaqueStat<8> cookieverf;
    uint32_t dir_count;
    uint32_t max_count;
};

class FSStatArgs : public RPCCall
{
public:
    FSStatArgs(XDRReader& in) : RPCCall(in)
    {
        in >> fs_root;
    }
    
    const OpaqueDyn& get_fs_root() const
    {
        return fs_root;
    }

private:
    OpaqueDyn fs_root;
};

class FSInfoArgs : public RPCCall
{
public:
    FSInfoArgs(XDRReader& in) : RPCCall(in)
    {
        in >> fs_root;
    }
    
    const OpaqueDyn& get_fs_root() const
    {
        return fs_root;
    }

private:
    OpaqueDyn fs_root;
};

class PathConfArgs : public RPCCall
{
public:
    PathConfArgs(XDRReader& in) : RPCCall(in)
    {
        in >> object;
    }

    const OpaqueDyn& get_object() const
    {
        return object;
    }

private:
    OpaqueDyn object;
};

class CommitArgs : public RPCCall
{
public:
    CommitArgs(XDRReader& in) : RPCCall(in)
    {
        in >> file >> offset >> count;
    }

    const OpaqueDyn& get_file() const
    {
        return file;
    }
    uint64_t get_offset() const
    {
        return offset;
    }
    uint32_t get_count() const
    {
        return count;
    }

private:
    OpaqueDyn file;
    uint64_t offset;
    uint32_t count;
};

} // namespace NFS3
} // namespace filter
} // namespace NST
//------------------------------------------------------------------------------
#endif//NFS_STRUCT_H
//------------------------------------------------------------------------------
