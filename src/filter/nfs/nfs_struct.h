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
#include "nfs_procedures.h"
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

class NullArgs : public RPCCall
{
public:
    NullArgs(XDRReader& in) : RPCCall(in)
    {
    }
    virtual ~NullArgs()
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
    virtual ~GetAttrArgs()
    {
    }

    const OpaqueDyn& get_file() const
    {
        return file;
    }

private:
    OpaqueDyn file;     // File handle
};

class SetAttrArgs : public RPCCall
{
public:
    SetAttrArgs(XDRReader& in) : RPCCall(in)
    {
        in >> object;
        attr = "NOT IMPLEMENTED";
        guard_attr = "NOT IMPLEMENTED";
    }
    virtual ~SetAttrArgs()
    {
    }

    const OpaqueDyn& get_object() const
    {
        return object;
    }
    const std::string& get_attr() const
    {
        return attr;
    }
    const std::string& get_guard_attr() const
    {
        return guard_attr;
    }

private:
    OpaqueDyn object;     // File handle
    std::string attr;
    std::string guard_attr;
};

class LookUpArgs : public RPCCall
{
public:
    LookUpArgs(XDRReader& in) : RPCCall(in)
    {
        in >> dir >> name;
    }
    virtual ~LookUpArgs()
    {
    }
    
    const OpaqueDyn& get_dir() const
    {
        return dir;
    }
    const std::string& get_name() const
    {
        return name;
    }

private:
    OpaqueDyn dir;      // File handle
    std::string name;   // File name
};

class AccessArgs : public RPCCall
{
public:
    AccessArgs(XDRReader& in) : RPCCall(in)
    {
        in >> object >> access;
    }
    virtual ~AccessArgs()
    {
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
    OpaqueDyn object;   // File handle
    uint32_t access;
};

class ReadLinkArgs : public RPCCall
{
public:
    ReadLinkArgs(XDRReader& in) : RPCCall(in)
    {
        in >> symlink;
    }
    virtual ~ReadLinkArgs()
    {
    }

    const OpaqueDyn& get_symlink() const
    {
        return symlink;
    }

private:
    OpaqueDyn symlink;  // File handle
};

class ReadArgs : public RPCCall
{
public:
    ReadArgs(XDRReader& in) : RPCCall(in)
    {
        in >> file >> offset >> count;
    }
    virtual ~ReadArgs()
    {
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
    OpaqueDyn file;     // File handle
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
    virtual ~WriteArgs()
    {
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
    OpaqueDyn file;     // File handle
    uint64_t  offset;
    uint32_t  count;
    uint32_t  stable;
};

class CreateArgs : public RPCCall
{
public:
    CreateArgs(XDRReader& in) : RPCCall(in)
    {
    }
    virtual ~CreateArgs()
    {
    }
};

class MkDirArgs : public RPCCall
{
public:
    MkDirArgs(XDRReader& in) : RPCCall(in)
    {
        in >> dir;

        OpaqueDyn tmp;
        in >> tmp;
        name = std::string(tmp.data.begin(), tmp.data.end());
    }
    virtual ~MkDirArgs()
    {
    }

private:
    OpaqueDyn dir;      // File handle
    std::string name;   // File name
};

class RemoveArgs : public RPCCall
{
public:
    RemoveArgs(XDRReader& in) : RPCCall(in)
    {
        in >> dir >> name;
    }
    virtual ~RemoveArgs()
    {
    }
    
    const OpaqueDyn& get_dir() const
    {
        return dir;
    }
    const std::string& get_name() const
    {
        return name;
    }

private:
    OpaqueDyn dir;      // File handle
    std::string name;   // File name
}; 

class RmDirArgs : public RPCCall
{
public:
    RmDirArgs(XDRReader& in) : RPCCall(in)
    {
        in >> dir >> name;
    }
    virtual ~RmDirArgs()
    {
    }
    
    const OpaqueDyn& get_dir() const
    {
        return dir;
    }
    const std::string& get_name() const
    {
        return name;
    }

private:
    OpaqueDyn dir;      // File handle
    std::string name;   // File name
};

class RenameArgs : public RPCCall
{
public:
    RenameArgs(XDRReader& in) : RPCCall(in)
    {
        in >> from_dir >> from_name;
        in >> to_dir >> to_name;
    }
    virtual ~RenameArgs()
    {
    }
    
    const OpaqueDyn& get_from_dir() const
    {
        return from_dir;
    }
    const std::string& get_from_name() const
    {
        return from_name;
    }
    const OpaqueDyn& get_to_dir() const
    {
        return to_dir;
    }
    const std::string& get_to_name() const
    {
        return to_name;
    }

private:
    OpaqueDyn from_dir; // File handle
    std::string from_name;
    OpaqueDyn to_dir;   // File handle
    std::string to_name;
}; 

class LinkArgs : public RPCCall
{
public:
    LinkArgs(XDRReader& in) : RPCCall(in)
    {
        in >> file >> dir >> name;
    }
    virtual ~LinkArgs()
    {
    }
    
    const OpaqueDyn& get_file() const
    {
        return file;
    }
    const OpaqueDyn& get_dir() const
    {
        return dir;
    }
    const std::string& get_name() const
    {
        return name;
    }

private:
    OpaqueDyn file;     // File handle
    OpaqueDyn dir;      // File handle
    std::string name;
};

class ReadDirArgs : public RPCCall
{
public:
    ReadDirArgs(XDRReader& in) : RPCCall(in)
    {
        in >> dir >> cookie >> cookieverf >> count;
    }
    virtual ~ReadDirArgs()
    {
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
    OpaqueDyn dir;      // File handle
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
    virtual ~ReadDirPlusArgs()
    {
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
    OpaqueDyn dir;      // File handle
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
    virtual ~FSStatArgs()
    {
    }
    
    const OpaqueDyn& get_fs_root() const
    {
        return fs_root;
    }

private:
    OpaqueDyn fs_root;  // File handle
};

class FSInfoArgs : public RPCCall
{
public:
    FSInfoArgs(XDRReader& in) : RPCCall(in)
    {
        in >> fs_root;
    }
    virtual ~FSInfoArgs()
    {
    }
    
    const OpaqueDyn& get_fs_root() const
    {
        return fs_root;
    }

private:
    OpaqueDyn fs_root;  // File handle
};

class PathConfArgs : public RPCCall
{
public:
    PathConfArgs(XDRReader& in) : RPCCall(in)
    {
        in >> object;
    }
    virtual ~PathConfArgs()
    {
    }

    const OpaqueDyn& get_object() const
    {
        return object;
    }

private:
    OpaqueDyn object;   // File handle
};

class CommitArgs : public RPCCall
{
public:
    CommitArgs(XDRReader& in) : RPCCall(in)
    {
        in >> file >> offset >> count;
    }
    virtual ~CommitArgs()
    {
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
    OpaqueDyn file;     // File handle
    uint64_t offset;
    uint32_t count;
};

} // namespace NFS3
} // namespace filter
} // namespace NST
//------------------------------------------------------------------------------
#endif//NFS_STRUCT_H
//------------------------------------------------------------------------------
