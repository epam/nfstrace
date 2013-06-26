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

class GetAttrArgs : public RPCCall
{
public:
    GetAttrArgs(XDRReader& in) : RPCCall(in)
    {
        in >> file;
    }

private:
    OpaqueDyn file;
};

} // namespace NFS3
} // namespace filter
} // namespace NST
//------------------------------------------------------------------------------
#endif//NFS_STRUCT_H
//------------------------------------------------------------------------------
