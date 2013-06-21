//------------------------------------------------------------------------------
// Author: Dzianis Huznou
// Description: Different nfs structures.
// Copyright (c) 2013 EPAM Systems. All Rights Reserved.
//------------------------------------------------------------------------------
#ifndef NFS_STRUCT_H
#define NFS_STRUCT_H
//------------------------------------------------------------------------------
#include "../xdr/xdr_struct.h"
#include "../xdr/xdr_reader.h"
//------------------------------------------------------------------------------
using namespace NST::filter::XDR;
//------------------------------------------------------------------------------
namespace NST
{
namespace filter
{
namespace NFS3
{

struct ReadArgs
{
    OpaqueDyn file;
    uint64_t  offset;
    uint32_t  count;

    ReadArgs()
    {
    }
    ReadArgs(XDRReader& in)
    {
        in>>*this;
    }

    friend XDRReader& operator>>(XDRReader& in, ReadArgs& obj)
    {
        return in >> obj.file >> obj.offset >> obj.count;
    }
};

struct WriteArgs
{
    OpaqueDyn file;
    uint64_t  offset;
    uint32_t  count;
    uint32_t  stable;
/*  Meaning of the 'stable':
    UNSTABLE  = 0
    DATA_SYNC = 1
    FILE_SYNC = 2 */
    OpaqueDyn data;

    WriteArgs()
    {
    }
    WriteArgs(XDRReader& in)
    {
        in>>*this;
    }

    friend XDRReader& operator>>(XDRReader& in, WriteArgs& obj)
    {
        return in >> obj.file >> obj.offset >> obj.count >> obj.stable >> obj.data;
    }
};

}
}
}
//------------------------------------------------------------------------------
#endif//NFS_STRUCT_H
//------------------------------------------------------------------------------
