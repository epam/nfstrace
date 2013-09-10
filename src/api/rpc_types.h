//------------------------------------------------------------------------------
// Author: Dzianis Huznou
// Description: Different rpc structures.
// Copyright (c) 2013 EPAM Systems. All Rights Reserved.
//------------------------------------------------------------------------------
#ifndef RPC_TYPES_H
#define RPC_TYPES_H
//------------------------------------------------------------------------------
#include "xdr_types.h"
//------------------------------------------------------------------------------
//------------------------------------------------------------------------------
extern "C"
{

struct OpaqueAuth
{
    uint32_t flavor;
    Opaque   body;
};

struct MismatchInfo
{
    uint32_t low;
    uint32_t high;
};

struct RPCMessage
{
    uint32_t  xid;
    uint32_t type;
};

struct RPCCall : public RPCMessage
{
    uint32_t rpcvers;
    uint32_t prog;
    uint32_t vers;
    uint32_t proc;
    OpaqueAuth cred;
    OpaqueAuth verf;
};

struct AcceptedReply
{
    OpaqueAuth      verf;
    uint32_t        stat;
    MismatchInfo    mismatch_info;
};

struct RejectedReply
{
    uint32_t         stat;
    union U
    {
        MismatchInfo mismatch_info;
        OpaqueAuth   auth_stat;
    } u;
};

struct RPCReply : public RPCMessage
{
    uint32_t          stat;
    union U
    {
        AcceptedReply accepted;
        RejectedReply rejected;
    } u;
};

}
//------------------------------------------------------------------------------
#endif//RPC_TYPES_H
//------------------------------------------------------------------------------
