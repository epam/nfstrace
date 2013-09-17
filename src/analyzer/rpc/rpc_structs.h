//------------------------------------------------------------------------------
// Author: Dzianis Huznou
// Description: Different rpc structures.
// Copyright (c) 2013 EPAM Systems. All Rights Reserved.
//------------------------------------------------------------------------------
#ifndef RPC_STRUCTS_H
#define RPC_STRUCTS_H
//------------------------------------------------------------------------------
#include "../../auxiliary/exception.h"
#include "../../filter/rpc/rpc_header.h"
#include "../xdr/xdr_reader.h"
//------------------------------------------------------------------------------
using namespace NST::filter::rpc;
using namespace NST::analyzer::XDR;
using NST::auxiliary::Exception;
//------------------------------------------------------------------------------
namespace NST
{
namespace analyzer
{
namespace RPC
{

#include "../../api/rpc_types.h"

inline XDRReader& operator>>(XDRReader& in, OpaqueAuth& o)
{
    in >> o.flavor;
    in.read_variable_len(o.body);
    return in;
}

inline XDRReader& operator>>(XDRReader& in, MismatchInfo& o)
{
    return in >> o.low >> o.high;
}

inline XDRReader& operator>>(XDRReader& in, RPCMessage& o)
{
    return in >> o.xid >> o.type;
}

inline XDRReader& operator>>(XDRReader& in, RPCCall& o)
{
    const size_t size = sizeof(o.xid) +
                        sizeof(o.type) +
                        sizeof(o.rpcvers) +
                        sizeof(o.prog) +
                        sizeof(o.vers) +
                        sizeof(o.proc);
    in.arrange_check(size);
    in.read_unchecked(o.xid);   // direct fill RPCMessage fileds
    in.read_unchecked(o.type);  // direct fill RPCMessage fileds
    in.read_unchecked(o.rpcvers);
    in.read_unchecked(o.prog);
    in.read_unchecked(o.vers);
    in.read_unchecked(o.proc);
    return in >> o.cred >> o.verf;
}


inline XDRReader& operator>>(XDRReader& in, AcceptedReply& o)
{
    in >> o.verf >> o.stat;
    switch(o.stat)
    {
        case SUNRPC_SUCCESS:
            // Data will be parsed in the specific reader.
            break;
        case SUNRPC_PROG_MISMATCH:
            in >> o.mismatch_info;
            break;
        case SUNRPC_PROG_UNAVAIL:
        case SUNRPC_PROC_UNAVAIL:
        case SUNRPC_GARBAGE_ARGS:
        case SUNRPC_SYSTEM_ERR:
            break;
    }
    return in;
}

inline XDRReader& operator>>(XDRReader& in, RejectedReply& o)
{
    in >> o.stat;
    switch(o.stat)
    {
        case SUNRPC_RPC_MISMATCH:   in >> o.u.mismatch_info; break;
        case SUNRPC_AUTH_ERROR:     in >> o.u.auth_stat;     break;
    }
    return in;
}

inline XDRReader& operator>>(XDRReader& in, RPCReply& o)
{
    const size_t size = sizeof(o.xid) +
                        sizeof(o.type) +
                        sizeof(o.stat);
    in.arrange_check(size);
    in.read_unchecked(o.xid);   // direct fill RPCMessage fileds
    in.read_unchecked(o.type);  // direct fill RPCMessage fileds
    in.read_unchecked(o.stat);
    switch(o.stat)
    {
        case SUNRPC_MSG_ACCEPTED:  in >> o.u.accepted; break;
        case SUNRPC_MSG_DENIED:    in >> o.u.rejected; break;
    }
    return in;
}

} // namespace rpc
} // namespace analyzer
} // namespace NFS
//------------------------------------------------------------------------------
#endif//RPC_STRUCTS_H
//------------------------------------------------------------------------------
