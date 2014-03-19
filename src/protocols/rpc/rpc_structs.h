//------------------------------------------------------------------------------
// Author: Dzianis Huznou
// Description: Different rpc structures.
// Copyright (c) 2013 EPAM Systems. All Rights Reserved.
//------------------------------------------------------------------------------
#ifndef RPC_STRUCTS_H
#define RPC_STRUCTS_H
//------------------------------------------------------------------------------
#include "protocols/rpc/rpc_header.h"
#include "protocols/xdr/xdr_reader.h"
//------------------------------------------------------------------------------
using namespace NST::protocols::rpc;
using namespace NST::protocols::xdr;
//------------------------------------------------------------------------------
namespace NST
{
namespace protocols
{
namespace rpc
{

#include "api/rpc_types.h"


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
        case AcceptStat::SUCCESS:
            // Data will be parsed in the specific reader.
            break;
        case AcceptStat::PROG_MISMATCH:
            in >> o.mismatch_info;
            break;
        case AcceptStat::PROG_UNAVAIL:
        case AcceptStat::PROC_UNAVAIL:
        case AcceptStat::GARBAGE_ARGS:
        case AcceptStat::SYSTEM_ERR:
            break;
    }
    return in;
}

inline XDRReader& operator>>(XDRReader& in, RejectedReply& o)
{
    in >> o.stat;
    switch(o.stat)
    {
        case RejectStat::RPC_MISMATCH:   in >> o.u.mismatch_info; break;
        case RejectStat::AUTH_ERROR:     in >> o.u.auth_stat;     break;
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
        case ReplyStat::MSG_ACCEPTED:  in >> o.u.accepted; break;
        case ReplyStat::MSG_DENIED:    in >> o.u.rejected; break;
    }
    return in;
}

} // namespace rpc
} // namespace protocols
} // namespace NST
//------------------------------------------------------------------------------
#endif//RPC_STRUCTS_H
//------------------------------------------------------------------------------
